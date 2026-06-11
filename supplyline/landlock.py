"""Helpers for running child processes under Sandlock confinement."""

import json
import os
import signal
import subprocess
import sys
import textwrap
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field

MINIMAL_SECCOMP_DENY_SYSCALLS: tuple[str, ...] = ("fork", "vfork")


@dataclass
class Result:
    """Process execution result for a confined child run."""

    success: bool
    exit_code: int = 0
    stdout: bytes = field(default=b"")
    stderr: bytes = field(default=b"")
    error: str | None = None


def _kill_process_group(proc: subprocess.Popen) -> None:
    """Best-effort kill for the process group started by this launcher."""
    with suppress(ProcessLookupError):
        os.killpg(proc.pid, signal.SIGKILL)


def run_confined(
    cmd: Sequence[str],
    *,
    fs_readable: Sequence[str] = (),
    fs_writable: Sequence[str] = (),
    env: Mapping[str, str] | None = None,
    timeout: float | None = None,
) -> Result:
    """Run a command in a child process after applying Sandlock confine.

    Args:
        cmd: Command and arguments to execute.
        fs_readable: Paths allowed for read/execute under Landlock.
        fs_writable: Paths allowed for write under Landlock.
        env: Environment variables to apply for the child process.
        timeout: Optional timeout in seconds.

    Returns:
        Captured process result with success/exit code/stdout/stderr.
    """
    child_env = os.environ.copy()
    child_env.update(env or {})

    bootstrap = textwrap.dedent(
        f"""
        import ctypes
        import errno
        import json
        import os
        import sys
        import pyseccomp
        from sandlock.sandbox import _resolve_syscall

        # Landlock syscall numbers (x86_64)
        LANDLOCK_CREATE_RULESET = 438
        LANDLOCK_ADD_RULE = 439
        LANDLOCK_RESTRICT_SELF = 440

        # Landlock access rights for ABI v1 (filesystem only)
        LANDLOCK_ACCESS_FS_EXECUTE = (1 << 0)
        LANDLOCK_ACCESS_FS_WRITE_FILE = (1 << 1)
        LANDLOCK_ACCESS_FS_READ_FILE = (1 << 2)
        LANDLOCK_ACCESS_FS_READ_DIR = (1 << 3)
        LANDLOCK_ACCESS_FS_REMOVE_DIR = (1 << 4)
        LANDLOCK_ACCESS_FS_REMOVE_FILE = (1 << 5)
        LANDLOCK_ACCESS_FS_MAKE_CHAR = (1 << 6)
        LANDLOCK_ACCESS_FS_MAKE_DIR = (1 << 7)
        LANDLOCK_ACCESS_FS_MAKE_REG = (1 << 8)
        LANDLOCK_ACCESS_FS_MAKE_SOCK = (1 << 9)
        LANDLOCK_ACCESS_FS_MAKE_FIFO = (1 << 10)
        LANDLOCK_ACCESS_FS_MAKE_BLOCK = (1 << 11)
        LANDLOCK_ACCESS_FS_MAKE_SYM = (1 << 12)

        # All filesystem rights
        FS_ALL_RIGHTS = (
            LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
            LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
            LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
            LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |
            LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |
            LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
            LANDLOCK_ACCESS_FS_MAKE_SYM
        )

        f = pyseccomp.SyscallFilter(pyseccomp.ALLOW)
        deny = pyseccomp.ERRNO(errno.EPERM)
        for name in {MINIMAL_SECCOMP_DENY_SYSCALLS!r}:
            try:
                _resolve_syscall(name)
                f.add_rule(deny, name)
            except (ValueError, RuntimeError, OSError):
                pass

        f.load()

        readable = json.loads(sys.argv[1])
        writable = json.loads(sys.argv[2])

        # Try Sandlock confine first (works on ABI v6+)
        confine_succeeded = False
        try:
            from sandlock import Sandbox as SandlockSandbox, confine
            confine(SandlockSandbox(fs_readable=readable, fs_writable=writable))
            confine_succeeded = True
        except Exception:
            # If Sandlock confine fails, fall back to direct Landlock syscalls (ABI v1+)
            pass

        if not confine_succeeded:
            libc = ctypes.CDLL(None)

            # PR_SET_NO_NEW_PRIVS = 38
            libc.prctl(38, 1, 0, 0, 0)

            ruleset_fd = libc.syscall(LANDLOCK_CREATE_RULESET, 0, 0, 0)
            if ruleset_fd >= 0:
                for path in readable:
                    path_fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
                    rule_attr = (ctypes.c_int64 * 2)()
                    rule_attr[0] = FS_ALL_RIGHTS & ~(LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK | LANDLOCK_ACCESS_FS_MAKE_SYM)
                    rule_attr[1] = path_fd
                    libc.syscall(LANDLOCK_ADD_RULE, ruleset_fd, 1, ctypes.byref(rule_attr), 0)
                    os.close(path_fd)

                for path in writable:
                    path_fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
                    rule_attr = (ctypes.c_int64 * 2)()
                    rule_attr[0] = FS_ALL_RIGHTS
                    rule_attr[1] = path_fd
                    libc.syscall(LANDLOCK_ADD_RULE, ruleset_fd, 1, ctypes.byref(rule_attr), 0)
                    os.close(path_fd)

                libc.syscall(LANDLOCK_RESTRICT_SELF, ruleset_fd, 0)
                os.close(ruleset_fd)

        os.execv(sys.argv[3], sys.argv[3:])
        """
    )

    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            bootstrap,
            json.dumps([str(path) for path in fs_readable]),
            json.dumps([str(path) for path in fs_writable]),
            *map(str, cmd),
        ],
        env=child_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_process_group(proc)
        stdout, stderr = proc.communicate()
        return Result(
            success=False,
            exit_code=-1,
            stdout=stdout or b"",
            stderr=stderr or b"",
            error="timeout",
        )
    except (OSError, subprocess.SubprocessError) as exc:
        _kill_process_group(proc)
        return Result(success=False, exit_code=-1, error=str(exc))

    return Result(
        success=proc.returncode == 0,
        exit_code=proc.returncode,
        stdout=stdout,
        stderr=stderr,
        error=None,
    )
