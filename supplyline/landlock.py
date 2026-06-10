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
        import errno
        import json
        import os
        import sys
        import pyseccomp
        from sandlock import Sandbox as SandlockSandbox, confine
        from sandlock.sandbox import _resolve_syscall

        f = pyseccomp.SyscallFilter(pyseccomp.ALLOW)
        deny = pyseccomp.ERRNO(errno.EPERM)
        for name in {MINIMAL_SECCOMP_DENY_SYSCALLS!r}:
            try:
                _resolve_syscall(name)
                f.add_rule(deny, name)
            except (ValueError, RuntimeError, OSError):
                pass
        try:
            f.load()
        except (RuntimeError, OSError):
            pass

        readable = json.loads(sys.argv[1])
        writable = json.loads(sys.argv[2])
        confine(SandlockSandbox(fs_readable=readable, fs_writable=writable))
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
