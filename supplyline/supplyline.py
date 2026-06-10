"""Assemblyline service extracts and identifies supply-chain embedded malicious payloads."""

import os
import re
import shutil
import site
import sys
import tempfile
from pathlib import Path
from tempfile import TemporaryDirectory
from xml.etree.ElementTree import ParseError

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultSection
from lxml import etree
from platformdirs import PlatformDirs
from sandlock import landlock_abi_version, min_landlock_abi

from supplyline.landlock import run_confined

MATCH_MSBUILD_ROOT = re.compile(r"^(\{[^\}]*\})?Project")
MSBUILD_RUNTIME_SECONDS = 10
MSBUILD_EVAL_PATH = Path(__file__).parent / "util" / "collect_exec.py"


class MSBuildEvalError(Exception):
    """Custom exception for MSBuild evaluation errors."""


def is_msbuild_script(file: Path) -> bool:
    """Determines if the provided file is a .Net MSBuild script based on file extension and content.

    Args:
        file: Path to the file to be evaluated.

    Returns:
        bool: True if the file is identified as a .Net MSBuild script, False otherwise.
    """
    with open(file, "r") as f:
        try:
            tree = etree.parse(f)
            root = tree.getroot()
            return MATCH_MSBUILD_ROOT.match(root.tag) is not None
        except ParseError:
            return False


def extract_msbuild_scripts(file: Path, results_dir: Path) -> list[Path]:
    """Invokes msbuild wrapper to evaluate and dump exec directives in a Project file.

    Args:
        file: .Net MSBuild Project file
        results_dir: Directory to store extraction results

    Returns:
        List of extracted files or empty list if none found.

    Raises:
        MSBuildEvalError: If the msbuild evaluation process fails.
    """
    results_dir = Path(results_dir).resolve()
    results_dir.mkdir(parents=True, exist_ok=True)

    dotnet_libs = PlatformDirs("supplyshell-libs", "cccs").user_data_dir

    with TemporaryDirectory() as temp_dir:
        copied_file = Path(temp_dir) / file.name
        shutil.copyfile(file, copied_file)

        py_prefix = str(Path(sys.prefix).resolve())
        fs_readable = [
            "/usr",
            "/lib",
            "/lib64",
            "/bin",
            "/etc",
            "/proc",
            "/dev",
            py_prefix,
            "/usr/share/dotnet",
            "/opt/al_service",
            dotnet_libs,
            *site.getsitepackages(),
            site.getusersitepackages(),
            MSBUILD_EVAL_PATH.parent,
            copied_file.parent,
            "/tmp",
        ]

        supply_line_command = [sys.executable, MSBUILD_EVAL_PATH, copied_file, results_dir]

        # The launcher applies Landlock in the child process before executing
        # collect_exec.py, and the path lists below define the allowed file
        # system view for the evaluator.
        result = run_confined(
            supply_line_command,
            fs_readable=fs_readable,
            fs_writable=[str(results_dir), "/tmp"],
            env={"DOTNET_ROOT": "/usr/share/dotnet", "PYTHONPATH": dotnet_libs},
            timeout=MSBUILD_RUNTIME_SECONDS,
        )

    if not result.success:
        raise MSBuildEvalError(
            f"MSBuild evaluation failed: {result.stderr.decode()}; {result.error};"
            f"Landlock ABI Version: {landlock_abi_version()}; "
            f"Required ABI Version: {min_landlock_abi()}; "
        )

    return [Path(root) / f for root, _, files in os.walk(results_dir) for f in files]


class Supplyline(ServiceBase):
    """Extract and identify supply-chain embedded malicious payloads."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def execute(self, request: ServiceRequest):
        """Run the service.

        Raises:
            MSBuildEvalError: If Landlock is unavailable for safe MSBuild evaluation.
        """
        result = Result()
        request.result = result

        if not is_msbuild_script(request.file_path):
            self.log.info("File is not identified as a .Net MSBuild script. Skipping processing.")
            return

        results_dir = tempfile.mkdtemp(dir=self.working_directory)

        extracted_scripts = extract_msbuild_scripts(Path(request.file_path), results_dir)

        if not extracted_scripts:
            self.log.info("No .Net MSBuild scripts were found.")
            return

        result_section = ResultSection("MSBuild scripts successfully unpacked!")

        for unpacked_result in extracted_scripts:
            if not request.add_extracted(
                unpacked_result,
                unpacked_result.name,
                f"Unpacked from MSBuild Script {request.sha256}",
                safelist_interface=self.api_interface,
            ):
                result_section.body = "This extracted file will not be re-submitted due to being known as safe."

        request.result.add_section(result_section)
