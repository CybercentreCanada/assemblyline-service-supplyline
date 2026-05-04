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
from sandlock import Policy, Sandbox, landlock_abi_version, min_landlock_abi

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
    supply_line_command = [sys.executable, MSBUILD_EVAL_PATH, f"/tmp/{file.name}", results_dir]

    dotnet_libs = PlatformDirs("supplyshell-libs", "cccs").user_data_dir

    with TemporaryDirectory() as temp_dir:
        shutil.copyfile(file, Path(temp_dir) / file.name)

        policy = Policy(
            fs_readable=[
                "/usr",
                "/lib",
                "/lib64",
                "/bin",
                "/etc",
                "/proc",
                "/dev",
                "/usr/share/dotnet",
                "/opt/al_service",
                dotnet_libs,
                *site.getsitepackages(),
                site.getusersitepackages(),
                MSBUILD_EVAL_PATH.parent,
                "/tmp",
            ],
            fs_writable=[str(results_dir), "/tmp"],
            fs_mount={"/tmp": temp_dir},
            env={"DOTNET_ROOT": "/usr/share/dotnet", "PYTHONPATH": dotnet_libs},
        )
        result = Sandbox(policy).run(supply_line_command, timeout=MSBUILD_RUNTIME_SECONDS)

    if not result.success:
        raise MSBuildEvalError(f"MSBuild evaluation failed: {result.stderr.decode()}; "
                               f"Landlock ABI Version: {landlock_abi_version()}; "
                               f"Required ABI Version: {min_landlock_abi()}; ")

    return [Path(root) / f for root, _, files in os.walk(results_dir) for f in files]


class Supplyline(ServiceBase):
    """An Assemblyline service implementation for extracting and identifying supply-chain embedded malicious payloads."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sandlock_available = landlock_abi_version() >= min_landlock_abi()

    def execute(self, request: ServiceRequest):
        """Run the service. Returns the result or None if no result was produced."""
        result = Result()
        request.result = result

        if not self.sandlock_available:
            self.log.warning(
                "Landlock is either not enabled or the ABI version is too old. MSBuild script extraction will be skipped."
            )
            return

        if not is_msbuild_script(request.file_path):
            self.log.info("File is not identified as a .Net MSBuild script. Skipping processing.")
            return

        results_dir = tempfile.mkdtemp(dir=self.working_directory)

        try:
            extracted_scripts = extract_msbuild_scripts(Path(request.file_path), results_dir)
        except MSBuildEvalError as e:
            self.log.error(f"Error during MSBuild evaluation: {e}")
            return

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
