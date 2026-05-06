import os
import re
import shutil
import site
import sys
import tempfile
from pathlib import Path
from tempfile import TemporaryDirectory
from xml.etree.ElementTree import ParseError
import json
import subprocess

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultSection
from lxml import etree
from platformdirs import PlatformDirs
from sandlock import Policy, Sandbox, landlock_abi_version, min_landlock_abi
import os

readable_files = [
    "/lib",
    "/lib64",
    "/usr/lib",
    "/usr/lib64",
    "/bin",
    "/usr/bin",
    "/etc"
]
readable_files = [os.path.realpath(r) for r in readable_files]

readable_files = list(set(readable_files))

#raise MSBuildEvalError(f"Testing readability of required paths: {readable_files}")

for r in readable_files:
    if not os.path.exists(r):
        print(f"Required readable path does not exist: {r}")

policy = Policy(
    fs_readable=readable_files
)
result = Sandbox(policy).run(["/bin/true"], timeout=10)
print(f"PYTHON ISOLATED TEST : {result}, {result.stderr.decode()}, {result.stdout.decode()}")
