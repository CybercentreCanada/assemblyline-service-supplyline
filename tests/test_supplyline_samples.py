import os
import subprocess
import sys

import pytest
from assemblyline.common.importing import load_module_by_path
from assemblyline_service_utilities.testing.helper import TestHelper

# Force manifest location
os.environ["SERVICE_MANIFEST_PATH"] = os.path.join(os.path.dirname(__file__), "..", "service_manifest.yml")

# Setup folder locations
RESULTS_FOLDER = os.path.join(os.path.dirname(__file__), "results")
SAMPLES_FOLDER = os.path.join(os.path.dirname(__file__), "samples")

# Initialize test helper
service_class = load_module_by_path("supplyline.supplyline.Supplyline", os.path.join(os.path.dirname(__file__), ".."))
th = TestHelper(service_class, RESULTS_FOLDER, SAMPLES_FOLDER)


@pytest.mark.parametrize("sample", th.result_list())
def test_sample(sample):
    # pytest does is not compatible with sandlock so we will launch a separate process to run the test in isolation
    # using sandlock. The results are asserted in this parent process
    test_launch = f"""
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultSection
from lxml import etree
from platformdirs import PlatformDirs
import os
import time

import pytest
from assemblyline.common.importing import load_module_by_path
from assemblyline_service_utilities.testing.helper import TestHelper

# Force manifest location
os.environ["SERVICE_MANIFEST_PATH"] = "{os.environ["SERVICE_MANIFEST_PATH"]}"

# Setup folder locations
RESULTS_FOLDER = "{RESULTS_FOLDER}"
SAMPLES_FOLDER = "{SAMPLES_FOLDER}"

# Initialize test helper
service_class = load_module_by_path(
    "supplyline.supplyline.Supplyline", "{os.path.join(os.path.dirname(__file__), "..")}")
th = TestHelper(service_class, RESULTS_FOLDER, SAMPLES_FOLDER)

th.run_test_comparison("{sample}")
"""
    r = subprocess.run([sys.executable, "-c", test_launch], capture_output=True)
    assert r.returncode == 0, f"Test failed for sample {sample} with error: {r.stderr.decode()}"
