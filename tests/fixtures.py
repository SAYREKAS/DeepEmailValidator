import os
import shutil

import pytest


@pytest.fixture(scope="function")
def temp_cache_dir() -> str:
    test_dir = os.path.join(os.path.dirname(__file__), "test_cache")
    os.makedirs(test_dir, exist_ok=True)
    yield test_dir
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir, ignore_errors=True)
