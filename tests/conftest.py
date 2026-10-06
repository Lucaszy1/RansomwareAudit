import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from RansomwareAudit.config.manager import ConfigManager  # noqa: E402


@pytest.fixture
def cfg(tmp_path):
    """Default config that ignores any config.yaml on disk."""
    return ConfigManager(config_file=str(tmp_path / "missing.yaml"))


def write_text_files(folder, n, words=200):
    os.makedirs(folder, exist_ok=True)
    paths = []
    for i in range(n):
        p = os.path.join(folder, f"notes_{i}.txt")
        with open(p, "w") as f:
            f.write(" ".join(f"word{(i * 7 + j) % 50}" for j in range(words)))
        paths.append(p)
    return paths
