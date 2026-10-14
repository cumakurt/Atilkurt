"""Shared isolated environments for shell integration tests."""

import os
from pathlib import Path
import site
import subprocess
import venv

import pytest


@pytest.fixture
def prepared_python_environment(tmp_path):
    """Reuse installed test dependencies in an isolated, offline environment."""
    environment_dir = tmp_path / "python environment"
    venv.EnvBuilder(with_pip=False, symlinks=os.name != "nt").create(environment_dir)
    python = environment_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    result = subprocess.run(
        [str(python), "-c", "import site; print(site.getsitepackages()[0])"],
        capture_output=True, text=True, check=True, timeout=10,
    )
    packages = Path(result.stdout.strip())
    packages.mkdir(parents=True, exist_ok=True)
    (packages / "test_dependencies.pth").write_text(
        "\n".join(site.getsitepackages()) + "\n", encoding="utf-8",
    )
    return environment_dir

