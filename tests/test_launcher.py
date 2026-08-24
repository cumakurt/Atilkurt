"""Integration tests for the Linux launcher."""

import os
import subprocess
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = PROJECT_ROOT / "run.sh"
DOCKER_ENTRYPOINT = PROJECT_ROOT / "docker-entrypoint.sh"


def launcher_environment(environment_file):
    environment = os.environ.copy()
    for key in (
        "ATILKURT_DOMAIN",
        "ATILKURT_USER",
        "ATILKURT_PASS",
        "ATILKURT_DC_IP",
        "ATILKURT_OUTPUT",
    ):
        environment.pop(key, None)
    environment["ATILKURT_ENV_FILE"] = str(environment_file)
    environment["ATILKURT_VENV_DIR"] = ".venv"
    return environment


def test_launcher_skips_satisfied_dependency_installation(tmp_path):
    environment_file = tmp_path / "missing.env"

    result = subprocess.run(
        [str(LAUNCHER), "--help"],
        cwd=PROJECT_ROOT,
        env=launcher_environment(environment_file),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    assert result.returncode == 0
    assert "Python dependencies already satisfy requirements; installation skipped." in result.stdout


def test_launcher_treats_environment_file_values_as_data(tmp_path):
    marker = tmp_path / "must-not-exist"
    environment_file = tmp_path / ".env"
    environment_file.write_text(
        f"ATILKURT_DOMAIN=$(touch {marker})\n"
        "ATILKURT_USER=auditor\n"
        "ATILKURT_PASS=secret\n",
        encoding="utf-8",
    )
    environment_file.chmod(0o600)

    result = subprocess.run(
        [str(LAUNCHER), "--timeout", "301"],
        cwd=PROJECT_ROOT,
        env=launcher_environment(environment_file),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    assert result.returncode == 2
    assert "--timeout must be between 1 and 300 seconds" in result.stderr
    assert not marker.exists()


def test_docker_entrypoint_uses_domain_as_default_server(tmp_path):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_python = fake_bin / "python3"
    fake_python.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n', encoding="utf-8")
    fake_python.chmod(0o755)
    environment = os.environ.copy()
    environment.update({
        "PATH": f"{fake_bin}:{environment['PATH']}",
        "ATILKURT_DOMAIN": "example.com",
        "ATILKURT_USER": "auditor",
        "ATILKURT_PASS": "synthetic",
        "ATILKURT_OUTPUT": "/output/report.html",
    })
    environment.pop("ATILKURT_DC_IP", None)

    result = subprocess.run(
        ["/bin/sh", str(DOCKER_ENTRYPOINT), "--ssl"],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert result.returncode == 0
    assert result.stdout.splitlines() == [
        "AtilKurt.py",
        "--domain",
        "example.com",
        "--username",
        "auditor",
        "--output",
        "/output/report.html",
        "--ssl",
    ]
