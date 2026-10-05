import subprocess
import sys
from pathlib import Path


def test_main_scan_cli_handles_missing_file():
    cmd = [
        sys.executable,
        "main.py",
        "scan",
        "does_not_exist.bin",
    ]
    result = subprocess.run(
        cmd,
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert '"status": "error"' in result.stdout
