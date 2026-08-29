import subprocess
import sys


def test_main_scan_cli_handles_missing_file():
    cmd = [
        sys.executable,
        "main.py",
        "scan",
        "does_not_exist.bin",
    ]
    result = subprocess.run(cmd, cwd="C:/Users/dexte/Downloads/anti-virus-ias-project", capture_output=True, text=True)

    assert result.returncode == 0
    assert '"status": "error"' in result.stdout
