"""Seed one clearly labelled harmless hash match for a classroom demo."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from antivirus.repository.threat_repository import ThreatRepository  # noqa: E402
from antivirus.services.hash_service import HashService  # noqa: E402


def main():
    sample = ROOT / "demo_samples" / "hash-match-demo.txt"
    digest = HashService.calculate_sha256(str(sample))
    ThreatRepository().add_threat(
        name="Educational.Hash.Catalogue",
        category="Harmless demonstration",
        sha256=digest,
        severity="Low",
        description="This harmless sample was deliberately added to demonstrate exact hash matching.",
    )
    print(
        "Added the harmless hash-match sample to the local catalogue. Restart the dashboard to refresh its count."
    )


if __name__ == "__main__":
    main()
