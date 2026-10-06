"""Copy the six harmless classroom samples to explicitly selected folders.

Standard-library only: this helper can run from the standalone demo kit or
from the repository. It does not run the scanner, seed its database or execute
sample contents.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

SOURCE_DIR = Path(__file__).resolve().parents[1] / "demo_samples"
SAMPLE_NAMES = (
    "clean.txt",
    "hash-match-demo.txt",
    "ransomware-demo.txt",
    "spyware-demo.txt",
    "trojan-demo.txt",
    "worm-demo.txt",
)
DEMO_FOLDER = "IAS-AM-Scan-Demo"


def distribute_samples(
    destinations: list[str | Path],
    copies: int = 1,
    *,
    source_dir: Path = SOURCE_DIR,
    dry_run: bool = False,
) -> list[Path]:
    """Create one reserved demo folder per destination, without replacing files.

    All destinations and source samples are checked before writing. Each copy
    is a separate nested folder containing byte-identical samples, preserving
    the exact-hash demonstration. I/O failures can leave partial demo folders;
    existing folders are never reused, overwritten or removed.
    """
    if not destinations:
        raise ValueError("Choose at least one destination folder or drive.")
    if not 1 <= copies <= 20:
        raise ValueError("Copies must be between 1 and 20 per destination.")

    samples = {}
    for name in SAMPLE_NAMES:
        source = source_dir / name
        if source.is_symlink() or not source.is_file():
            raise ValueError(f"Included sample is missing or linked: {source}")
        samples[name] = source.read_bytes()

    targets = []
    for supplied in destinations:
        destination = Path(supplied).expanduser()
        if destination.is_symlink() or (
            hasattr(destination, "is_junction") and destination.is_junction()
        ):
            raise ValueError(
                f"Choose a folder directly, rather than a link: {supplied}"
            )
        if not destination.is_dir():
            raise ValueError(f"Destination folder or drive does not exist: {supplied}")
        target = destination.resolve() / DEMO_FOLDER
        if target.exists() or target.is_symlink():
            raise ValueError(
                f"Demo folder already exists: {target}. Choose another destination "
                "or move the previous demo folder before trying again."
            )
        if target in targets:
            raise ValueError(f"Destination was selected more than once: {supplied}")
        targets.append(target)

    if dry_run:
        return targets

    for target in targets:
        # Exclusive creation prevents a previously existing folder being reused.
        target.mkdir()
        for number in range(1, copies + 1):
            folder = target / f"location-{number:02d}"
            folder.mkdir()
            for name, content in samples.items():
                with (folder / name).open("xb") as output:
                    output.write(content)
    return targets


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Copy harmless IAS-AM test text to selected folders/drives. "
            "Creates IAS-AM-Scan-Demo beneath each destination."
        )
    )
    parser.add_argument(
        "--destination",
        "-d",
        action="append",
        required=True,
        help="Existing folder or drive. Repeat this option for several locations.",
    )
    parser.add_argument(
        "--copies",
        type=int,
        default=1,
        help="Number of nested sample sets per destination (1-20; default: 1).",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Show planned folders without writing."
    )
    args = parser.parse_args(argv)
    try:
        targets = distribute_samples(
            args.destination, args.copies, dry_run=args.dry_run
        )
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Could not copy samples: {exc}", file=sys.stderr)
        print(
            "Existing files are preserved. An I/O failure can leave a partial "
            "IAS-AM-Scan-Demo folder; inspect it before retrying.",
            file=sys.stderr,
        )
        return 2

    print("Harmless classroom text only. Samples do not execute or copy themselves.")
    for target in targets:
        verb = "Would create" if args.dry_run else "Created"
        print(f"{verb}: {target} ({args.copies * len(SAMPLE_NAMES)} sample files)")
    print(
        "With YARA enabled, each set has four educational matches and one clean "
        "control. The hash sample matches only after scripts/prepare_demo.py "
        "seeds the scanner's local catalogue."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
