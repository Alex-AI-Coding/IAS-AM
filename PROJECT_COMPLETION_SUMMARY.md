# Engineering review status

Premiere Security 1.2 has one maintained source tree, explicit incomplete-scan outcomes, a scan-driven radar, the six-color ocean palette from the reference image, authenticated folder-scoped API access, signed JSON reports, safer exports, optional read-only download monitoring and network visibility.

The new quarantine workflow verifies a detected file's SHA-256, holds an AES-256-GCM encrypted copy, removes the original only after verification, displays engine-provided type/severity and offers restore, restore-as, retry and deletion. Restores refuse existing destinations and retain an encrypted backup. Windows protects the vault key with account-bound DPAPI; POSIX restricts file permissions. Worker cleanup and scanning/quarantine coordination have regression coverage. See [the quarantine guide](docs/QUARANTINE-GUIDE.md) and [validation evidence](docs/VALIDATION.md).

The project is an educational scanner. Completion of its software workflows does not guarantee an IAS passing grade, regulatory compliance or production antivirus protection. The full feature inventory, controls, course mapping, evidence and remaining work are in [the engineering review](docs/IAS-ENGINEERING-REVIEW.md).

Use the root README and Quick Start. The duplicate nested tree has been consolidated, and its original source is recoverable from the baseline commit in Git history.
