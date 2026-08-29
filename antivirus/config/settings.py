from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
RULE_DIR = BASE_DIR / "detection" / "rules"
THREAT_DB_PATH = BASE_DIR / "data" / "threats.db"
QUARANTINE_DIR = BASE_DIR / "data" / "quarantine"
