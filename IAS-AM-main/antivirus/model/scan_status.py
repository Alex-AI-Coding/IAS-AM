from enum import Enum


class ScanStatus(str, Enum):
    CLEAN = "clean"
    DETECTED = "detected"
    ERROR = "error"
    SKIPPED = "skipped"
