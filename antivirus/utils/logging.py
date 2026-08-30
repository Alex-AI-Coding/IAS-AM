import logging


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """Return a configured logger for the antivirus backend."""
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        )
        logger.addHandler(handler)

    logger.propagate = False
    return logger
