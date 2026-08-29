import logging

from antivirus.utils.logging import get_logger


def test_logger_is_named_and_configured():
    logger = get_logger("antivirus.tests")

    assert logger.name == "antivirus.tests"
    assert logger.level == logging.INFO
    assert any(handler for handler in logger.handlers)
