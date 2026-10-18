
import logging
import logging.handlers
import os
import sys
from pathlib import Path


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

LOG_DIRECTORY = Path(
    os.getenv("LOG_DIRECTORY", "logs")
)

LOG_FILE = LOG_DIRECTORY / "graphguard.log"

VALID_LOG_LEVELS = {
    "DEBUG",
    "INFO",
    "WARNING",
    "ERROR",
    "CRITICAL",
}


# --------------------------------------------------
# LOG FORMAT
# --------------------------------------------------

LOG_FORMAT = (
    "%(asctime)s | "
    "%(levelname)-8s | "
    "%(name)s | "
    "%(message)s"
)

DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


# --------------------------------------------------
# LOGGER SETUP
# --------------------------------------------------

def setup_logging() -> None:
    """
    Configure application-wide logging.

    Logs are written to the console and to a rotating
    log file. Old log files are automatically rotated.
    """
    level_name = (
        LOG_LEVEL
        if LOG_LEVEL in VALID_LOG_LEVELS
        else "INFO"
    )

    log_level = getattr(logging, level_name)

    formatter = logging.Formatter(
        fmt=LOG_FORMAT,
        datefmt=DATE_FORMAT,
    )

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)

    # Prepare the log directory and file.
    try:
        LOG_DIRECTORY.mkdir(
            parents=True,
            exist_ok=True,
        )

        file_handler = logging.handlers.RotatingFileHandler(
            filename=LOG_FILE,
            maxBytes=5 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8",
        )

        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)

        handlers = [
            console_handler,
            file_handler,
        ]

    except OSError:
        # Keep console logging available if the file
        # cannot be created.
        handlers = [console_handler]

    logging.basicConfig(
        level=log_level,
        handlers=handlers,
        force=True,
    )

    logging.captureWarnings(True)

    logging.getLogger(__name__).debug(
        "GraphGuard logging initialized."
    )


# --------------------------------------------------
# LOGGER FACTORY
# --------------------------------------------------

def get_logger(name: str) -> logging.Logger:
    """
    Return a named logger for a module.

    Example:
        logger = get_logger(__name__)
    """
    return logging.getLogger(name)


# --------------------------------------------------
# SECURITY AUDIT LOGGING
# --------------------------------------------------

def log_security_event(
    event_type: str,
    message: str,
    severity: str = "INFO",
) -> None:
    """
    Write a security-related event to the application log.

    Do not include passwords, API keys, access tokens,
    or other sensitive credentials in messages.
    """
    security_logger = logging.getLogger(
        "graphguard.security"
    )

    normalized_severity = severity.upper()

    log_method = getattr(
        security_logger,
        normalized_severity,
        None,
    )

    if not callable(log_method):
        log_method = security_logger.info

    log_method(
        "event_type=%s | %s",
        event_type,
        message,
    )


# --------------------------------------------------
# EXCEPTION LOGGING
# --------------------------------------------------

def log_exception(
    logger: logging.Logger,
    message: str,
) -> None:
    """
    Log an exception with its traceback.

    Call this inside an except block.
    """
    logger.exception(message)


# Initialize logging when this module is imported.
setup_logging()
