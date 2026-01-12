"""
Logging Configuration

Sets up structured logging for the MCP server.
All logs go to stderr to keep stdout clean for MCP protocol.
"""

import logging
import os
import sys
from typing import Optional

# Log levels mapping
LOG_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}


class StderrHandler(logging.StreamHandler):
    """Handler that always writes to stderr."""

    def __init__(self):
        super().__init__(sys.stderr)


def setup_logging(level: Optional[str] = None) -> logging.Logger:
    """
    Configure logging for the MCP server.

    All logs go to stderr to keep stdout available for MCP protocol messages.

    Args:
        level: Log level string (DEBUG, INFO, WARNING, ERROR, CRITICAL)
               Defaults to MCP_LOG_LEVEL environment variable or INFO

    Returns:
        The root logger
    """
    if level is None:
        level = os.environ.get("MCP_LOG_LEVEL", "INFO").upper()

    log_level = LOG_LEVELS.get(level, logging.INFO)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Remove any existing handlers
    root_logger.handlers.clear()

    # Create stderr handler
    handler = StderrHandler()
    handler.setLevel(log_level)

    # Create formatter
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)

    # Add handler to root logger
    root_logger.addHandler(handler)

    # Set levels for noisy libraries
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    return root_logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger with the specified name.

    Args:
        name: Logger name (usually __name__)

    Returns:
        Logger instance
    """
    return logging.getLogger(name)
