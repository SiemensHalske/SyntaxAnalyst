#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script Name: src/nordstream/utils/logger.py
Author: Hendrik Siemens
Date Created: 2025-03-22
Last Modified: 2025-03-22 (Updated for suiteier version)
Python Version: 3.9+
Version: 0.4

Description:
    This script provides an enhanced custom logging suite for the pipeline module.
    It includes console logging with Rich, file logging with a rotating file handler,
    supports JSON formatting for log files, and offers advanced contextual logging via
    a context manager and streamlined logging method definitions.

Usage:
    python3 logger.py

Requirements:
    - Python >= 3.6
    - Additional libraries: rich, logging, logging.handlers, os, json

License:
    To be determined.

Copyright (c) 2025 Hendrik Siemens
"""

import logging
import os
import json
import inspect
from datetime import datetime
from logging.handlers import RotatingFileHandler
from rich.console import Console
from rich.logging import RichHandler
from functools import partialmethod
from contextlib import contextmanager


class JSONFormatter(logging.Formatter):
    """
    A custom logging formatter to output logs in JSON format.
    """

    def format(self, record):
        log_record = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage(),
        }
        return json.dumps(log_record)


class PipelineLogger:
    """
    A dedicated logging suite for the pipeline module.
    Provides console logging with Rich, file logging with a rotating file handler,
    and enhanced contextual logging with support for temporary extra context.
    """

    def __init__(self, log_file_prefix="pipeline", max_bytes=5 * 1024 * 1024, backup_count=3, use_json=False, include_caller_info=True):
        """
        Initialize the PipelineLogger.

        Args:
            log_file_prefix (str): Prefix for the log file name (default: "pipeline").
            max_bytes (int): Maximum size of a single log file before rotation (default: 5 MB).
            backup_count (int): Number of backup log files to keep (default: 3).
            use_json (bool): Whether to use JSON format for log files (default: False).
            include_caller_info (bool): Whether to automatically include caller info in logs (default: True).
        """
        self.include_caller_info = include_caller_info
        self._context = {}  # persistent context for logging

        self.console = Console()
        self.logger = logging.getLogger("PipelineLogger")
        self.logger.propagate = False  # Prevent duplicate logging

        # Set log level from environment variable or default to INFO
        log_level = os.getenv("LOG_LEVEL", "INFO").upper()
        self.logger.setLevel(getattr(logging, log_level, logging.INFO))

        # Ensure log directory exists
        log_dir = os.getenv("LOG_DIR", "logs")
        os.makedirs(log_dir, exist_ok=True)

        # Create a timestamped log file name
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_file = os.path.join(log_dir, f"{log_file_prefix}_{timestamp}.log")

        # Rich Handler for console logging
        rich_handler = RichHandler(console=self.console, show_path=False, markup=True)
        rich_handler.setLevel(self.logger.level)
        self.logger.addHandler(rich_handler)

        # Rotating File Handler for file logging
        file_handler = RotatingFileHandler(log_file, maxBytes=max_bytes, backupCount=backup_count)
        file_handler.setLevel(self.logger.level)
        if use_json:
            file_handler.setFormatter(JSONFormatter())
        else:
            file_formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
            file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)

    def _log(self, level, message, *args, **kwargs):
        # Redact sensitive characters
        if '€' in message:
            message = "[redacted]"

        # Include caller info if enabled
        if self.include_caller_info:
            frame = inspect.currentframe()
            # Attempt to climb two frames safely
            for _ in range(2):
                if frame is not None:
                    frame = frame.f_back
                else:
                    break
            if frame is not None:
                function_name = frame.f_code.co_name
                line_number = frame.f_lineno
                message = f"[{function_name}:{line_number}] {message}"
            else:
                # Optionally, you could log a warning here that caller info wasn't available
                pass

        # Merge persistent context with any extra context provided
        extra = kwargs.pop("extra", {})
        if self._context:
            extra = {**self._context, **extra}
        kwargs["extra"] = extra

        self.logger.log(level, message, *args, **kwargs)

    # Define logging methods using partialmethod for brevity and consistency
    info = partialmethod(_log, logging.INFO)
    info.__doc__ = "Log an informational message."

    warning = partialmethod(_log, logging.WARNING)
    warning.__doc__ = "Log a warning message."

    error = partialmethod(_log, logging.ERROR)
    error.__doc__ = "Log an error message."

    debug = partialmethod(_log, logging.DEBUG)
    debug.__doc__ = "Log a debug message."

    critical = partialmethod(_log, logging.CRITICAL)
    critical.__doc__ = "Log a critical message."

    def exception(self, exception, message="An exception occurred"):
        """
        Log an exception with its traceback.

        Args:
            exception (Exception): The exception to log.
            message (str): Additional message to provide context (default: "An exception occurred").
        """
        self.logger.error(f"{message}: {exception}", exc_info=True)

    @contextmanager
    def context(self, extra):
        """
        Context manager to temporarily add extra context to log messages.

        Args:
            extra (dict): A dictionary of additional context to merge into log records.
        """
        old_context = self._context.copy()
        self._context.update(extra)
        try:
            yield
        finally:
            self._context = old_context

    def set_context(self, extra):
        """
        Set persistent extra context for all log messages.

        Args:
            extra (dict): A dictionary of context data to persist across log messages.
        """
        self._context = extra.copy()


# Example usage (if this script is run directly)
if __name__ == "__main__":
    logger = PipelineLogger(use_json=False)
    logger.info("Pipeline started.")
    with logger.context({"job_id": 42, "user": "Hendrik"}):
        logger.debug("Processing data chunk.")
    try:
        1 / 0
    except Exception as e:
        logger.exception(e, "Division by zero error")
