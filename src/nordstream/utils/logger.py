#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script Name: src/nordstream/utils/logger.py
Author: Hendrik Siemens
Date Created: 2025-03-22
Last Modified: 2025-03-22
Python Version: 3.9+
Version: 0.3

Description:
    This script provides a custom logging suite for the pipeline module.
    It includes console logging with Rich and file logging with a rotating file handler
    and supports JSON formatting for log files.

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
    Provides console logging with Rich and file logging with a rotating file handler.
    """

    def __init__(self, log_file_prefix="pipeline", max_bytes=5 * 1024 * 1024, backup_count=3, use_json=False):
        """
        Initialize the PipelineLogger.

        Args:
            log_file_prefix (str): Prefix for the log file name (default: "pipeline").
            max_bytes (int): Maximum size of a single log file before rotation (default: 5 MB).
            backup_count (int): Number of backup log files to keep (default: 3).
            use_json (bool): Whether to use JSON format for log files (default: False).
        """
        self.console = Console()
        self.logger = logging.getLogger("PipelineLogger")

        # Configurable log level from environment variable
        log_level = os.getenv("LOG_LEVEL", "INFO").upper()
        self.logger.setLevel(getattr(logging, log_level, logging.INFO))

        # Configurable log directory from environment variable
        log_dir = os.getenv("LOG_DIR", "logs")
        os.makedirs(log_dir, exist_ok=True)

        # Timestamped log file name
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_file = os.path.join(log_dir, f"{log_file_prefix}_{timestamp}.log")

        # Rich Handler for console logging
        rich_handler = RichHandler(console=self.console, show_path=False, markup=True)
        rich_handler.setLevel(self.logger.level)
        self.logger.addHandler(rich_handler)

        # Rotating File Handler for file logging
        file_handler = RotatingFileHandler(log_file, maxBytes=max_bytes, backupCount=backup_count)
        file_handler.setLevel(self.logger.level)

        # Choose JSON or standard formatter for file logging
        if use_json:
            file_handler.setFormatter(JSONFormatter())
        else:
            file_formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
            file_handler.setFormatter(file_formatter)

        self.logger.addHandler(file_handler)

    def log_message(self, message, level):
        """
        Log a message with the specified log level, including contextual information.

        Args:
            message (str): The message to log.
            level (int): The logging level (e.g., logging.INFO, logging.ERROR).
        """
        # Check for sensitive characters
        if '€' in message:
            message = "[redacted]"

        # Add contextual information (function name and line number)
        frame = inspect.currentframe().f_back
        function_name = frame.f_code.co_name
        line_number = frame.f_lineno
        contextual_message = f"[{function_name}:{line_number}] {message}"

        self.logger.log(level, contextual_message)

    def log_exception(self, exception, message="An exception occurred"):
        """
        Log an exception with its traceback.

        Args:
            exception (Exception): The exception to log.
            message (str): Additional message to provide context (default: "An exception occurred").
        """
        self.logger.error(f"{message}: {exception}", exc_info=True)

    def log_info(self, message):
        """Log an informational message."""
        self.log_message(message, logging.INFO)

    def log_warning(self, message):
        """Log a warning message."""
        self.log_message(message, logging.WARNING)

    def log_error(self, message):
        """Log an error message."""
        self.log_message(message, logging.ERROR)

    def log_debug(self, message):
        """Log a debug message."""
        self.log_message(message, logging.DEBUG)

    def log_critical(self, message):
        """Log a critical message."""
        self.log_message(message, logging.CRITICAL)
