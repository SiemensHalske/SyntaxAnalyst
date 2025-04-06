"""
File: nordstream2/utils/logger.py
"""

import logging
from rich.logging import RichHandler



class Bronchiale:
    def __init__(self, name="Asmageddon", level=logging.INFO):
        logging.basicConfig(
            level=level,
            format="%(message)s",
            datefmt="[%X]",
            handlers=[RichHandler()]
        )
        self.logger = logging.getLogger(name)

    def info(self, msg):
        self.logger.info(msg)

    def debug(self, msg):
        self.logger.debug(msg)

    def error(self, msg):
        self.logger.error(msg)

    def warning(self, msg):
        self.logger.warning(msg)