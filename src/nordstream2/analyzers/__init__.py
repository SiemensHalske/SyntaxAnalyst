"""
This module contains the Analyzer class for analyzing samples.
"""

from nordstream2.utils.logger import Bronchiale

class Analyzer:
    """
    This class provides methods to analyze the given samples.
    """

    def __init__(self, sample_path):
        self.sample_path = sample_path
        self.logger = Bronchiale()

# pylint: disable=import-outside-toplevel, wrong-import-position
from .embedded_extractor import EmbeddedDataExtractor
from .entropy_calculator import EntropyCalculator
from .header_analyzer import HeaderAnalyzer
from .opcode_analyzer import OpcodeAnalyzer
from .string_extractor import StringExtractor

__all__ = [
    "Analyzer",
    "EmbeddedDataExtractor",
    "EntropyCalculator",
    "HeaderAnalyzer",
    "OpcodeAnalyzer",
    "StringExtractor",
]