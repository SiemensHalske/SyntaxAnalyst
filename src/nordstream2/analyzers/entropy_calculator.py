"""
Entropy Calculator
This module contains the EntropyCalculator class, which is responsible for
calculating the entropy of a binary file. The entropy is a measure of the
randomness or complexity of the data in the file. High entropy values may
indicate compressed or encrypted data, while low values may indicate simple
or repetitive data.
The EntropyCalculator class inherits from the Analyzer class and implements
the calculate method to compute the Shannon entropy of the file.
It uses the logger to log the progress of the calculation.
This module is part of the NordStream2 project, which is designed to
analyze and extract information from binary files, particularly in the
context of malware analysis and reverse engineering.
"""

import numpy as np
from ..analyzers import Analyzer

class EntropyCalculator(Analyzer):
    """
    Calculates the entropy of the binary file.
    This class computes the Shannon entropy of the file, which can be used
    to measure the randomness or complexity of the data.
    High entropy values may indicate compressed or encrypted data, while low
    values may indicate simple or repetitive data.
    """

    def _get_shannon_entropy(self, data: bytes) -> float:
        """
        Calculate the Shannon entropy of the given data.
        :param data: The binary data to analyze.
        :return: The calculated entropy value.
        """
        if not data:
            return 0.0  # Guard against empty input

        # Use np.frombuffer to efficiently create an array without copying data
        data_array = np.frombuffer(data, dtype=np.uint8)

        # Use np.bincount for efficient frequency calculation
        byte_freq = np.bincount(data_array, minlength=256)
        total_bytes = len(data_array)
        probabilities = byte_freq / total_bytes
        probabilities = probabilities[probabilities > 0]

        entropy = -np.sum(probabilities * np.log2(probabilities))
        return entropy

    def calculate(self) -> float:
        """
        Calculates the entropy of the binary file.
        This method computes the Shannon entropy of the file, which can be used
        to measure the randomness or complexity of the data.
        High entropy values may indicate compressed or encrypted data, while low
        values may indicate simple or repetitive data.
        """
        self.logger.info("Calculating entropy...")

        try:
            with open(self.sample_path, 'rb') as f:
                # For huge files, consider processing in chunks.
                data = f.read()

            # Shannon entropy calculation
            entropy = self._get_shannon_entropy(data)

            self.logger.info(f"Entropy calculated: {entropy:.4f}")
            return entropy
        except Exception as e:  # pylint: disable=broad-except
            self.logger.error(f"Error calculating entropy: {str(e)}")
            return 0.0
