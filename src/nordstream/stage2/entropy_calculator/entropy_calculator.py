"""Entropy calculation utilities for Stage 2."""

from __future__ import annotations

import numpy as np

from nordstream.utils import PipelineLogger
from nordstream.config import Sample
from nordstream.stage2.base import SubtaskBase


class EntropyCalculator(SubtaskBase):
    """Calculate Shannon entropy for binary samples."""

    def __init__(self):
        self.logger = PipelineLogger(use_json=False)

    def _get_shannon_entropy(self, data: bytes) -> float:
        """Return the Shannon entropy of *data*."""

        if not data:
            return 0.0

        data_array = np.frombuffer(data, dtype=np.uint8)
        byte_freq = np.bincount(data_array, minlength=256)
        total_bytes = len(data_array)
        probabilities = byte_freq / total_bytes
        probabilities = probabilities[probabilities > 0]

        entropy = -np.sum(probabilities * np.log2(probabilities))
        return float(entropy)

    def run(self, sample: Sample):
        """Compute and return the entropy for *sample*."""

        self.logger.info(f"Calculating entropy for {sample.file_path}")
        try:
            with open(sample.file_path, "rb") as f:
                data = f.read()

            entropy = self._get_shannon_entropy(data)
            self.logger.info(f"Entropy calculated: {entropy:.4f}")
            return {"entropy": entropy}
        except Exception as exc:  # pylint: disable=broad-except
            self.logger.error(f"Error calculating entropy: {exc}")
            return {"entropy": 0.0}

