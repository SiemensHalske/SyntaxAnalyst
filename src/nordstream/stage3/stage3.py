"""Stage 3 of the NordStream pipeline.

This stage performs final processing and classification of a
:class:`~nordstream.config.Sample`.  It expects a ``Sample`` instance
that already contains the results of Stage 2 (strings, headers, embedded
resources, opcodes and entropy information).  The stage applies a very
simple heuristic based on this data to produce a classification label and
score.  The classification result is stored in ``sample.data['classification']``
and the stage 3 hashes are recorded in ``sample.hashes['stage3_hashes']``.
"""

from __future__ import annotations

from typing import Dict

from nordstream.config import Sample, calculate_file_hashes
from nordstream.utils import PipelineLogger
from nordstream.stage2.stage2 import Stage2


class Stage3:
    """Pipeline stage that classifies samples based on Stage 2 output."""

    def __init__(self, stage2: Stage2):
        self.stage2 = stage2
        self.logger = PipelineLogger(use_json=False)

    def _calc_score(self, sample: Sample) -> int:
        """Return a simple suspicion score based on Stage 2 results."""
        score = 0

        strings = getattr(sample, "strings", {}) or {}
        if isinstance(strings, dict):
            suspicious = strings.get("suspicious", {}) or {}
            score += len(suspicious.get("urls", []))
            score += len(suspicious.get("ips", []))
            score += len(suspicious.get("commands", []))

        embedded = getattr(sample, "embedded_data", {}) or {}
        if isinstance(embedded, dict) and embedded.get("files"):
            score += 1

        entropy = getattr(sample, "entropy", 0)
        if isinstance(entropy, (int, float)) and entropy > 7.0:
            score += 1

        return score

    def classify(self, sample: Sample) -> Dict[str, object]:
        """Classify ``sample`` and return a dictionary with the result."""
        score = self._calc_score(sample)
        if score == 0:
            label = "benign"
        elif score <= 2:
            label = "suspicious"
        else:
            label = "malicious"

        return {"label": label, "score": score}

    def run(self, sample: Sample) -> Dict[str, object]:
        """Run Stage 3 on the provided ``sample``."""
        result = self.classify(sample)
        sample.data["classification"] = result
        sample.hashes["stage3_hashes"] = calculate_file_hashes(3, sample.file_path)
        self.logger.info(
            f"Sample {sample.uuid} classified as {result['label']} (score {result['score']})"
        )
        return result