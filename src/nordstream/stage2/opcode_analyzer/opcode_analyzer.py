"""nordstream stage2 opcode analyzer

This module provides the implementation for Subtask D – Opcode Distribution
Analysis.  It disassembles binary files using Capstone and returns a histogram
of opcode mnemonics.  The resulting dictionary can be embedded into a
:class:`~nordstream.config.Sample` instance for further analysis.
"""

from collections import Counter
from typing import Dict

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

from nordstream.config import Sample
from nordstream.utils import PipelineLogger
from nordstream.stage2.base import SubtaskBase


class OpcodeAnalyzer(SubtaskBase):
    """Analyze opcode distribution in a binary sample."""

    def __init__(self):
        self.logger = PipelineLogger(use_json=False)

    def _read_file(self, file_path: str) -> bytes:
        """Read and return the binary data from ``file_path``."""
        try:
            with open(file_path, "rb") as f:
                return f.read()
        except Exception as exc:  # pylint: disable=broad-except
            self.logger.error(f"Failed to read file: {exc}")
            return b""

    def _disassemble(self, data: bytes) -> Counter:
        """Disassemble ``data`` and count opcode mnemonics."""
        disasm = Cs(CS_ARCH_X86, CS_MODE_64)
        disasm.detail = False
        counter: Counter = Counter()
        for ins in disasm.disasm(data, 0x0):
            counter[ins.mnemonic] += 1
        return counter

    def run(self, sample: Sample) -> Dict[str, int]:
        """Execute opcode analysis on ``sample`` and return a frequency map."""
        self.logger.info(f"Analyzing opcode frequency of {sample.file_path}")
        binary = self._read_file(sample.file_path)
        if not binary:
            self.logger.error("No data to analyze.")
            return {}
        try:
            frequencies = self._disassemble(binary)
        except Exception as exc:  # pylint: disable=broad-except
            self.logger.error(f"Disassembly failed: {exc}")
            return {}
        result = dict(frequencies)
        self.logger.debug(f"Opcode histogram: {result}")
        return result
