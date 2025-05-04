from nordstream2.analyzers import Analyzer
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from collections import Counter

class OpcodeAnalyzer(Analyzer):
    """
    Analyzes the opcode frequency in the binary file.
    This class disassembles the binary and analyzes the opcode frequency,
    potentially revealing patterns that could indicate malicious behavior.
    """

    def read_sample(self):
        """
        Reads the binary sample file.
        This method is a placeholder and can be extended to read the sample
        in different ways if needed.
        """
        self.logger.info("Reading sample file...")
        data = None
        try:
            with open(self.sample_path, 'rb') as f:
                data = f.read()
                return data
        except Exception as e:  # pylint: disable=broad-except
            self.logger.error(f"Failed to read file: {e}")
            return None

    def analyze(self):
        """
        Disassembles the binary and analyzes the frequency of opcodes.
        Returns a dict mapping each opcode mnemonic to its frequency.
        """
        self.logger.info("Analyzing opcode frequency...")

        code = self.read_sample()
        if code is None:
            self.logger.error("No data to analyze.")
            return {}

        # Set up Capstone for 64-bit x86. You can make this configurable.
        disasm = Cs(CS_ARCH_X86, CS_MODE_64)
        disasm.detail = False

        opcode_counter = Counter()
        try:
            for instr in disasm.disasm(code, 0x1000):  # arbitrary starting addr
                opcode_counter[instr.mnemonic] += 1
        except Exception as e:
            self.logger.error(f"Disassembly failed: {e}")
            return {}

        return dict(opcode_counter)
