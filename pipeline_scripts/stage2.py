"""
Stage 2 of the pipeline
"""

from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from rich.prompt import Prompt
from rich.panel import Panel
from rich.text import Text
from rich import print

from .config import Sample, HashTree, calculate_file_hashes
from .stage1 import Stage1

class StringExtractor:
    """
    - Use `strings`, or something similar to extract readable text from the binary.
    - Identify suspicious strings (e.g., URLs, IPs, commands, error messages).
    - Save results in a structured format (e.g., JSON) using the 
    """

class HeaderSectionAnalyzer:
    pass

class ExtractEmbeddedData:
    pass

class OpcodeAnalyzer:
    pass

class EntropyCalculator:
    pass

class Stage2:
    """
    Subtask a:
        - Use `strings` to extract readable text from the binary.
        - Identify suspicious strings (e.g., URLs, IPs, commands, error messages).
        - Save results in a structured format (e.g., JSON).
    Subtask b:
        - Parse PE/ELF headers for key details (e.g., entry point, imports, exports).
        - Analyze sections (e.g., `.text`, `.data`, `.rsrc`) for anomalies.
        - Tools: `pefile`, `pyelftools`.
    Subtask c:
        - Use `binwalk` to identify and extract embedded files or compressed data.
        - Look for hidden resources or packed payloads.
    Subtask d:
        - Disassemble code using `capstone` or similar tools.
        - Calculate opcode frequencies to identify unusual patterns.
        - Save results for ML feature extraction.
    Subtask e:
        - Calculate entropy for each section to detect packed or encrypted data.
        - Flag high-entropy regions for further inspection.
    """
    
    def __init__(self, stage1: Stage1):
        self.stage1 = stage1
        
    def run(self):
        """
        Run Stage 2 of the pipeline.
        """
        print("Running Stage 2...")
        for sample in self.stage1.samples:
            print(f"Processing: {sample}")

            # Subtask a: Extract strings
            string_extractor = StringExtractor()
            strings = string_extractor.extract(sample)
            sample.strings = strings
            
            # Subtask b: Analyze headers
            header_analyzer = HeaderSectionAnalyzer()
            headers = header_analyzer.analyze(sample)
            sample.headers = headers
            
            # Subtask c: Extract embedded data
            embedded_data_extractor = ExtractEmbeddedData()
            embedded_data = embedded_data_extractor.extract(sample)
            sample.embedded_data = embedded_data
            
            # Subtask d: Analyze opcodes
            opcode_analyzer = OpcodeAnalyzer()
            opcodes = opcode_analyzer.analyze(sample)
            sample.opcodes = opcodes
            
            # Subtask e: Calculate entropy
            entropy_calculator = EntropyCalculator()
            entropy = entropy_calculator.calculate(sample)
            sample.entropy = entropy
            
            print(f"Completed processingfor sample id: {sample.id}")
            print("Generating file hashes...")
            
            # Calculate file hashes
            sample.hashes["stage2"] = calculate_file_hashes(2, sample.file_path)
            print("File hashes generated.")
        print("Stage 2 completed.")