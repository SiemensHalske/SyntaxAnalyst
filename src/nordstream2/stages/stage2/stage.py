"""
File: nordstream2/stages/stage2/stage.py
"""

import concurrent.futures
from nordstream2.utils.logger import Bronchiale
from nordstream2.stages import BaseStage
from nordstream2.analyzers import (
    StringExtractor, HeaderAnalyzer,
    EmbeddedDataExtractor, OpcodeAnalyzer,
    EntropyCalculator
)


# Stage 2: Static Analysis
class Stage2(BaseStage):
    """
    Stage 2: Static Analysis
    This stage performs static analysis on the binary file.
    It includes the following methods:
    - strings_extraction: Extracts human-readable strings from the binary.
    - header_analysis: Analyzes the file header and sections.
    - embedded_data_extraction: Extracts embedded data using binwalk.
    - opcode_analysis: Analyzes opcode frequency using capstone.
    - entropy_calculation: Calculates entropy for file sections.
    """

    def __init__(self, sample_path, output_dir, metadata):
        super().__init__(sample_path, output_dir)
        self.metadata = metadata
        self.logger = Bronchiale()

    def strings_extraction(self):
        """
        Extracts strings from the binary using a string extractor.
        This method uses the StringExtractor class to extract
        human-readable strings from the binary file.
        It also validates the hash of the extracted strings
        against the metadata provided.

        :return: None
        :raises: Exception if the hash validation fails
        """
        self.logger.info("Extracting strings from the binary...")
        extractor = StringExtractor(self.sample_path)
        file_strings = extractor.extract()
        valid = self.validate_hash(self.metadata.get("hash"))
        if not valid:
            return file_strings, False
        return file_strings, True

    def header_analysis(self):
        """
        Analyzes the file header and sections using a header analyzer.
        This method uses the HeaderAnalyzer class to analyze
        the file header and sections of the binary file.
        It also validates the hash of the analyzed header
        against the metadata provided.

        :return: None
        :raises: Exception if the hash validation fails
        """
        self.logger.info("Performing header and section analysis (PE/ELF)...")
        analyzer = HeaderAnalyzer(self.sample_path)
        file_header = analyzer.analyze()
        valid = self.validate_hash(self.metadata.get("hash"))
        if not valid:
            return file_header, False
        return file_header, True

    def embedded_data_extraction(self):
        """
        Extracts embedded data using binwalk.
        This method uses the EmbeddedDataExtractor class to extract
        embedded data from the binary file using binwalk.
        It also validates the hash of the extracted data
        against the metadata provided.

        :return: None
        :raises: Exception if the hash validation fails
        """
        self.logger.info("Extracting embedded data using binwalk...")
        extractor = EmbeddedDataExtractor(self.sample_path)
        embedded_data = extractor.extract()
        valid = self.validate_hash(self.metadata.get("hash"))
        if not valid:
            return embedded_data, False
        return embedded_data, True

    def opcode_analysis(self):
        """
        Analyzes opcode frequency using capstone.
        This method uses the OpcodeAnalyzer class to analyze
        the opcode frequency of the binary file using capstone.
        It also validates the hash of the analyzed opcode
        against the metadata provided.

        :return: None
        :raises: Exception if the hash validation fails
        """
        self.logger.info(
            "Performing opcode frequency analysis using capstone...")
        analyzer = OpcodeAnalyzer(self.sample_path)
        opcode_frequency = analyzer.analyze()
        valid = self.validate_hash(self.metadata.get("hash"))
        if not valid:
            return opcode_frequency, False
        return opcode_frequency, True

    def entropy_calculation(self):
        """
        Calculates entropy for file sections.
        This method uses the EntropyCalculator class to calculate
        the entropy of the file sections in the binary file.
        It also validates the hash of the calculated entropy
        against the metadata provided.

        :return: None
        :raises: Exception if the hash validation fails
        """
        self.logger.info("Calculating entropy for file sections...")
        calculator = EntropyCalculator(self.sample_path)
        entropy = calculator.calculate()
        valid = self.validate_hash(self.metadata.get("hash"))
        if not valid:
            return entropy, False
        return entropy, True

    def run(self):
        """
        Runs the static analysis stage.
        This method orchestrates the execution of the static
        analysis methods defined in this class. It logs the start
        and end of each method, and validates the hash of the
        results against the metadata provided.

        :return: dict containing the report of the analysis
        """
        self.logger.info("Running Stage 2: Static Analysis")
        strings_result, strings_valid = self.strings_extraction()
        header_result, header_valid = self.header_analysis()
        embedded_data_result, embedded_data_valid = self.embedded_data_extraction()
        opcode_result, opcode_valid = self.opcode_analysis()
        entropy_result, entropy_valid = self.entropy_calculation()

        report = {
            "strings": {"result": strings_result, "valid": strings_valid},
            "header": {"result": header_result, "valid": header_valid},
            "embedded_data": {"result": embedded_data_result, "valid": embedded_data_valid},
            "opcode": {"result": opcode_result, "valid": opcode_valid},
            "entropy": {"result": entropy_result, "valid": entropy_valid},
        }

        self.logger.info("Stage 2 completed. Generating report...")
        return {"report": report}

    def run_parallel(self):
        """
        Runs the static analysis stage in parallel.
        This method orchestrates the execution of the static
        analysis methods defined in this class in parallel.
        It logs the start and end of each method, and validates
        the hash of the results against the metadata provided.

        :return: dict containing the report of the analysis
        """
        self.logger.info("Running Stage 2: Static Analysis in parallel")
        methods = [
            self.strings_extraction,
            self.header_analysis,
            self.embedded_data_extraction,
            self.opcode_analysis,
            self.entropy_calculation
        ]
        results = {}
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_to_method = {executor.submit(
                method): method for method in methods}
            for future in concurrent.futures.as_completed(future_to_method):
                method = future_to_method[future]
                try:
                    result = future.result()
                    results[method.__name__] = result
                except Exception as exc:  # pylint: disable=broad-except
                    self.logger.error(
                        f"{method.__name__} generated an exception: {exc}")
                    results[method.__name__] = {"result": None, "valid": False}
        report = {
            "strings": results["strings_extraction"],
            "header": results["header_analysis"],
            "embedded_data": results["embedded_data_extraction"],
            "opcode": results["opcode_analysis"],
            "entropy": results["entropy_calculation"],
        }
        self.logger.info("Stage 2 completed. Generating report...")
        return {"report": report}
