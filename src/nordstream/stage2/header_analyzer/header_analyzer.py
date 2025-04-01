"""
File: nordstream/stage2/header_analyzer/header_analyzer.py

This module implements Subtask B – Header and Section Analysis, enabling detailed
examination of binary files using the LIEF library. It provides functionality to:

1. Parse binaries and return a LIEF binary object for further inspection.
2. Extract and compile header metadata, including file format and entry point.
3. Collect section-related data such as section names, sizes, virtual addresses,
   and raw content sizes.

Combined, these features facilitate in-depth analysis of executable headers and
sections, helping to detect structural anomalies or irregular configurations.
The extracted metadata is returned in a structured dictionary, allowing for
easy integration into broader analysis pipelines.

Author: Hendrik Siemens
Date: 2025-04-01
Version: 0.1.0
License: MIT
Python version: >=3.8
Requirements: lief
"""

from typing import Optional

import lief

from nordstream.config import Sample
from nordstream.utils import PipelineLogger
from nordstream.stage2.base import SubtaskBase


class HeaderSectionAnalyzer(SubtaskBase):
    """
    🧩 Subtask B – Header and Section Analysis
    🎯 Purpose
        - Parse executable headers and analyze memory sections for structural anomalies.

    🔍 Details
        - PE (Windows): entry point, imports, exports, section sizes and flags
        - ELF (Linux): segments, symbols, stripped or malformed headers
        - Detect unusual sections, non-standard permissions (e.g., RWX)

    🛠️ Tools/Packages
        - `lief` (cross-platform library)

    📦 Output
        - Dictionary structure or JSON with parsed header metadata
    """

    def __init__(self):
        self.logger = PipelineLogger(use_json=False)

    def parse(self, file_path: str) -> Optional[lief.Binary]:  # pylint: disable=no-member
        """
        Parse a binary file and return a LIEF binary object.

        This method uses the LIEF library to parse the binary file at the specified 
        file path. If the parsing is successful, a LIEF binary object is returned, 
        which can be used for further analysis. If the parsing fails, an error is 
        logged, and `None` is returned.

        :param file_path: The path to the binary file to be parsed.
        :type file_path: str
        :return: A LIEF binary object representing the parsed binary, or `None` if 
                 parsing fails.
        :rtype: Optional[lief.Binary]
        :raises Exception: If an unexpected error occurs during parsing.
        """
        try:
            binary = lief.parse(file_path)  # pylint: disable=no-member
            if binary is None:
                self.logger.error("Failed to parse binary: LIEF returned None.")
                return None
        except Exception as e:  # pylint: disable=broad-except
            self.logger.error(f"LIEF parse error: {e}")
            return None
        return binary

    def extract_section_info(self, binary: lief.Binary, header_info: dict):  # pylint: disable=no-member
        """
        Extract detailed information about the sections in the binary.

        This method iterates through all sections in the provided binary object and 
        extracts key attributes for each section, including:
        - The section name.
        - The size of the section.
        - The virtual address where the section is loaded in memory.
        - The size of the raw content in the section.

        The extracted section details are appended to the `sections` list in the 
        provided `header_info` dictionary.

        :param binary: The binary object parsed by the LIEF library.
        :type binary: lief.Binary
        :param header_info: A dictionary containing header metadata, which will be 
                            updated with section details.
        :type header_info: dict
        :return: The updated `header_info` dictionary containing section details.
        :rtype: dict
        """
        for section in binary.sections:
            header_info["sections"].append(
                {
                    "name": section.name,
                    "size": section.size,
                    "virtual_address": hex(section.virtual_address),
                    "content_size": len(section.content)  # Size of raw content
                }
            )
        return header_info

    def extract_header_info(self, binary: lief.Binary):  # pylint: disable=no-member
        """
        Extract metadata from the binary's header.

        This method retrieves key information from the binary's header, including:
        - The binary format (e.g., PE, ELF, Mach-O).
        - The entry point address of the binary.
        - An empty list to hold section details, which will be populated later.

        The extracted information is returned as a dictionary, which serves as the 
        foundation for further analysis of the binary's structure.

        :param binary: The binary object parsed by the LIEF library.
        :type binary: lief.Binary
        :return: A dictionary containing the header metadata and an empty section list.
        :rtype: dict
        """
        header_info = {
            "format": str(binary.format),
            "entrypoint": hex(binary.entrypoint),
            "sections": []
        }
        return header_info

    def run(self, sample: Sample):
        """
        Execute the header and section analysis on the provided binary sample.

        This method performs the following steps:
        1. Parses the binary file using the LIEF library to extract structural information.
        2. Extracts header metadata, including format and entry point details.
        3. Analyzes section information, such as section names, sizes, virtual addresses, 
           and raw content sizes.
        4. Returns the extracted information as a structured dictionary.

        If the binary cannot be parsed or an error occurs during analysis, 
        appropriate error messages are logged, and an empty dictionary is returned.

        :param sample: The binary sample to analyze.
        :type sample: Sample
        :return: A dictionary containing the extracted header and section information.
        :rtype: dict
        :raises Exception: If an unexpected error occurs during analysis.
        :raises lief.exception: If the LIEF library fails to parse the binary.
        """
        try:
            self.logger.info(f"Analyzing binary: {sample.file_path}")
            binary = self.parse(sample.file_path)
            if not binary:
                self.logger.error("Failed to parse binary.")
                return {}

            header_info = self.extract_header_info(binary)
            header_info = self.extract_section_info(binary, header_info)
            self.logger.info("Successfully analyzed binary using LIEF.")
            return header_info
        # pylint: disable=broad-except
        except Exception as e:
            self.logger.error(f"An error occurred during analysis: {e}")
            return {}