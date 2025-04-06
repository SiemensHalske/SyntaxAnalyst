"""
To be edited...
"""

import pefile
from nordstream.utils import PipelineLogger
from nordstream.config import Sample
from nordstream.stage2.base import SubtaskBase


class Parser:
    """
    Base class for parsers.
    """

    def __init__(self, parent, use_json: bool = False, file_path: str = ''):
        self.parent = parent
        self.logger = PipelineLogger(use_json=use_json)

        self.file_path = file_path
        self.file_data = None
        self.embedded_data = {}

        self.parse()

    def parse(self) -> dict:
        """
        Parse the binary file and extract relevant information.
        """
        embedded_data = self.parent.parse()
        if not embedded_data:
            self.logger.warning(f"No embedded data found in {self.file_path}")
            return {}
        self.embedded_data = embedded_data
        return self.embedded_data

    def get_data(self) -> dict:
        """
        Get the parsed data.
        """
        try:
            return self.embedded_data
        # pylint: disable=broad-except
        except Exception as e:
            self.logger.error(f"Error getting data: {e}")
            return {}

    def load_file(self) -> bytes:
        """
        Load the file data.
        """
        data = b''
        try:
            with open(self.file_path, 'rb') as f:
                data = f.read()
        except FileNotFoundError as e:
            self.logger.error(
                f"File not found: {self.file_path}\n"
                f"Error: {e}"
            )

        # pylint: disable=broad-except
        except Exception as e:
            self.logger.error(f"Error reading file: {e}")
        return data


class PEParser(Parser):
    """
    🧩 PE Parser
    🎯 Purpose
        - Detect embedded executables, scripts, or archives.
        - Recover known signatures (ZIP, PNG, PE, ELF, etc.)
        - Carve out by offset and type.

    🔍 Details
        - Parse PE files to extract relevant information.
        - Identify and extract embedded data.
        - Detect hidden files, embedded executables, scripts, or archives.
        - Recover known signatures (ZIP, PNG, PE, ELF, etc.)
        - Carve out by offset and type.
        - Detect unusual sections, non-standard permissions (e.g., RWX)
        - Analyze memory sections for structural anomalies.

    🛠️ Tools/Packages specific for PE files
        - `pefile` (for PE files)
        - `pyzipper` (for ZIP files)
        - `py7zr` (for 7z files)
        - `pyexiftool` (for EXIF data)
        - `pyelftools` (for ELF files)

    📦 Output
        - Dictionary structure or JSON with parsed header metadata
        - List of extracted file metadata and paths
        - Referenced in Sample.embedded_data

    """

    def __init__(self, file_path: str = ''):
        super().__init__(self, use_json=False, file_path=file_path)

        self.parse()

    def parse(self) -> dict:
        """
        Parse the PE file and extract relevant information,
        including embedded data and using the pefile library.
        """

        # Load the file data
        self.file_data = self.load_file()
        if not self.file_data:
            self.logger.warning(f"No data found in {self.file_path}")
            return {}

        # PE parsing logic using pefile:
        # - Extract embedded data based on known signatures.
        pef = pefile.PE(data=self.file_data)

        # Extracting embedded data
        for section in pef.sections:
            if section.Name.startswith(b'.rsrc'):
                # Extract resource data
                resource_data = section.get_data()
                self.embedded_data[section.Name.decode(
                    'utf-8')] = resource_data
            elif section.Name.startswith(b'.text'):
                # Extract text data
                text_data = section.get_data()
                self.embedded_data[section.Name.decode('utf-8')] = text_data
            elif section.Name.startswith(b'.data'):
                # Extract data section
                data_section = section.get_data()
                self.embedded_data[section.Name.decode('utf-8')] = data_section

        return self.embedded_data


class ELFParser(Parser):
    """
    Class to parse ELF files.
    """

    def __init__(self, file_path: str = ''):
        super().__init__(self, use_json=False, file_path=file_path)

    def parse(self) -> dict:
        """
        Parse the ELF file and extract relevant information.
        """
        # Placeholder for ELF parsing logic
        return {}


class DLLParser(Parser):
    """
    Class to parse DLL files.
    """

    def __init__(self, file_path: str = ''):
        super().__init__(self, use_json=False, file_path=file_path)

    def parse(self) -> dict:
        """
        Parse the DLL file and extract relevant information.
        """
        # Placeholder for DLL parsing logic
        return {}


class EXEParser(Parser):
    """
    Class to parse EXE files.
    """

    def __init__(self, file_path: str = ''):
        super().__init__(self, use_json=False, file_path=file_path)

    def parse(self) -> dict:
        """
        Parse the EXE file and extract relevant information.
        """
        # Placeholder for EXE parsing logic
        return {}


class BINParser(Parser):
    """
    Class to parse BIN files.
    """

    def __init__(self, file_path: str = ''):
        super().__init__(self, use_json=False, file_path=file_path)

    def parse(self) -> dict:
        """
        Parse the BIN file and extract relevant information.
        """
        # Placeholder for BIN parsing logic
        return {}


class ArchiveParser(Parser):
    """
    Class to parse archive files.
    """

    def __init__(self, file_path: str = ''):
        super().__init__(self, use_json=False, file_path=file_path)

    def parse(self) -> dict:
        """
        Parse the archive file and extract relevant information.
        """
        # Placeholder for archive parsing logic
        return {}


class ExtractEmbeddedData(SubtaskBase):
    """
    🧩 Subtask C – Embedded Data & Resource Extraction
    🎯 Purpose
        - Identify and extract embedded or compressed data within the binary.

    🔍 Details
        - Detect hidden files, embedded executables, scripts, or archives
        - Recover known signatures (ZIP, PNG, PE, ELF, etc.)
        - Carve out by offset and type

    🛠️ Tools/Packages
        - `binwalk` (external binary, or subprocess)
        - `pyunpack`, `patool` (for archive formats)
        - Python packages for extracting embedded data:
            - `pyzipper` (for ZIP files)
            - `py7zr` (for 7z files)
            - `pyexiftool` (for EXIF data)
            - `pyelftools` (for ELF files)
            - `pefile` (for PE files)
            - `pyinstaller` (for PyInstaller archives)


    📦 Output
        - List of extracted file metadata and paths
        - Referenced in Sample.embedded_data
    """

    def __init__(self):
        self.logger = PipelineLogger(use_json=False)

    def __str__(self):
        return "Extract Embedded Data"

    def parse(self, file_path: str, file_type: str) -> dict:
        """
        Parse the binary file and extract embedded data based on file type.
        """

        # Initialize an empty dictionary to store extracted data
        extracted_data = {}

        # Check the file type and call the appropriate extraction method
        if file_type == "PE":
            parser = PEParser(file_path)
            extracted_data = parser.get_data()

        return extracted_data

    def run(self, sample: Sample):
        """
        Run the string extraction subtask on the given sample.
        """

        # Get the file path from the sample
        file_path = sample.file_path
        file_type = sample.file_type

        # Check which type of file it is
        if file_type not in ["PE", "ELF", "DLL", "EXE", "BIN"]:
            self.logger.warning(f"Unsupported file type: {file_type}")
            return {}

        # Parse the file and extract embedded data
        extracted_data = self.parse(file_path, file_type)
        if not extracted_data:
            self.logger.warning(f"No embedded data found in {file_path}")
            return {}
        # Update the sample with the extracted data
        sample.data["embedded_data"] = extracted_data
        self.logger.info(f"Extracted embedded data from {file_path}")
        # Return the extracted data for further processing

        return extracted_data
