"""
File: nordstream2/stages/stage1/stage.py
"""

import magic
from nordstream2.utils.logger import Bronchiale
from nordstream2.stages import BaseStage


# Stage 1: Preprocessing and File Validation
class Stage1(BaseStage):
    """
    Stage 1: Preprocessing and File Validation
    This stage is responsible for validating the input file, detecting its type,
    and extracting metadata. It ensures that the file meets the required criteria
    before proceeding to the next stage.
    """

    def __init__(self, sample_path, output_dir):
        super().__init__(sample_path, output_dir)
        self.logger = Bronchiale()
        self.metadata = {}

    def file_validation(self):
        """
        Validates the input file to ensure it meets the required criteria.
        This includes checking the file's hash against known values and
        verifying its integrity.

        Criteria:
        - File must exist
        - File must be of a specific type (e.g., EXE, ELF, etc.)
        - File must not be corrupted or tampered with
        - File must have a valid hash (e.g., SHA256)
        - File must not be empty
        """
        self.logger.info("Performing file validation...")

        # Check if file exists
        if not self.sample_path.exists():
            self.logger.error(f"File {self.sample_path} does not exist.")
            raise FileNotFoundError(f"File {self.sample_path} does not exist.")

        if self.sample_path.stat().st_size == 0:
            self.logger.error(f"File {self.sample_path} is empty.")
            raise ValueError(f"File {self.sample_path} is empty.")

        if not self.validate_hash(self.initial_hash):
            self.logger.error(f"File {self.sample_path} has an invalid hash.")
            raise ValueError(f"File {self.sample_path} has an invalid hash.")

        self.validate_hash(self.initial_hash)

    def file_type_detection(self):
        """
        Detects the file type using python-magic.
        This is important for understanding how to process the file further.
        """
        self.logger.info("Detecting file type using python-magic...")
        # Use python-magic to detect the file type
        file_type = magic.from_file(str(self.sample_path), mime=True)
        self.logger.info(f"Detected file type: {file_type}")

        # Group file types into categories

        # Common executable file types for Windows and Linux
        # PE
        pe_types = [
            "application/x-dosexecutable",  # PE
            "application/x-msdownload",  # Windows executable
            "application/x-msdos-program"  # DOS executable
        ]

        # ELF
        elf_types = [
            "application/x-executable",  # ELF
            "application/x-elf",  # ELF binary
            "application/x-pie-executable"  # Position Independent Executable
        ]

        # Mach-O
        mach_o_types = [
            "application/x-mach-binary",
            "application/x-mach-o",
            "application/vnd.apple.binary",
        ]

        # APK
        apk_types = [
            "application/vnd.android.package-archive",
        ]

        executable_types = [
            *pe_types,
            *elf_types,
            *mach_o_types,
            *apk_types
        ]

        # Common archive file types
        archive_types = [
            "application/zip",  # ZIP
            "application/x-tar",  # TAR
            "application/x-gzip",  # GZIP
            "application/x-bzip2",  # BZIP2
            "application/x-7z-compressed"  # 7Z
        ]

        # Common document file types
        document_types = [
            "application/pdf",  # PDF
            "text/plain",  # TXT
            "application/msword",  # DOC
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"  # DOCX
        ]

        # Group file types into categories
        file_type_groups = {
            "executable": executable_types,
            "archive": archive_types,
            "document": document_types
        }

        # Check if the detected file type matches any of the known types
        # If exectuable return either PE, ELF, MachO or APK
        for group, types in file_type_groups.items():
            if file_type in types:
                self.logger.info(f"File type recognized as {group}.")
                if group == "executable":
                    if file_type in pe_types:
                        return "PE"
                    if file_type in elf_types:
                        return "ELF"
                    if file_type in mach_o_types:
                        return "MachO"
                    if file_type in apk_types:
                        return "APK"
                return group

        self.logger.warning("File type not recognized.")
        return "unknown"

    def metadata_extraction(self, file_type: str):
        """
        Extracts metadata from the file.
        This includes file size, timestamps, and other relevant information.
        The metadata is stored in a dictionary for further processing.

        Possible metadata:
        - File size
        - File type
        - Creation date
        - Modification date
        - Access date
        """
        self.logger.info("Extracting metadata from the file...")

        size: int = 0
        creation_date: str = ""
        modification_date: str = ""
        access_date: str = ""

        # Extract file size
        size = self.sample_path.stat().st_size
        self.logger.info(f"File size: {size} bytes")

        # Extract timestamps
        creation_date = self.sample_path.stat().st_ctime
        modification_date = self.sample_path.stat().st_mtime
        access_date = self.sample_path.stat().st_atime
        self.logger.info(
            f"Creation date: {creation_date}, "
            f"Modification date: {modification_date}, "
            f"Access date: {access_date}"
        )

        self.metadata = {
            "hash": self.initial_hash,
            "file_size": size,
            "creation_date": creation_date,
            "modification_date": modification_date,
            "access_date": access_date,
            "file_type": file_type
        }
        self.validate_hash(self.initial_hash)

    def run(self):
        """
        Run the preprocessing stage.
        This includes file validation, file type detection, and metadata extraction.
        """
        self.logger.info("Running Stage 1: Preprocessing")
        self.file_validation()
        file_type = self.file_type_detection()
        self.metadata_extraction(file_type)
        return self.metadata
