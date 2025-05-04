import tempfile
import shutil
import os
import binwalk

from nordstream2.analyzers import Analyzer


class EmbeddedDataExtractor(Analyzer):
    """
    Extracts embedded data from the binary file using binwalk.
    Identifies and extracts embedded resources (e.g. images, compressed files).
    """

    def extract(self):
        """
        Uses binwalk to scan and extract embedded resources from the binary file.
        Extracted file paths are returned as a list.
        """
        self.logger.info("Extracting embedded data...")

        if not os.path.exists(self.sample_path):
            self.logger.error(f"File does not exist: {self.sample_path}")
            return []

        # Create a temp dir for extracted files
        extract_dir = tempfile.mkdtemp(prefix="nordstream2_embedded_")

        try:
            binwalk.scan(self.sample_path,
                         signature=True,
                         extract=True,
                         quiet=True,
                         directory=extract_dir)

            # Collect all extracted files
            extracted_files = []
            for root, _, files in os.walk(extract_dir):
                for f in files:
                    extracted_files.append(os.path.join(root, f))

            self.logger.info(f"Extracted {len(extracted_files)} files.")
            return extracted_files
        except Exception as e:  # pylint: disable=broad-except
            self.logger.error(f"Binwalk extraction failed: {e}")
            return []

        # Optional: clean up after use
        # shutil.rmtree(extract_dir)
        finally:
            # Ensure the temp directory is removed
            if os.path.exists(extract_dir):
                shutil.rmtree(extract_dir)
