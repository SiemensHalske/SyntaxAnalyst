import hashlib
import os
from nordstream2.utils.logger import Bronchiale

class BaseStage:
    """
    Base class for all stages in the Asmageddon pipeline.
    This class provides common functionality for all stages, including
    hash computation and validation.

    :param sample_path: Path to the malware sample file.
    :type sample_path: str
    :param output_dir: Directory where output files will be saved.
    :type output_dir: str
    :param logger: Logger instance for logging messages.
    :type logger: Bronchiale
    """
    def __init__(self, sample_path, output_dir, logger=None):
        self.logger = logger if logger else Bronchiale()
        self.sample_path = sample_path
        self.output_dir = output_dir
        self.initial_hash = self.compute_hash()

    def compute_hash(self):
        self.logger.info("Computing file hash...")
        if not os.path.isfile(self.sample_path):
            self.logger.error(f"File not found: {self.sample_path}")
            return "no_file"
        hasher = hashlib.sha256()
        with open(self.sample_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        file_hash = hasher.hexdigest()
        self.logger.info(f"Computed hash: {file_hash}")
        return file_hash

    def validate_hash(self, previous_hash):
        current_hash = self.compute_hash()
        if current_hash != previous_hash:
            self.logger.error("Hash mismatch detected!")
        else:
            self.logger.info("Hash validation passed.")
        return current_hash