from hashlib import md5, sha256, sha1
from dataclasses import dataclass, field

@dataclass
class AllowedTypes:
    """
    Data class to store allowed file types.
    """
    PE: str = "PE"
    ELF: str = "ELF"
    DLL: str = "DLL"
    EXE: str = "EXE"
    BIN: str = "BIN"
    UNKNOWN: str = "UNKNOWN"


@dataclass
class HashTree:
    """Data class to store hash tree information."""
    stage_id: int = -1
    MD5: str = ""
    SHA1: str = ""
    SHA256: str = ""
    hok: bool = True  # used to indicate if the hashes of this stage are OK


@dataclass
class Sample:
    """
    Data class to store information about a malware sample.
    """
    uuid: str
    file_path: str = ''
    name: str = ''
    size: int = 0
    file_type: str = AllowedTypes.UNKNOWN
    encoding: str = ''
    hashes: dict = field(default_factory=lambda: {
        "stage1_hashes": HashTree(),
        "stage2_hashes": HashTree(),
        "stage3_hashes": HashTree()
    })
    timestamp: str = ''
    data: dict = field(default_factory=lambda: {
        "strings": {},
        "headers": {},
        "embedded_data": {},
        "opcodes": {},
        "entropy": {},
        "imports": {},
        "exports": {},
    })

    def __str__(self):
        return f"Sample: {self.name} ({self.file_type})"


class HashValidator:
    """
    Class to validate hash values of a file
    through the different stages of the pipeline. 
    """

    @staticmethod
    def comp_hash(sample: Sample, stage_nr: int) -> bool:
        """
        Compare the hash values of a file with the hash values stored in the sample object.

        Conditions:
            1) The actual file hash values match the hash values of the current stage.
            2) The file hash of the current stage matches the hash values of previous stages.
            3) The actual file hash values match the hash values of the previous stages.
        """

        # Initialize hok_flag to False (fail-safe default)
        hok_flag = False

        # Read file data
        with open(sample.file_path, "rb") as f:
            data = f.read()

        # Generate hash values from the file
        file_hashes = HashValidator.get_hashes(data)
        sample_hash_tree = sample.hashes

        # Stage-specific checks
        if stage_nr == 1:
            # Validate hashes for stage 1
            if file_hashes == (sample_hash_tree.stage1_hashes.MD5, sample_hash_tree.stage1_hashes.SHA1, sample_hash_tree.stage1_hashes.SHA256):
                hok_flag = True  # Set to True only if all conditions are met

        elif stage_nr == 2:
            # Validate hashes for stage 2
            if file_hashes == (sample_hash_tree.stage2_hashes.MD5, sample_hash_tree.stage2_hashes.SHA1, sample_hash_tree.stage2_hashes.SHA256):
                hok_flag = True

            # Compare against stage 1 hashes
            if file_hashes != (sample_hash_tree.stage1_hashes.MD5, sample_hash_tree.stage1_hashes.SHA1, sample_hash_tree.stage1_hashes.SHA256):
                hok_flag = False  # Reset to False if mismatch occurs

        elif stage_nr == 3:
            # Validate hashes for stage 3
            if file_hashes == (sample_hash_tree.stage3_hashes.MD5, sample_hash_tree.stage3_hashes.SHA1, sample_hash_tree.stage3_hashes.SHA256):
                hok_flag = True

            # Compare against previous stages
            for i in range(1, stage_nr):
                current_stage_hashes = sample_hash_tree[f"stage{i}_hashes"]
                if file_hashes != (current_stage_hashes.MD5, current_stage_hashes.SHA1, current_stage_hashes.SHA256):
                    hok_flag = False  # Reset to False if mismatch occurs
                    break  # Exit loop early if any condition fails

        # Update the sample object with the hok_flag result
        sample.hashes[f"stage{stage_nr}_hashes"].hok = hok_flag

        # Return the modified sample object
        return sample

    @staticmethod
    def get_hashes(data: bytes) -> tuple:
        """
        Calculate MD5, SHA1, and SHA256 hashes for a given data block.
        """
        return md5(data).hexdigest(), sha1(data).hexdigest(), sha256(data).hexdigest()


def init_sample_tree() -> dict:
    """
        Generate a dictionary with empty hash trees.
        """
    return {
        "stage1": HashTree(),
        "stage2": HashTree(),
        "stage3": HashTree()
    }


def calculate_file_hashes(stage_nr: int, file_path: str) -> dict:
    """
    Calculate MD5, SHA1, and SHA256 hashes for a file.
    """

    # Initialize the hash tree
    hash_tree = HashTree(stage_id=stage_nr)

    # Read the file in binary mode
    with open(file_path, "rb") as f:
        data = f.read()

    # Calculate the hashes
    hash_tree.MD5, hash_tree.SHA1, hash_tree.SHA256 = HashValidator.get_hashes(
        data)

    return hash_tree
