from hashlib import md5, sha256, sha1
from dataclasses import dataclass

@dataclass



@dataclass
class HashTree:
    """Data class to store hash tree information."""
    stage_id: int = -1
    MD5: str = ""
    SHA1: str = ""
    SHA256: str = ""

@dataclass
class Sample:
    """
    Data class to store infomation about a malware sample.
    """
    file_path: str
    name: str
    size: int
    file_type: str
    encoding: str
    hashes: dict = {
        stage1_hashes: HashTree,
        stage2_hashes: HashTree,
        stage3_hashes: HashTree,
    }
    timestamp: str
    data: dict = {
        strings: dict = None
        headers: dict = None
        embedded_data: dict = None
        opcodes: dict = None
        entropy: dict = None
    }
    
    def __str__(self):
        return f"Sample: {self.name} ({self.file_type})"
    
def init_sample_tree() -> dict
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
    hash_tree.MD5 = md5(data).hexdigest()
    hash_tree.SHA1 = sha1(data).hexdigest()
    hash_tree.SHA256 = sha256(data).hexdigest()
    
    return hash_tree
    