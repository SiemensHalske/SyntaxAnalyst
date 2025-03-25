import re
import sys
import lief
from nordstream.config import Sample
from nordstream.utils import PipelineLogger
from nordstream.stage2.base import SubtaskBase

class StringExtractor(SubtaskBase):
    """
    🧩 Subtask A – String Extraction & Classification
    🎯 Purpose
        - Extract readable strings and flag suspicious or IOC-related content.

    🔍 Details
        - Identify and categorize:
            - IP addresses, URLs, domains
            - Filenames, registry keys, mutexes
            - Command line artifacts (cmd.exe, powershell, curl, etc.)
            - Base64 or encoded-looking strings
        - Filter common false positives (junk chars, padding, random unicode)

    🛠️ Tools/Packages
        - `strings-cli` (external binary alternative)
        - `python-magic` (for encoding detection)
        - Custom Python regex-based classifier (likely wanna have this handcrafted)

    📦 Output
        - JSON per sample:
            {
              "raw_strings": [...],
              "suspicious": {
                  "urls": [...],
                  "ips": [...],
                  "commands": [...]
              }
            }
        - Embedded into Sample.strings attribute.
    """

    url_pattern = r'(https?|ftp)://[^\s/$.?#].[^\s]*'
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    cmd_pattern = r'(?i)(cmd\.exe|powershell|curl|wget|bash|sh|python|perl|php|gcc|g\+\+|javac|java|node|npm|pip|ruby|gem|gcc|g\+\+|make|cmake|msbuild|nmake|cl|csc|ld|as|gas|nasm'

    def __init__(self):
        self.logger = PipelineLogger(use_json=False)

    def run(self, sample: Sample):
        """
        Run the string extraction subtask on the given sample.
        """

        strings_list = self.extract_strings_from_binary(sample.file_path)
        
        # String classification logic
        suspicious_urls = []
        suspicious_ips = []
        suspicious_commands = []

        for s in strings_list:
            if re.search(self.url_pattern, s):
                suspicious_urls.append(s)
            elif re.search(self.ip_pattern, s):
                suspicious_ips.append(s)
            elif re.search(self.cmd_pattern, s):
                suspicious_commands.append(s)

        
        # Assemble JSON output
        output = {
            "raw_strings": strings_list,
            "suspicious": {
                "urls": suspicious_urls,
                "ips": suspicious_ips,
                "commands": suspicious_commands
            }
        }

        # Log the output
        self.logger.info(output)

        return output
    
    def extract_strings_from_binary(self, filename, min_length=4):
        """
        Extract strings from a binary file using LIEF.
        """
        # Parse the binary with LIEF
        binary = lief.parse(filename)  # pylint: disable=no-member
        if binary is None:
            print("Error: Unable to parse the binary.")
            sys.exit(1)
        
        strings_list = []
        # Iterate over all sections in the binary
        for section in binary.sections:
            # Convert section content (a list of ints) to a bytes object
            section_data = bytes(section.content)
            # Use regex to find sequences of printable ASCII characters (from space to ~)
            found_strings = re.findall(rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}', section_data)
            # Decode the bytes to string using latin1 encoding to preserve original characters
            strings_list.extend([s.decode('latin1', errors='replace') for s in found_strings])
        
        return strings_list