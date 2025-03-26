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
    cmd_pattern = r'(?i)(cmd\.exe|powershell|curl|wget|bash|sh|python|perl|php|gcc|g\+\+|javac|java|node|npm|pip|ruby|gem|make|cmake|msbuild|nmake|cl|csc|ld|as|gas|nasm)'
    min_length = 4

    def __init__(self):
        self.logger = PipelineLogger(use_json=False)

    def _get_section_data(self, filename):
        """
        Concatenate all binary sections into a single byte stream.
        """
        binary = lief.parse(filename)  # pylint: disable=no-member
        if binary is None:
            print("Error: Unable to parse the binary.")
            return None

        section_data = b"".join(bytes(section.content) for section in binary.sections)
        return section_data

    def _extract_suspicous_strings(self, strings_list):
        """
        Classify strings based on suspicious patterns (URLs, IPs, commands).
        """
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

        return suspicious_urls, suspicious_ips, suspicious_commands

    def run(self, sample: Sample):
        """
        Run the string extraction subtask on the given sample.
        """
        strings_list = self.extract_strings_from_binary(sample.file_path)

        # String classification logic
        suspicious_urls, suspicious_ips, suspicious_commands = self._extract_suspicous_strings(strings_list)

        try:
            section_data = self._get_section_data(sample.file_path)
            if section_data is not None:
                found_unicode = re.findall(
                    rb'(?:[\x00-\x7F]{2}){' + str(self.min_length).encode() + rb',}', section_data)
            else:
                found_unicode = []
            unicode_strings = [
                s.decode('utf-16-le', errors='replace') for s in found_unicode
            ]
            strings_list.extend(unicode_strings)
        except UnicodeDecodeError:
            print("Error: Unable to decode Unicode strings.")

        # Assemble JSON output with deduplication
        output = {
            "raw_strings": list(set(strings_list)),
            "suspicious": {
                "urls": list(set(suspicious_urls)),
                "ips": list(set(suspicious_ips)),
                "commands": list(set(suspicious_commands))
            }
        }

        # Log the output
        self.logger.info(output)

        return output

    def extract_strings_from_binary(self, filename, min_length=4):
        """
        Extract ASCII strings from a binary file using LIEF.
        """
        binary = lief.parse(filename)  # pylint: disable=no-member
        if binary is None:
            print("Error: Unable to parse the binary.")
            sys.exit(1)

        strings_list = []
        for section in binary.sections:
            section_data = bytes(section.content)
            found_strings = re.findall(
                rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}', section_data)
            strings_list.extend(
                [s.decode('latin1', errors='replace') for s in found_strings])

        return strings_list
