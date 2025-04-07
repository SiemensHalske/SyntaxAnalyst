"""
Extracts strings from the binary file.
This class is responsible for identifying and extracting human-readable strings
from the binary. This can be useful for identifying embedded resources,
configuration data, or other relevant information.
The extracted strings can be used for further analysis or reporting.
"""

import subprocess
from nordstream2.analyzers import Analyzer

class StringExtractor(Analyzer):
    """
    Extracts strings from the binary file.
    This class is responsible for identifying and extracting human-readable strings
    from the binary. This can be useful for identifying embedded resources,
    configuration data, or other relevant information.
    The extracted strings can be used for further analysis or reporting.
    """

    def extract(self):
        self.logger.info("Extracting strings using external `strings` command...")
        cmd = ["strings", "-a", "-n", "4", str(self.sample_path)]  # -a for all data|-n 4 is default
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            strings_output = result.stdout.splitlines()
            self.logger.info(f"Extracted {len(strings_output)} strings.")
            return strings_output
        except subprocess.CalledProcessError as e:
            self.logger.error(f"String extraction failed: {e}")
            return []
        except FileNotFoundError:
            self.logger.error("`strings` utility not found. Please install binutils.")
            return []
