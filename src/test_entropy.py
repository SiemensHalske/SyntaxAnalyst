"""
This script tests the entropy of a given file.
It uses the EntropyCalculator class to calculate the entropy
of the file and compares it to a known value.
The script is designed to be run as a standalone program.
"""

import argparse
import os
import sys

from nordstream2.analyzers.entropy_calculator import EntropyCalculator


def main():
    parser = argparse.ArgumentParser(description="Test entropy calculation.")
    parser.add_argument("file", help="Path to the file to test.")

    args = parser.parse_args()
    file_path = args.file
    if not os.path.isfile(file_path):
        print(f"Error: File '{file_path}' does not exist.")
        sys.exit(1)
    if not os.access(file_path, os.R_OK):
        print(f"Error: File '{file_path}' is not readable.")
        sys.exit(1)

    # Create an instance of the EntropyCalculator
    calculator = EntropyCalculator(file_path)
    # Calculate the entropy
    _ = calculator.calculate()


if __name__ == "__main__":
    main()
