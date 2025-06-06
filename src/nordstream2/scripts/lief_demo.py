"""
just to see if pylint wants to fuck with me
or if lief has some import problem. but i think
i know whos the sucker here...
"""

import sys
import zipfile
from pathlib import Path

import lief


def main():
    if len(sys.argv) != 2:
        print("Usage: python test_lief.py <sample_path>")
        sys.exit(1)

    sample_path = Path(sys.argv[1])

    if not sample_path.exists():
        print(f"File not found: {sample_path}")
        sys.exit(1)

    try:
        if zipfile.is_zipfile(sample_path):
            print("File type: ZIP (probably APK)")
            return

        binary = lief.parse(str(sample_path))  # pylint: disable=no-member

        if binary is None:
            print("Could not parse file using LIEF.")
            return

        # This will show something like 'ELF', 'PE', 'MACHO', etc.
        print(f"File type: {binary.format.name}")

    except Exception as e:
        print(f"Error while analyzing file: {e}")


if __name__ == "__main__":
    main()
