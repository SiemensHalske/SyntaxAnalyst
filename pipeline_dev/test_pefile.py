"""
This script is used to showcase the usage of the pefile library
and its general capabilities; more than just extracting strings.
"""

import sys
import pefile

def pefile_test(file_path):
    """
    Showcases the capabilities of the pefile library, including:

    - Parsing the PE header
    - Extracting strings from the binary
    - Listing the imported and exported functions
    - Listing the sections of the binary
    """

    # Parse the PE header
    pe = pefile.PE(filename)

    print("[*] Listing imported functions:")
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        print("[*] Listing imported functions:")
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            print(f"  {entry.dll.decode()}")
            for imp in entry.imports:
                print(f"    {imp.name.decode()}")

    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        print("\n[*] Listing exported functions:")
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                print(f"  {exp.name.decode()}")

    print("\n[*] Listing sections:")
    for section in pe.sections:
        print(f"  {section.Name.decode().strip()}")

    print("\n[*] Extracting strings is not supported by pefile.")
    return []

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python lief_strings.py <binary_file>")
        sys.exit(1)
    
    filename = sys.argv[1]
    extracted_strings = pefile_test(filename)
    
    for string in extracted_strings:
        print(string)