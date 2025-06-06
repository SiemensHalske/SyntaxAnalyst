import lief
import re
import sys

def extract_strings_from_binary(filename, min_length=4):
    # Parse the binary with LIEF
    binary = lief.parse(filename)
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

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python lief_strings.py <binary_file>")
        sys.exit(1)
    
    filename = sys.argv[1]
    strings_list = extract_strings_from_binary(filename)
    
    for s in strings_list:
        print(s)
