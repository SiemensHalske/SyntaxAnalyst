""""
Look on the entire system for a file 'no_p_hollowing_here.py'
"""

import os

def find_file_in_system(filename):
    """
    Search for a file in the entire system.
    """
    for root, dirs, files in os.walk("/"):
        if filename in files:
            return os.path.join(root, filename)
    return None

if __name__ == "__main__":
    filename = "no_p_hollowing_here.py"
    file_path = find_file_in_system(filename)
    if file_path:
        print(f"File found: {file_path}")
    else:
        print(f"File '{filename}' not found in the system.")