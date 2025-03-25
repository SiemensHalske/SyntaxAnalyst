import re
import sys

def extract_strings(filename, min_length=4):
    with open(filename, 'rb') as f:
        data = f.read()
    # Define a regex for printable ASCII characters (adjustable as needed)
    pattern = rb'[%s]{%d,}' % (re.escape(b'abcdefghijklmnopqrstuvwxyz'
                                        b'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                                        b'0123456789'
                                        b'!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ '), min_length)
    result = re.findall(pattern, data)
    # Decode bytes to strings using latin1 encoding to preserve the original bytes
    return [s.decode('latin1') for s in result]

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python extract_strings.py <binary_file>")
        sys.exit(1)
    strings_list = extract_strings(sys.argv[1])
    for s in strings_list:
        print(s)
