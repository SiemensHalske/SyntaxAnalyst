import sys
import os
import types
import math
import unittest

# Ensure src is on the import path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

# Stub heavy optional dependencies so the nordstream2 package can be imported
for mod in ['binwalk', 'lief', 'pefile', 'capstone']:
    if mod not in sys.modules:
        stub = types.ModuleType(mod)
        if mod == 'capstone':
            stub.Cs = object
            stub.CS_ARCH_X86 = 0
            stub.CS_MODE_64 = 0
        sys.modules[mod] = stub

from nordstream2.analyzers.entropy_calculator import EntropyCalculator


class TestEntropyCalculator(unittest.TestCase):
    def test_entropy_known_sequence(self):
        data = b'aaab'
        calculator = EntropyCalculator('dummy')
        entropy = calculator._get_shannon_entropy(data)
        expected = -(3/4) * math.log2(3/4) - (1/4) * math.log2(1/4)
        self.assertAlmostEqual(entropy, expected, places=6)


if __name__ == '__main__':
    unittest.main()
