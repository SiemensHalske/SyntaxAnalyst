#!/usr/bin/env python3
import argparse
import hashlib

from nordstream2.utils.logger import Bronchiale
from nordstream2.stages.stage1 import Stage1
from nordstream2.stages.stage2 import Stage2

# Global logger instance
logger = Bronchiale()

def main():
    parser = argparse.ArgumentParser(
        description="Asmageddon - Malware Analysis Pipeline"
    )
    parser.add_argument("-f", "--file", required=True, help="Path to malware sample")
    parser.add_argument("-o", "--output", required=True, help="Output directory")
    args = parser.parse_args()

    logger.info("Starting Asmageddon Pipeline")

    # Stage 1: Preprocessing
    stage1 = Stage1(args.file, args.output)
    metadata = stage1.run()

    # Stage 2: Static Analysis
    stage2 = Stage2(args.file, args.output, metadata)
    report = stage2.run()

    # Placeholder: Save the final report in the output directory
    logger.info("Pipeline completed. Report generated.")

if __name__ == "__main__":
    main()
