#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Main entry point for the NordStream pipeline.

The original version of this file only contained demonstration logging
statements.  It now orchestrates the three pipeline stages shipped with
the ``nordstream`` package.  Stage 1 prepares ``Sample`` objects from the
given input path, Stage 2 performs static analysis and Stage 3 performs a
simple classification based on the results of Stage 2.
"""

import os

from nordstream.utils import PipelineLogger
from nordstream.stage1.stage1 import Stage1
from nordstream.stage2.stage2 import Stage2
from nordstream.stage3.stage3 import Stage3


def main():
    """Run the three stage NordStream pipeline."""

    logger = PipelineLogger(log_file_prefix="pipeline", use_json=True)

    input_path = os.getenv("NS_INPUT_PATH", "input")
    output_dir = os.getenv("NS_OUTPUT_DIR", "output")

    stage1 = Stage1(in_file=input_path, out_dir=output_dir, batch=True)
    stage1.run()

    stage2 = Stage2(stage1)
    for sample in stage1.samples:
        stage2.run(sample)

    stage3 = Stage3(stage2)
    for sample in stage1.samples:
        stage3.run(sample)

    logger.info("Pipeline completed")
