#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Main orchestrator for the SyntaxAnalyst pipeline."""

from nordstream.utils import PipelineLogger
from nordstream.stage1.stage1 import Stage1
from nordstream.stage2.stage2 import Stage2
from nordstream.stage3 import Stage3


def main():
    """Run Stage1, Stage2 and Stage3 sequentially."""
    logger = PipelineLogger(log_file_prefix="pipeline", use_json=True)
    logger.info("Pipeline start")

    try:
        stage1 = Stage1()
        logger.info("Running Stage 1")
        stage1.run()
        logger.info(f"Stage 1 finished with {len(stage1.samples)} sample(s)")

        stage2 = Stage2(stage1)
        stage3 = Stage3(stage2)

        for sample in stage1.samples:
            logger.info(f"Stage 2 start for sample {sample.uuid}")
            stage2.run(sample)
            logger.info(f"Stage 2 finished for sample {sample.uuid}")

            logger.info(f"Stage 3 start for sample {sample.uuid}")
            stage3.run(sample)
            logger.info(f"Stage 3 finished for sample {sample.uuid}")

    except Exception as exc:  # pylint: disable=broad-except
        logger.exception(exc, "Pipeline execution failed")
    else:
        logger.info("Pipeline completed successfully")


if __name__ == "__main__":
    main()
