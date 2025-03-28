"""Run script for the pipeline."""

from nordstream.stage2.string_extractor import StringExtractor
from nordstream.config import Sample

if __name__ == "__main__":
    # Sample usage
    sample = Sample(
        uuid="1234",
        timestamp="2021-09-01T12:00:00Z",
        file_path="/home/bortex/schwarzwaldhonig/SyntaxAnalyst/pipeline_dev/FancyBear.GermanParliament"
        )
    extractor = StringExtractor()
    output = extractor.run(sample)
    print(output)