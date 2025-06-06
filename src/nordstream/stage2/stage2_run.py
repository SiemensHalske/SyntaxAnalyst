from concurrent.futures import ThreadPoolExecutor, as_completed
from nordstream.utils import PipelineLogger  # pylint: disable=unused-import
from nordstream.config import calculate_file_hashes
from .stage2 import ExtractEmbeddedData, OpcodeAnalyzer, EntropyCalculator
from .string_extractor import StringExtractor
from .header_analyzer import HeaderSectionAnalyzer

def run(self, sample):
    # `Sample` objects expose the identifier as ``uuid``.  Using ``id``
    # would raise an :class:`AttributeError` and stop the pipeline.
    with self.logger.context({"sample_id": sample.uuid}):
        self.logger.info(f"Processing sample uuid: {sample.uuid}")

        tasks = {
            "strings": StringExtractor(),
            "headers": HeaderSectionAnalyzer(),
            "embedded": ExtractEmbeddedData(),
            "opcodes": OpcodeAnalyzer(),
            "entropy": EntropyCalculator(),
        }

        results = {}

        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_key = {
                executor.submit(tool.run, sample): key
                for key, tool in tasks.items()
            }

            for future in as_completed(future_to_key):
                key = future_to_key[future]
                try:
                    result = future.result()
                    results[key] = result
                # pylint: disable=broad-except
                except Exception as e:
                    self.logger.exception(e, f"Error in subtask '{key}'")
                    results[key] = {}

        # Assign results to the sample
        sample.strings = results["strings"]
        sample.headers = results["headers"]
        sample.embedded_data = results["embedded"]
        sample.opcodes = results["opcodes"]
        sample.entropy = results["entropy"]

        self.logger.info(f"Completed processing for sample uuid: {sample.uuid}")
        # store the newly calculated hashes in the expected ``stage2_hashes``
        # entry of the sample
        sample.hashes["stage2_hashes"] = calculate_file_hashes(2, sample.file_path)
