from nordstream.config import Sample

class SubtaskBase:
    """
    Base class for Stage 2 subtasks.
    """

    def run(self, sample: Sample):
        """
        Run the subtask on the given sample.

        Args:
            sample (Sample): The sample to process.
        """
        raise NotImplementedError