#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script Name: nordsream/stage1/stage1.py
Author: Hendrik Siemens
Date Created: 2025-03-21
Last Modified: 2025-03-23
Version: 0.1

Description:
    This script represents the first stage of the malware analysis pipeline.
    It is responsible for preparing malware samples for further analysis. The
    processed samples are stored as `Sample` objects and metadata can be saved
    to a JSON file.

Usage:
    python3 nordsream/stage1/stage1.py [options]

Requirements:
    - Python >= 3.6
    - Additional libraries: rich, magic, os, json, uuid, datetime, pathlib

License:
    To be determined.

Copyright (c) 2025 Hendrik Siemens
"""

import os
import json
import uuid
from typing import Union
from datetime import datetime
from pathlib import Path

import magic
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from rich.prompt import Prompt
from rich.panel import Panel
from rich.text import Text
from rich import print  # pylint: disable=redefined-builtin, unused-import

from nordstream.config import (
    AllowedTypes, Sample, HashValidator, calculate_file_hashes, init_sample_tree
)

NEVER_RUN = False


class Stage1:
    """
    Stage 1: Input - Malware Samples

    This class represents the first stage of the malware analysis pipeline.
    It is responsible for preparing malware samples for further analysis.

    For further stages, the processed data are stored in `self.samples` as a list of `Sample`
    objects. Metadata could also be saved to a JSON file if `save_metadata` is set to `True`.
    """

    def __init__(
        self,
        in_file: str = None,
        out_dir: str = None,
        batch: bool = False,
        save_meta: bool = False
    ):
        """
        Initialize the Stage1 object.

        Args:
            input_file (str): Path to the input file or directory containing malware samples.
            output_dir (str): Directory where the processed samples will be saved.
            batch_mode (bool): Flag to enable batch processing of multiple samples.
        """

        self.input_file = in_file
        self.input_path_full = Path(in_file)
        self.output_dir = out_dir
        self.batch_mode = batch
        self.save_metadata = save_meta
        self.samples = []
        self.console = Console()

    def display_summary(self, sample: Sample) -> None:
        """
        Display a summary of the processed malware sample.

        Args:
            sample (Sample): The processed malware sample.
        """

        title = Text(
            f"Summary of Malware Sample: {sample.name}", style="bold cyan")

        table = Table(title=title, show_header=False)
        table.add_column("Attribute", justify="right", style="cyan")
        table.add_column("Value", style="magenta")

        table.add_row("File Path", sample.file_path)
        table.add_row("Name", sample.name)
        table.add_row("Size", str(sample.size) + " bytes")
        table.add_row("File Type", sample.file_type)
        table.add_row("Encoding", sample.encoding)
        table.add_row("MD5 Hash", sample.md5)
        table.add_row("SHA256 Hash", sample.sha256)
        table.add_row("Timestamp", sample.timestamp)

        self.console.print(table)

    def process_samples(self) -> bool:
        """
        Process the malware samples based on the input provided.
        """
        if self.batch_mode:
            self.console.print(
                "[bold]Processing samples in batch mode...[/bold]")
            ack = self.process_batch()
        else:
            self.console.print("[bold]Processing a single sample...[/bold]")
            ack = self.process_single()

        if not ack:
            self.console.print(
                "[bold red]Error:[/bold red] Failed to process samples.")
            return False

        if not self.save_metadata:
            self.console.print("[bold]Metadata not saved.[/bold]")
            return True

        ack = self.save_metadata_to_file()
        if not ack:
            self.console.print(
                "[bold red]Error:[/bold red] Failed to save metadata.")
            return False

        return True

    def process_file(self, file_path: str) -> Sample:
        """
        Process a single malware sample file.

        Args:
            file_path (str): Path to the malware sample file.

        Returns:
            Sample: Information about the processed malware sample.
        """
        file_uuid = str(uuid.uuid4())
        sample_tree = init_sample_tree()
        if not self.ensure_file(file_path):
            # Create an empty sample object with a uuid,
            # but no other information, to indicate that the file was not processed,
            # and keeping the pipeline running and consistent.
            time_stamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            sample = Sample(
                uuid=file_uuid,
                hashes=sample_tree,
                timestamp=time_stamp,
                data={}
            )

        file_name = Path(file_path).name
        file_size = Path(file_path).stat().st_size

        # get the hashes of stage1
        sample_tree["stage1_hashes"] = calculate_file_hashes(1, file_path)

        file_timestamp = datetime.fromtimestamp(
            Path(file_path).stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')

        meta_file = self.analyze_file(file_path)
        if meta_file:
            file_type, encoding = meta_file
        else:
            file_type, encoding = "Unknown", "Unknown"

        sample = Sample(
            file_path=file_path,
            name=file_name,
            size=file_size,
            file_type=file_type,
            encoding=encoding,
            hashes=sample_tree,
            timestamp=file_timestamp
        )

        # -----
        # Hash Validation
        # -----

        sample = HashValidator.comp_hash(sample, 1)
        # -----

        return sample

    def process_single(self):
        """
        Process a single malware sample.
        """
        if not self.input_file:
            self.input_file = Prompt.ask(
                "Enter the path to the malware sample:")

        if not Path(self.input_file).exists():
            self.console.print("[bold red]Error:[/bold red] File not found.")
            return False

        sample = self.process_file(self.input_file)
        self.samples.append(sample)

        self.display_summary(sample)

    def process_batch(self) -> bool:
        """
        Process multiple malware samples.
        In this case `input_file`  represents a directory containing multiple samples.
        """

        if not self.input_file:
            self.input_file = Prompt.ask(
                "Enter the path to the directory containing malware samples:")

        if not Path(self.input_file).exists():
            self.console.print(
                "[bold red]Error:[/bold red] Directory not found.")
            return False

        files = [f for f in os.listdir(self.input_file) if os.path.isfile(
            os.path.join(self.input_file, f))]

        if NEVER_RUN:
            with Progress() as progress:
                task = progress.add_task(
                    "[cyan]Processing samples...", total=len(files))

                for file in files:
                    file_path = os.path.join(self.input_file, file)
                    sample = self.process_file(file_path)
                    self.samples.append(sample)
                    progress.update(task, advance=1)
        else:
            for file in files:
                file_path = os.path.join(self.input_file, file)
                sample = self.process_file(file_path)
                self.samples.append(sample)

        for sample in self.samples:
            self.display_summary(sample)

        self.console.print(
            "\n[green][bold]Batch processing completed.[/bold][/green]")
        return True

    def analyze_file(self, in_file) -> Union[tuple, bool]:
        """
        Analyze the file type and encoding using the 'magic' module.

        Args:
            input_file (str): Path to the input file.

        Returns:
            tuple: (file_type, encoding) if successful.
            bool: False if the operation fails.
        """

        if not os.path.exists(in_file):
            self.console.print(
                f"[bold red]Error:[/bold red] File not found: {in_file}")
            return False

        try:
            # Initialize magic for MIME type and encoding detection
            mime_detector = magic.Magic(mime=True)  # For MIME type detection
            encoding_detector = magic.Magic(
                mime_encoding=True)  # For encoding detection

            # Detect file type and encoding
            file_type = mime_detector.from_file(in_file)
            encoding = encoding_detector.from_file(in_file)

            # Return results as a tuple
            return file_type, encoding

        # pylint: disable=broad-except
        except Exception as e:
            self.console.print(
                f"[bold red]Error:[/bold red] Failed to analyze file '{in_file}': {str(e)}")
            return False

    def save_metadata_to_file(self) -> bool:
        """
        Save the metadata of the processed samples to a JSON file.
        """
        # Ensure the output directory is specified
        if not self.output_dir:
            self.output_dir = Prompt.ask(
                "Enter the path to the output directory:")

        # Check if the directory exists, create it if not
        try:
            if not Path(self.output_dir).exists():
                self.console.print(
                    "[bold yellow]Warning:[/bold yellow] Output directory "
                    f"'{self.output_dir}' does not exist. Creating it..."
                )
                Path(self.output_dir).mkdir(parents=True, exist_ok=True)

        # pylint: disable=broad-except
        except Exception as e:
            self.console.print(
                "[bold red]Error:[/bold red] Failed to create output directory "
                f"'{self.output_dir}': {str(e)}"
            )
            return False

        # Ensure there are samples to save
        if not self.samples:
            self.console.print(
                "[bold red]Error:[/bold red] No samples to save. "
                "Metadata file will not be created."
            )
            return False

        # Generate metadata file name
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        file_name = f"metadata_{timestamp}.json"
        metadata_file = os.path.join(self.output_dir, file_name)

        try:
            # Write metadata to the JSON file
            with open(metadata_file, "w", encoding="utf-8") as file:
                metadata = [sample.__dict__ for sample in self.samples]
                json.dump(metadata, file, indent=4)

            self.console.print(
                f"\n[bold green]Success:[/bold green] Metadata saved to: {metadata_file}")
            return True
        # pylint: disable=broad-except
        except Exception as e:
            self.console.print(
                "[bold red]Error:[/bold red] Failed to write metadata to file "
                f"'{metadata_file}': {str(e)}"
            )
            return False

    def ensure_file(self, file_path: str) -> bool:
        """
        Ensure that the provided file is valid and accessible.
        """

        if not Path(file_path).exists():
            self.console.print(
                f"[bold red]Error:[/bold red] File not found: {file_path}")
            return False

        if not Path(file_path).is_file():
            self.console.print(
                f"[bold red]Error:[/bold red] Invalid file: {file_path}")
            return False

        if not os.access(file_path, os.R_OK):
            self.console.print(
                f"[bold red]Error:[/bold red] Permission denied: {file_path}")
            return False

        # check if the file extension is in the allowed types
        file_type = Path(file_path).suffix[1:].upper()
        if file_type not in AllowedTypes.__dict__.values():
            self.console.print(
                f"[bold red]Error:[/bold red] Invalid file type: {file_type}")
            return False

        return True

    def run(self):
        """
        Run the Stage 1 pipeline.
        """
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.console.print(Panel.fit(
            "[bold cyan]Stage 1: Input - Malware Samples[/bold cyan]\n"
            f"[bold]Timestamp:[/bold] {timestamp}\n",
            title="Pipeline Stage"
        ))
        self.process_samples()


if __name__ == "__main__":
    BASE_PATH = "C:\\Users\\Hendrik.Siemens\\Documents\\SyntaxAnalyst\\pipeline_scripts"
    input_file = os.path.join(BASE_PATH, "input")
    output_dir = os.path.join(BASE_PATH, "output")
    BATCH = True
    SAVE_META = True

    stage1 = Stage1(
        in_file=input_file, out_dir=output_dir,
        batch=BATCH, save_meta=SAVE_META
    )
    stage1.run()
