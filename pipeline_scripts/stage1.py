import os
import sys
import shutil
import argparse
import json
import pandas as pd
import uuid
from datetime import datetime
from dataclasses import dataclass
from typing import List, Dict
from pathlib import Path
from hashlib import md5, sha256, sha1
from zipfile import ZipFile

import magic
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from rich.prompt import Prompt
from rich.panel import Panel
from rich.text import Text
from rich import print

from .config import Sample, HashTree, calculate_file_hashes

never_run = False
    
class Stage1:
    """
    Stage 1: Input - Malware Samples
    
    This class represents the first stage of the malware analysis pipeline.
    It is responsible for preparing malware samples for further analysis.
    
    For further stages, the processed data are stored in `self.samples` as a list of `Sample` objects.
    Metadata could also be saved to a JSON file if `save_metadata` is set to `True`.
    """
    
    def __init__(self, input_file: str = None, output_dir: str = None, batch_mode: bool = False, save_metadata: bool = False):
        """
        Initialize the Stage1 object.
        
        Args:
            input_file (str): Path to the input file or directory containing malware samples.
            output_dir (str): Directory where the processed samples will be saved.
            batch_mode (bool): Flag to enable batch processing of multiple samples.
        """
        
        self.input_file = input_file
        self.input_path_full = Path(input_file)
        self.output_dir = output_dir
        self.batch_mode = batch_mode
        self.save_metadata = save_metadata
        self.samples = []
        self.console = Console()
    
    def display_summary(self, sample: Sample) -> None:
        """
        Display a summary of the processed malware sample.
        
        Args:
            sample (Sample): The processed malware sample.
        """
        
        title = Text(f"Summary of Malware Sample: {sample.name}", style="bold cyan")
        
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
            self.console.print("[bold]Processing samples in batch mode...[/bold]")
            ack = self.process_batch()
        else:
            self.console.print("[bold]Processing a single sample...[/bold]")
            ack = self.process_single()
            
        if not ack:
            self.console.print("[bold red]Error:[/bold red] Failed to process samples.")
            return False
        
        if not self.save_metadata:
            self.console.print("[bold]Metadata not saved.[/bold]")
            return True
        
        ack = self.save_metadata_to_file()
        if not ack:
            self.console.print("[bold red]Error:[/bold red] Failed to save metadata.")
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
        file_name = Path(file_path).name
        file_size = Path(file_path).stat().st_size
        
        # get the hashes of stage1
        sample_tree = init_sample_tree()
        sample_tree["stage1"] = calculate_file_hashes(1, file_path, sample_tree)
                
        file_timestamp = datetime.fromtimestamp(Path(file_path).stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        
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
            hashes=stage1_hashes,
            timestamp=file_timestamp
        )
        
        return sample
    
    def process_single(self):
        """
        Process a single malware sample.
        """
        if not self.input_file:
            self.input_file = Prompt.ask("Enter the path to the malware sample:")
        
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
            self.input_file = Prompt.ask("Enter the path to the directory containing malware samples:")
        
        if not Path(self.input_file).exists():
            self.console.print("[bold red]Error:[/bold red] Directory not found.")
            return False
        
        files = [f for f in os.listdir(self.input_file) if os.path.isfile(os.path.join(self.input_file, f))]

        if never_run:
            with Progress() as progress:
                task = progress.add_task("[cyan]Processing samples...", total=len(files))
                
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
        
        self.console.print("\n[green][bold]Batch processing completed.[/bold][/green]")
        return True

    def analyze_file(self, input_file) -> tuple or bool:
        """
        Analyze the file type and encoding using the 'magic' module.
        
        Args:
            input_file (str): Path to the input file.
        
        Returns:
            tuple: (file_type, encoding) if successful.
            bool: False if the operation fails.
        """

        
        if not os.path.exists(input_file):
            self.console.print(f"[bold red]Error:[/bold red] File not found: {input_file}")
            return False

        try:
            # Initialize magic for MIME type and encoding detection
            mime_detector = magic.Magic(mime=True)  # For MIME type detection
            encoding_detector = magic.Magic(mime_encoding=True)  # For encoding detection

            # Detect file type and encoding
            file_type = mime_detector.from_file(input_file)
            encoding = encoding_detector.from_file(input_file)

            # Return results as a tuple
            return file_type, encoding

        except Exception as e:
            self.console.print(f"[bold red]Error:[/bold red] Failed to analyze file '{input_file}': {str(e)}")
            return False

    def save_metadata_to_file(self) -> bool:
        """
        Save the metadata of the processed samples to a JSON file.
        """
        # Ensure the output directory is specified
        if not self.output_dir:
            self.output_dir = Prompt.ask("Enter the path to the output directory:")
        
        # Check if the directory exists, create it if not
        try:
            if not Path(self.output_dir).exists():
                self.console.print(f"[bold yellow]Warning:[/bold yellow] Output directory '{self.output_dir}' does not exist. Creating it...")
                Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        except Exception as e:
            self.console.print(f"[bold red]Error:[/bold red] Failed to create output directory '{self.output_dir}': {str(e)}")
            return False
        
        # Ensure there are samples to save
        if not self.samples:
            self.console.print("[bold red]Error:[/bold red] No samples to save. Metadata file will not be created.")
            return False
        
        # Generate metadata file name
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        file_name = f"metadata_{timestamp}.json"
        metadata_file = os.path.join(self.output_dir, file_name)
        
        try:
            # Write metadata to the JSON file
            with open(metadata_file, "w") as f:
                metadata = [sample.__dict__ for sample in self.samples]
                json.dump(metadata, f, indent=4)
            
            self.console.print(f"\n[bold green]Success:[/bold green] Metadata saved to: {metadata_file}")
            return True
        except Exception as e:
            self.console.print(f"[bold red]Error:[/bold red] Failed to write metadata to file '{metadata_file}': {str(e)}")
            return False
    
    def ensure_file(self, file_path: str) -> bool:
        """
        Ensure that the provided file is valid and accessible.
        """
        
        if not Path(file_path).exists():
            self.console.print(f"[bold red]Error:[/bold red] File not found: {file_path}")
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
    base_path = "C:\\Users\\Hendrik.Siemens\\Documents\\SyntaxAnalyst\\pipeline_scripts"
    input_file = os.path.join(base_path, "input")
    output_dir = os.path.join(base_path, "output")
    batch_mode = True
    save_metadata = True
    
    stage1 = Stage1(input_file=input_file, output_dir=output_dir, batch_mode=batch_mode, save_metadata=save_metadata)
    stage1.run()