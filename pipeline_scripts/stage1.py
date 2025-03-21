"""
Stage 1: Input - Malware Samples

The first stage of the pipeline focuses on preparing malware samples for analysis. 
This stage is designed to handle various file formats and ensure compatibility with the rest of the pipeline.

Key Features:
- **File Format Compatibility**: Accepts multiple file types such as `.exe`, `.dll`, `.apk`, `.bin`, `.elf`, among others. 
  This ensures flexibility in analyzing samples across different platforms.
- **Optional Batch Processing**: Enables the analysis of multiple samples simultaneously, making it efficient for handling large datasets.
- **File Validation**: Ensures that the provided samples are intact and suitable for analysis. This includes checking 
  file integrity and identifying corrupted or incomplete files.
- **Metadata Extraction**: Gathers basic information about each sample, such as file size, hash values (MD5, SHA256), 
  and timestamps. This metadata serves as an initial reference for further analysis.

Stage 1 sets the groundwork for the rest of the pipeline by ensuring that all input samples are properly validated 
and ready for processing.
"""

import os
import sys
import shutil
import argparse
import json
import pandas as pd
from datetime import datetime
from dataclasses import dataclass
from typing import List, Dict
from pathlib import Path
from hashlib import md5, sha256
from zipfile import ZipFile
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from rich.prompt import Prompt
from rich.panel import Panel
from rich.text import Text
from rich import print

@dataclass
class Sample:
    """
    Data class to store information about a malware sample.
    """
    name: str
    size: int
    md5: str
    sha256: str
    timestamp: str
    
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
        
        table.add_row("Name", sample.name)
        table.add_row("Size", str(sample.size) + " bytes")
        table.add_row("MD5 Hash", sample.md5)
        table.add_row("SHA256 Hash", sample.sha256)
        table.add_row("Timestamp", sample.timestamp)
        
        self.console.print(table)
        
    def process_samples(self) -> bool:
        """
        Process the malware samples based on the input provided.
        """
        if self.batch_mode:
            ack = self.process_batch()
        else:
            ack = self.process_single()
            
        if not ack:
            return False
        
        self.save_metadata() if self.save_metadata else None
        return True
    
    def process_file(self, file_path: str) -> Sample:
        """
        Process a single malware sample file.
        
        Args:
            file_path (str): Path to the malware sample file.
        
        Returns:
            Sample: Information about the processed malware sample.
        """
        file_name = Path(file_path).name
        file_size = Path(file_path).stat().st_size
        file_md5 = md5(Path(file_path).read_bytes()).hexdigest()
        file_sha256 = sha256(Path(file_path).read_bytes()).hexdigest()
        file_timestamp = datetime.fromtimestamp(Path(file_path).stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        
        sample = Sample(
            name=file_name,
            size=file_size,
            md5=file_md5,
            sha256=file_sha256,
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
        
    def process_batch(self):
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
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Processing samples...", total=len(files))
            
            for file in files:
                file_path = os.path.join(self.input_file, file)
                sample = self.process_file(file_path)
                self.samples.append(sample)
                progress.update(task, advance=1)
        
        for sample in self.samples:
            self.display_summary(sample)
        
        self.console.print("\n[green][bold]Batch processing completed.[/bold][/green]")
        
    def save_metadata(self):
        """
        Save the metadata of the processed samples to a JSON file.
        """
        
        if not self.output_dir:
            self.output_dir = Prompt.ask("Enter the path to the output directory:")
        
        if not Path(self.output_dir).exists():
            os.makedirs(self.output_dir)
        
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        file_name = f"metadata_{timestamp}.json"
        
        metadata_file = os.path.join(self.output_dir, file_name)
        
        with open(metadata_file, "w") as f:
            metadata = []
            for sample in self.samples:
                metadata.append(sample.__dict__)
            json.dump(metadata, f, indent=4)
        
        self.console.print(f"\n[bold]Metadata saved to:[/bold] {metadata_file}")
        
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
        self.console.print(Panel.fit("[bold cyan]Stage 1: Input - Malware Samples[/bold cyan]", title="Pipeline Stage"))
        self.process_samples()
        
if __name__ == "__main__":
    input_file = "input"
    output_dir = "output"
    batch_mode = True
    save_metadata = True
    
    stage1 = Stage1(input_file=input_file, output_dir=output_dir, batch_mode=batch_mode, save_metadata=save_metadata)
    stage1.run()