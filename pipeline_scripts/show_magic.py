# show_magic.py

import os
import magic
from rich.console import Console
from rich.traceback import install
from rich.panel import Panel

# Initialize Rich for better logging
console = Console()
install(show_locals=True)

def analyze_file(input_file) -> tuple or bool:
    """
    Analyze the file type and encoding using the 'magic' module.
    
    Args:
        input_file (str): Path to the input file.
    
    Returns:
        tuple: (file_type, encoding) if successful.
        bool: False if the operation fails.
    """
    if not os.path.exists(input_file):
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
        return False


if __name__ == "__main__":
    # Path to the input file
    input_file = "input/samples.txt"
    
    # Run the analysis
    result = analyze_file(input_file)
    
    if result:
        file_type, encoding = result
        console.print(Panel(f"File Type: {file_type}", title="File Type", border_style="green"))
        console.print(Panel(f"Encoding: {encoding}", title="Encoding", border_style="blue"))
        console.log(f"[bold green]Analysis Successful![/bold green] Result: {result}")
    else:
        console.log("[bold red]Analysis Failed![/bold red]")
