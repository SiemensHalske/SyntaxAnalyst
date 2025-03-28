#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()
project_root = Path(__file__).resolve().parent

def show_banner():
    banner = """
██╗     ██╗███████╗███████╗███████╗███████╗ ██████╗ ██████╗ ███████╗
██║     ██║██╔════╝██╔════╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
██║     ██║█████╗  █████╗  █████╗  █████╗  ██║   ██║██████╔╝█████╗  
██║     ██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══╝  ██║   ██║██╔═══╝ ██╔══╝  
███████╗██║███████╗██║     ██║     ███████╗╚██████╔╝██║     ███████╗
╚══════╝╚═╝╚══════╝╚═╝     ╚═╝     ╚══════╝ ╚═════╝ ╚═╝     ╚══════╝

                   🐻 LIEBESGRÜSSE AUS MOSKAU 🐻
    """
    console.print(Panel(banner, style="bold red", subtitle="Kernel Toolkit Initialisiert"))

def list_components():
    table = Table(title="Projektstruktur", box=box.SQUARE, show_lines=True)
    table.add_column("Komponente", style="cyan", no_wrap=True)
    table.add_column("Beschreibung", style="white")

    table.add_row("exploits/", "PoCs & vollwertige Exploits (LPE, RCE, Kernel-Breaks)")
    table.add_row("payloads/", "Shellcode, Dropper, Reverse Shells – compiled & raw")
    table.add_row("utils/", "Hilfsfunktionen, Memory Tools, Syscall Maps")
    table.add_row("docs/", "Technische Referenzen & Papers")
    table.add_row("tmp/", "Laufzeitdaten & RAM-Dumps")
    table.add_row("main.py", "Der Einstiegspunkt. Du bist hier.")
    console.print(table)

def handle_args():
    parser = argparse.ArgumentParser(
        description="Liebesgruesse aus Moskau – Kernel Exploit Toolkit"
    )
    subparsers = parser.add_subparsers(dest="command")

    # Beispiel-Command: list
    subparsers.add_parser("list", help="Zeigt Projektstruktur und Komponenten")

    # Beispiel-Command: scan
    scan_parser = subparsers.add_parser("scan", help="Scant System auf Schwachstellen")
    scan_parser.add_argument("--deep", action="store_true", help="Führe tiefe Analyse durch (langsamer)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    return args

def cmd_list(args):
    list_components()

def cmd_scan(args):
    console.print("[bold yellow]🧠 Starte Schwachstellenscan...[/bold yellow]")
    if args.deep:
        console.print("🔍 Führe tiefen Kernel-Scan aus...")
    else:
        console.print("🔍 Oberflächenscan aktiviert...")

    # Hier könnte man später echte Checks einbauen
    console.print("[green]✔️ Scan abgeschlossen (Demo-Modus).[/green]")

def main():
    show_banner()
    args = handle_args()

    if args.command == "list":
        cmd_list(args)
    elif args.command == "scan":
        cmd_scan(args)

if __name__ == "__main__":
    main()
