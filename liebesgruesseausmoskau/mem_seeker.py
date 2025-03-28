#!/usr/bin/env python3
import os
import ctypes
import ctypes.util
import re
from rich.console import Console
from rich.panel import Panel

console = Console()

libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
PTRACE_ATTACH = 16
PTRACE_DETACH = 17

target_pid = int(input("Ziel-PID: "))
console.rule("[bold blue]🕵️ Memory Peeker gestartet")

# Attach
with console.status("[yellow]Attach an Zielprozess...[/yellow]", spinner="dots"):
    if libc.ptrace(PTRACE_ATTACH, target_pid, None, None) != 0:
        console.print("[red]❌ ptrace attach failed.[/red]")
        exit(1)
    os.waitpid(target_pid, 0)

console.print("[green]✔️ Erfolgreich attached![/green]")

maps_path = f"/proc/{target_pid}/maps"
mem_path = f"/proc/{target_pid}/mem"
hits = 0

try:
    with open(maps_path, "r") as maps_file, open(mem_path, "rb") as mem_file:
        for line in maps_file:
            if not "r" in line.split()[1]:
                continue  # skip unreadable regions

            m = re.match(r"([0-9a-f]+)-([0-9a-f]+)", line)
            if not m:
                continue
            start = int(m.group(1), 16)
            end = int(m.group(2), 16)
            size = end - start

            read_size = min(size, 65536)  # cap to 64KB

            try:
                mem_file.seek(start)
                chunk = mem_file.read(read_size)

                if b"SECRET" in chunk:
                    hits += 1
                    console.print(Panel(
                        f"Match in region [bold]{hex(start)} - {hex(end)}[/bold]",
                        title=f"[green]🔓 SECRET gefunden ({hits})[/green]"
                    ))
                    preview = chunk[chunk.index(b"SECRET")-16:chunk.index(b"SECRET")+64]
                    console.print(preview.decode(errors="ignore"))

            except Exception as e:
                continue

except Exception as e:
    console.print(f"[red]❌ Fehler beim Lesen von Speicher: {e}[/red]")

libc.ptrace(PTRACE_DETACH, target_pid, None, None)
console.print("[bold green]🏁 Prozess wurde sauber freigegeben[/bold green]")
