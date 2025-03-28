#!/usr/bin/env python3
import os
import ctypes
import ctypes.util
import re

libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
PTRACE_ATTACH = 16
PTRACE_DETACH = 17

target_pid = int(input("Ziel-PID: "))
dump_file = f"dump_{target_pid}.bin"

# Attach
if libc.ptrace(PTRACE_ATTACH, target_pid, None, None) != 0:
    print("❌ ptrace attach failed.")
    exit(1)
os.waitpid(target_pid, 0)
print("✔️ Attached to target.")

maps_path = f"/proc/{target_pid}/maps"
mem_path = f"/proc/{target_pid}/mem"

with open(maps_path, "r") as maps_file, open(mem_path, "rb") as mem_file, open(dump_file, "wb") as out:
    for line in maps_file:
        if not "r" in line.split()[1]:
            continue  # only read readable regions
        m = re.match(r"([0-9a-f]+)-([0-9a-f]+)", line)
        if not m:
            continue
        start = int(m.group(1), 16)
        end = int(m.group(2), 16)
        size = end - start

        try:
            mem_file.seek(start)
            chunk = mem_file.read(size)
            out.write(chunk)
        except Exception:
            continue

print(f"🧪 Dump complete: {dump_file}")

# Detach
libc.ptrace(PTRACE_DETACH, target_pid, None, None)
print("🏁 Detached.")
