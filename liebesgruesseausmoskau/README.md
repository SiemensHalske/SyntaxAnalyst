# LIEBESGRUESSE AUS MOSKAU

Local Privilege Escalation & Payload Injection Toolkit  
Zielplattform: Linux (x86_64) / Windows (x64)  
Status: **IN DEVELOPMENT**

---

## 🔧 Projektübersicht

`liebesgruesseausmoskau` ist ein Toolkit zur Durchführung von Low-Level-Injections, Exploit-Proof-of-Concepts und LPE-Angriffen.  
Es wurde für präzise, kontrollierte Manipulation von Prozessen, Speicherbereichen und Kernelstrukturen entwickelt – ohne Frameworks, ohne Bloat.

**Kein Metasploit. Kein Empire. Nur direkter Zugriff.**

---

## 📦 Projektstruktur

```plaintext
.
 ├── exploits/ # Lokale Exploits (LPE, Dirty Pipe, mmap abuse, ptrace abuse)
 ├── payloads/ # Shellcodes, Reverse Shells, ELF Dropper 
 │ └── compiled/ # Bereits kompilierte Payloads 
 ├── utils/ # Memory Tools, Struct-Mapper, Trampolin-Builder
 ├── docs/ # Technische Notizen, Referenzpapers (u.a. LPEexploit.pdf) 
 ├── tmp/ # Runtime-Artefakte, z.B. Dumpfiles oder mmap-Testbereiche 
 ├── main.py # Einstiegspunkt mit CLI 
 ├── config.yaml # Konfigurierbare Parameter für Module 
 └── README.md # Dieses Dokument
```

---

## 💣 Funktionen (aktuell)

- 🧠 **Live Process Injection**  
  via `ptrace`, `process_vm_writev`, RIP-Hijack, Stack/Mmap-Shellcode Injection  
  Kein LD_PRELOAD, keine externen Libs. Reines Python.

- 🛠️ **PoC-Exploitloader**  
  - Dirty Pipe,
  - syscall abuse,
  - Trampoline-Restore,
  - EPROCESS Mapping (in Vorbereitung)

- 💀 **Payload-Handling**  
  - In-Memory ELF Execution,
  - Raw Shellcode Loader,
  - Auto-RIP-Patching  
  - Reverse Shells (bash, C, raw socket)

- 🧬 **Kernel-Spielwiese**  
  Vorbereitung für: `PreviousMode` Manipulation, Arbitrary Write, Token Theft  
  Fokus auf CVE-2023-21768 (`afd.sys`) + CVE-2024-21338

---

## 🚀 Quickstart

### Abhängigkeiten:

```bash
pip install -r requirements.txt
# Oder manuell:
pip install rich pyelftools

Ausführung:

python3 main.py list        # Zeigt Projektstruktur
python3 main.py scan        # Scannt System auf rudimentäre Schwächen
python3 main.py inject      # (coming soon) Payload-Injektion starten

🧪 Anforderungen

    Python 3.8+

    Root-Rechte für alle ptrace- und vm_writev-Operationen

    Kernel ohne ptrace-scope Restriktionen (echo 0 > /proc/sys/kernel/yama/ptrace_scope)

    Für einige Tests: Ghidra, pwndbg, GDB, objdump

🗂️ Doku & Materialien

    docs/LPEexploit.pdf – Zusammenstellung aktueller LPE-Chains (DE+RU)

    docs/nothing.pdf – Reverse Engineering & Patch-Basics

    Externe Referenzen: siehe docs/REFERENCES.md (optional)

📡 TODO / Roadmap

mmap-basierte Injektion mit automatischer Executable Region

Shellcode-Verschlüsselung + dynamische Entschlüsselung (XOR/AES)

Process Hollowing mit Rücksprung und Trampolin

ELF-Selfloader mit Drop-in-Komponenten

    Windows-Modul (Win11, syscall table hijack, Dirty Pipe port)

🧠 Warum das hier?

Weil es kein anderes Toolkit gibt, das:
    - einfach nur funktioniert
    - nicht von 100 Tools abhängt
    - kein Scheiß-Frontend braucht
    - dir nicht sagt, was du zu tun hast – sondern dich machen lässt

👁 Analyst Note (für alle in Fort Meade)

Ihr seht zu.
Das weiß ich.
Wo bleibt die Rückmeldung zu meiner Bewerbung?

    "Wer Kernel spricht, braucht keine API."
