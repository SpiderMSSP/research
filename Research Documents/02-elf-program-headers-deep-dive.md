# ELF Program Headers Deep Dive

**Companion to Lesson 01 - Memory Layout**
**Command Reference:** `readelf -l <binary>`

---

## Overview

When you run `readelf -l binary`, you see the **program headers** - the blueprint for how the OS loads your binary into memory. This document explains every field in detail.

---

## Sample Output

```
Elf file type is DYN (Position-Independent Executable file)
Entry point 0x1040
There are 13 program headers, starting at offset 64

Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  PHDR           0x0000000000000040 0x0000000000000040 0x0000000000000040
                 0x00000000000002d8 0x00000000000002d8  R      0x8
  INTERP         0x0000000000000318 0x0000000000000318 0x0000000000000318
                 0x000000000000001c 0x000000000000001c  R      0x1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
  LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x00000000000005f0 0x00000000000005f0  R      0x1000
  LOAD           0x0000000000001000 0x0000000000001000 0x0000000000001000
                 0x0000000000000145 0x0000000000000145  R E    0x1000
  LOAD           0x0000000000002000 0x0000000000002000 0x0000000000002000
                 0x00000000000000c4 0x00000000000000c4  R      0x1000
  LOAD           0x0000000000002df0 0x0000000000003df0 0x0000000000003df0
                 0x0000000000000220 0x0000000000000228  RW     0x1000
  DYNAMIC        0x0000000000002e00 0x0000000000003e00 0x0000000000003e00
                 0x00000000000001c0 0x00000000000001c0  RW     0x8
  NOTE           0x0000000000000338 0x0000000000000338 0x0000000000000338
                 0x0000000000000030 0x0000000000000030  R      0x8
  NOTE           0x0000000000000368 0x0000000000000368 0x0000000000000368
                 0x0000000000000044 0x0000000000000044  R      0x4
  GNU_PROPERTY   0x0000000000000338 0x0000000000000338 0x0000000000000338
                 0x0000000000000030 0x0000000000000030  R      0x8
  GNU_EH_FRAME   0x0000000000002004 0x0000000000002004 0x0000000000002004
                 0x000000000000002c 0x000000000000002c  R      0x4
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RW     0x10
  GNU_RELRO      0x0000000000002df0 0x0000000000003df0 0x0000000000003df0
                 0x0000000000000210 0x0000000000000210  R      0x1

 Section to Segment mapping:
  Segment Sections...
   00
   01     .interp
   02     .interp .note.gnu.property .note.gnu.build-id .note.ABI-tag .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rela.dyn
   03     .init .plt .plt.got .text .fini
   04     .rodata .eh_frame_hdr .eh_frame
   05     .init_array .fini_array .dynamic .got .data .bss
   06     .dynamic
   07     .note.gnu.property
   08     .note.gnu.build-id .note.ABI-tag
   09     .note.gnu.property
   10     .eh_frame_hdr
   11
   12     .init_array .fini_array .dynamic .got
```

---

## Header Information

```
Elf file type is DYN (Position-Independent Executable file)
Entry point 0x1040
There are 13 program headers, starting at offset 64
```

| Field | Value | Meaning |
|-------|-------|---------|
| **ELF file type** | DYN | Position-Independent Executable (PIE). Address randomized at runtime. If it said `EXEC`, addresses would be fixed. |
| **Entry point** | 0x1040 | First instruction executed (not `main`! It's `_start` which sets up and calls `main`) |
| **13 program headers** | at offset 64 | 13 segments defined, header table starts 64 bytes into file |

### ELF Types and Exploitation Impact

| Type | Meaning | ASLR Impact |
|------|---------|-------------|
| `EXEC` | Fixed-address executable | Binary at predictable address (easier to exploit) |
| `DYN` | Position-independent (PIE) | Binary address randomized (need info leak) |

---

## Program Header Column Meanings

```
Type           Offset             VirtAddr           PhysAddr
               FileSiz            MemSiz              Flags  Align
```

| Column | Meaning |
|--------|---------|
| **Type** | What kind of segment (LOAD, INTERP, etc.) |
| **Offset** | Where in the FILE this data is located |
| **VirtAddr** | Where in MEMORY it will be loaded |
| **PhysAddr** | Physical address (usually same as VirtAddr, ignore for userland) |
| **FileSiz** | Size of data in the file |
| **MemSiz** | Size in memory (can be > FileSiz for BSS) |
| **Flags** | Permissions: R=Read, W=Write, E=Execute |
| **Align** | Memory alignment requirement |

### Permission Flags

| Flag | Meaning | Security Implication |
|------|---------|---------------------|
| `R` | Readable | Can read data/code |
| `W` | Writable | Can modify data |
| `E` | Executable | Can execute as code |
| `R E` | Read + Execute | CODE segment (TEXT) |
| `RW` | Read + Write | DATA segment (writable, not executable) |
| `RWE` | All permissions | DANGEROUS - writable AND executable |

---

## Each Program Header Explained

### 1. PHDR - Program Header Table

```
PHDR           0x0000000000000040 0x0000000000000040 0x0000000000000040
               0x00000000000002d8 0x00000000000002d8  R      0x8
```

| Field | Value | Meaning |
|-------|-------|---------|
| Type | PHDR | The program header table itself |
| Offset | 0x40 | 64 bytes into file |
| Size | 0x2d8 | 728 bytes |
| Flags | R | Read-only |

**Purpose:** Tells the loader where all the other segments are.

---

### 2. INTERP - Interpreter

```
INTERP         0x0000000000000318 0x0000000000000318 0x0000000000000318
               0x000000000000001c 0x000000000000001c  R      0x1
    [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
```

| Field | Value | Meaning |
|-------|-------|---------|
| Type | INTERP | Dynamic linker path |
| Size | 0x1c | 28 bytes (just the path string) |
| Path | /lib64/ld-linux-x86-64.so.2 | The dynamic linker |

**Purpose:** This program runs BEFORE your code to:
1. Load shared libraries (libc, etc.)
2. Resolve symbols
3. Perform relocations

**Exploitation Note:** The dynamic linker is powerful. Attacks like `LD_PRELOAD` hijacking abuse this mechanism.

---

### 3. LOAD (Read-only headers) - Segment 02

```
LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000
               0x00000000000005f0 0x00000000000005f0  R      0x1000
```

| Field | Value | Meaning |
|-------|-------|---------|
| VirtAddr | 0x0 | Base address (relative, will be relocated) |
| Size | 0x5f0 | 1520 bytes |
| Flags | R | Read-only |
| Align | 0x1000 | 4KB page alignment |

**Contains:** ELF headers, notes, symbol info
**Sections:** `.interp .note.* .gnu.hash .dynsym .dynstr .gnu.version .rela.dyn`

---

### 4. LOAD (Code/TEXT) - Segment 03 ⭐ CRITICAL

```
LOAD           0x0000000000001000 0x0000000000001000 0x0000000000001000
               0x0000000000000145 0x0000000000000145  R E    0x1000
```

| Field | Value | Meaning |
|-------|-------|---------|
| VirtAddr | 0x1000 | Code starts here |
| Size | 0x145 | 325 bytes of code |
| Flags | **R E** | **Read + Execute = CODE!** |

**This is the TEXT segment. Contains:**

| Section | Purpose |
|---------|---------|
| `.init` | Initialization code (runs before main) |
| `.plt` | Procedure Linkage Table (library call stubs) |
| `.plt.got` | PLT entries that use GOT directly |
| `.text` | Your compiled functions (main, etc.) |
| `.fini` | Finalization code (runs after main) |

**Exploitation Notes:**
- You CANNOT write here (no W flag)
- You CAN execute code here
- **ROP gadgets come from this segment!**
- PLT entries can be used for ret2plt attacks

---

### 5. LOAD (Read-only data) - Segment 04

```
LOAD           0x0000000000002000 0x0000000000002000 0x0000000000002000
               0x00000000000000c4 0x00000000000000c4  R      0x1000
```

| Field | Value | Meaning |
|-------|-------|---------|
| VirtAddr | 0x2000 | RODATA starts here |
| Size | 0xc4 | 196 bytes |
| Flags | R | Read-only |

**This is RODATA. Contains:**

| Section | Purpose |
|---------|---------|
| `.rodata` | String literals ("Hello World"), constants |
| `.eh_frame_hdr` | Exception handling frame header |
| `.eh_frame` | Exception handling info (for stack unwinding) |

**Exploitation Note:** Useful strings for attacks may be found here.

---

### 6. LOAD (Writable data) - Segment 05 ⭐ CRITICAL

```
LOAD           0x0000000000002df0 0x0000000000003df0 0x0000000000003df0
               0x0000000000000220 0x0000000000000228  RW     0x1000
```

| Field | Value | Meaning |
|-------|-------|---------|
| VirtAddr | 0x3df0 | DATA starts here |
| FileSiz | 0x220 | 544 bytes in file |
| MemSiz | 0x228 | 552 bytes in memory (**8 bytes more!**) |
| Flags | **RW** | **Read + Write = WRITABLE!** |

**Why MemSiz > FileSiz?**

The extra 8 bytes are **BSS** - uninitialized data. It doesn't exist in the file (would waste space), but the OS allocates and zeroes it at runtime.

```
FileSiz (0x220): [.data - initialized globals]
MemSiz (0x228):  [.data - initialized globals][.bss - 8 bytes zeroed]
```

**This segment contains your exploitation targets:**

| Section | Purpose | Exploitation Use |
|---------|---------|------------------|
| `.init_array` | Function pointers called at init | Overwrite for code exec |
| `.fini_array` | Function pointers called at exit | Overwrite for code exec |
| `.dynamic` | Dynamic linking info | - |
| `.got` | Global Offset Table | **PRIMARY OVERWRITE TARGET** |
| `.data` | Initialized global variables | May contain function pointers |
| `.bss` | Uninitialized globals (zeroed) | May contain function pointers |

---

### 7. DYNAMIC - Dynamic Linking Info

```
DYNAMIC        0x0000000000002e00 0x0000000000003e00 0x0000000000003e00
               0x00000000000001c0 0x00000000000001c0  RW     0x8
```

| Field | Value | Meaning |
|-------|-------|---------|
| Flags | RW | Writable |
| Size | 0x1c0 | 448 bytes |

**Contains:** Information for the dynamic linker:
- List of needed shared libraries
- Symbol table locations
- Relocation information
- String table locations

---

### 8-10. NOTE Segments

```
NOTE           0x0000000000000338 ...  R
NOTE           0x0000000000000368 ...  R
GNU_PROPERTY   0x0000000000000338 ...  R
```

**Purpose:** Metadata about the binary:
- Build ID (unique identifier)
- ABI information
- Security properties (e.g., CET - Control-flow Enforcement)

**Not directly exploitable** but useful for:
- Fingerprinting binaries
- Identifying compiler/build system
- Checking security features

---

### 11. GNU_EH_FRAME - Exception Handling

```
GNU_EH_FRAME   0x0000000000002004 0x0000000000002004 0x0000000000002004
               0x000000000000002c 0x000000000000002c  R      0x4
```

**Purpose:** Unwind information for:
- Exception handling (C++ try/catch)
- Stack traces
- Debugger backtraces

Used by the runtime to know how to unwind the stack when an exception is thrown.

---

### 12. GNU_STACK ⭐ SECURITY CHECK

```
GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
               0x0000000000000000 0x0000000000000000  RW     0x10
```

| Field | Value | Meaning |
|-------|-------|---------|
| Size | 0 | Doesn't take file space |
| Flags | **RW** | **NO EXECUTE = NX ENABLED** |

**This is the NX (No-Execute) bit check!**

| Flags | Meaning | Security |
|-------|---------|----------|
| `RW` | Stack NOT executable | NX enabled (SECURE) |
| `RWE` | Stack IS executable | NX disabled (VULNERABLE) |

**How to check NX status:**
```bash
readelf -l binary | grep GNU_STACK
# RW = NX enabled (secure)
# RWE = NX disabled (can run shellcode on stack)
```

**How to disable NX (for practice):**
```bash
gcc -z execstack -o vuln vuln.c
# Now GNU_STACK will show RWE
```

---

### 13. GNU_RELRO - Relocation Read-Only ⭐ SECURITY

```
GNU_RELRO      0x0000000000002df0 0x0000000000003df0 0x0000000000003df0
               0x0000000000000210 0x0000000000000210  R      0x1
```

**Purpose:** Marks parts of GOT as read-only AFTER relocations complete.

**RELRO Levels:**

| Level | GOT Writable? | Compilation |
|-------|---------------|-------------|
| No RELRO | Always writable | `gcc -Wl,-z,norelro` |
| Partial RELRO | Partially writable | `gcc -Wl,-z,relro` (default) |
| Full RELRO | Read-only after start | `gcc -Wl,-z,relro,-z,now` |

**How to check RELRO:**
```bash
checksec --file=binary
# or
readelf -l binary | grep GNU_RELRO
# Present = at least Partial RELRO
# Check with checksec for Full vs Partial
```

---

## Section to Segment Mapping

```
Segment Sections...
 00
 01     .interp
 02     .interp .note.gnu.property .note.gnu.build-id .note.ABI-tag .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rela.dyn
 03     .init .plt .plt.got .text .fini
 04     .rodata .eh_frame_hdr .eh_frame
 05     .init_array .fini_array .dynamic .got .data .bss
 06     .dynamic
 07     .note.gnu.property
 08     .note.gnu.build-id .note.ABI-tag
 09     .note.gnu.property
 10     .eh_frame_hdr
 11
 12     .init_array .fini_array .dynamic .got
```

This maps **sections** (compile-time view) to **segments** (runtime view):

| Segment | Permissions | Key Sections | Purpose |
|---------|-------------|--------------|---------|
| 00 | - | (empty) | Program headers |
| 01 | R | .interp | Dynamic linker path |
| 02 | R | .dynsym, .dynstr | Symbol info for dynamic linking |
| **03** | **R E** | **.plt, .text** | **Executable code (TEXT)** |
| 04 | R | .rodata | String literals, constants |
| **05** | **RW** | **.got, .data, .bss** | **Writable data (attack surface)** |
| 06 | RW | .dynamic | Dynamic linking info |

---

## Visual Summary: File vs Memory

```
FILE (on disk)                    MEMORY (at runtime)
──────────────                    ──────────────────
┌──────────────────┐              ┌────────────────────────────┐
│ ELF Header       │              │ 0x0000: Headers (R)        │
│ Program Headers  │──────────────│   - ELF header             │
│ (PHDR)           │              │   - Program headers        │
├──────────────────┤              ├────────────────────────────┤
│ .text            │              │ 0x1000: TEXT (R-X)         │
│ .plt             │──────────────│   - .plt (PLT stubs)       │
│ .init            │              │   - .text (your code)      │
│ .fini            │              │   - .init/.fini            │
├──────────────────┤              ├────────────────────────────┤
│ .rodata          │──────────────│ 0x2000: RODATA (R--)       │
│ .eh_frame        │              │   - String literals        │
│                  │              │   - Constants              │
├──────────────────┤              ├────────────────────────────┤
│ .data            │              │ 0x3000: DATA (RW-)         │
│ .got             │──────────────│   - .got (GOT entries)     │
│                  │              │   - .data (globals)        │
│                  │   (zeroed)───│   - .bss (zeroed globals)  │
└──────────────────┘              ├────────────────────────────┤
                                  │                            │
                                  │        (unmapped)          │
                                  │                            │
                                  ├────────────────────────────┤
                                  │ HEAP (grows ↑)             │
                                  │   - malloc'd memory        │
                                  │                            │
                                  │        (unmapped)          │
                                  │                            │
                                  │ STACK (grows ↓)            │
                                  │   - Local variables        │
                                  │   - Return addresses       │
                                  └────────────────────────────┘
```

---

## Quick Reference: Security Checks from readelf

```bash
# Check NX (No-Execute / DEP)
readelf -l binary | grep GNU_STACK
# RW = NX enabled (secure)
# RWE = NX disabled (shellcode possible)

# Check RELRO
readelf -l binary | grep GNU_RELRO
# Present = RELRO enabled (use checksec for full vs partial)

# Check PIE
readelf -h binary | grep Type
# DYN = PIE enabled (address randomization)
# EXEC = No PIE (fixed addresses)

# Better: use checksec for all at once
checksec --file=binary
```

---

## Key Takeaways for Exploitation

1. **LOAD R E segment** = TEXT = Code = ROP gadgets live here
2. **LOAD RW segment** = DATA = GOT, function pointers = Overwrite targets
3. **GNU_STACK RW** = NX enabled = Need ROP, no direct shellcode
4. **GNU_STACK RWE** = NX disabled = Can execute shellcode on stack
5. **GNU_RELRO** = GOT protection = Full RELRO makes GOT read-only
6. **DYN type** = PIE enabled = Need address leak
7. **FileSiz < MemSiz** = BSS section = Zeroed at runtime

---

**Related Documents:**
- [01-memory-layout-deep-dive.md](./01-memory-layout-deep-dive.md) - Memory segments overview
- [02-compilation-and-protections.md](./02-compilation-and-protections.md) - Security mitigations

**Last Updated:** 2025-12-20
