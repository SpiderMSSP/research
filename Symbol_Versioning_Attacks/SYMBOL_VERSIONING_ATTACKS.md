# Part 7: Symbol Versioning Attacks - Exploiting GNU Symbol Versions

## Overview

GNU Symbol Versioning is a mechanism that allows multiple versions of the same function to exist in a shared library. This enables:
- Backwards compatibility (old binaries keep working)
- Bug fixes without breaking ABI
- Smooth library upgrades

However, this complexity also creates attack surfaces:
- Force programs to use vulnerable function versions
- Hijack specific versioned symbols
- Exploit version resolution logic

---

## How Symbol Versioning Works

### The Problem It Solves

```
SCENARIO: glibc fixes a bug in realpath()

Without Versioning:
─────────────────────────────────────────────────────────────────
  Old binary expects buggy realpath()
  New glibc has fixed realpath()
  Old binary might break because behavior changed!

With Versioning:
─────────────────────────────────────────────────────────────────
  glibc provides BOTH versions:
    realpath@GLIBC_2.2.5  → Old (buggy) behavior
    realpath@GLIBC_2.3    → New (fixed) behavior

  Old binary links to:    realpath@GLIBC_2.2.5 → Gets old behavior
  New binary links to:    realpath@GLIBC_2.3   → Gets new behavior
  Both work correctly!
```

### ELF Sections for Versioning

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      SYMBOL VERSIONING SECTIONS                             │
└─────────────────────────────────────────────────────────────────────────────┘

  .gnu.version (VERSYM)
  ─────────────────────────────────────────────────────────────────
    Maps each symbol table entry to a version index

    Symbol Table Index    Version Index
    ──────────────────    ─────────────
    [0] (null)            0 (LOCAL)
    [1] printf            3 (GLIBC_2.2.5)
    [2] realpath          4 (GLIBC_2.3)
    [3] memcpy            5 (GLIBC_2.14)


  .gnu.version_r (VERNEED)
  ─────────────────────────────────────────────────────────────────
    Version requirements - what versions we NEED from other libraries

    From libc.so.6:
      GLIBC_2.2.5 (index 3)
      GLIBC_2.3   (index 4)
      GLIBC_2.14  (index 5)


  .gnu.version_d (VERDEF)
  ─────────────────────────────────────────────────────────────────
    Version definitions - what versions we PROVIDE

    VERS_1.0 (index 2) [BASE]
    VERS_2.0 (index 3) inherits VERS_1.0
```

### Symbol Resolution with Versioning

```
    Binary requesting: printf@GLIBC_2.2.5
                              │
                              ▼
    ┌─────────────────────────────────────────────────────────────────────┐
    │                    DYNAMIC LINKER (ld.so)                           │
    │                                                                     │
    │  1. Look up "printf" in libc.so.6 symbol table                     │
    │  2. Check version: need GLIBC_2.2.5                                │
    │  3. Find printf entry with matching version                        │
    │  4. Bind symbol to that specific version                           │
    └─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
    Found: printf@@GLIBC_2.2.5 at 0x7f...
           (The @@ means this is the DEFAULT version)
```

---

## Version Syntax

### In Symbol Names

```
Symbol Notation           Meaning
────────────────────────────────────────────────────────────────
printf@GLIBC_2.2.5       Specific version (non-default)
printf@@GLIBC_2.2.5      Default version for new binaries
printf                    Unversioned symbol (matches any)
```

### In Source Code (.symver directive)

```c
/* Create versioned symbols */
__asm__(".symver old_func, func@VERSION_1.0");     /* Compat version */
__asm__(".symver new_func, func@@VERSION_2.0");    /* Default version */
```

### In Version Scripts (.map files)

```
VERSION_1.0 {
    global:
        function1;
        function2;
    local:
        *;
};

VERSION_2.0 {
    global:
        function1;  /* New version of function1 */
} VERSION_1.0;      /* Inherits from VERSION_1.0 */
```

---

## Attack Technique 1: Version Hijacking via LD_PRELOAD

Create a library that provides specific symbol versions to intercept calls:

```
ATTACK FLOW:
─────────────────────────────────────────────────────────────────

  1. Identify target function version:
     $ objdump -T victim | grep realpath
     realpath@GLIBC_2.2.5

  2. Create malicious library providing that version:

     char *evil_realpath(const char *path, char *resolved) {
         log_call(path);  // Steal data
         return real_realpath(path, resolved);
     }
     __asm__(".symver evil_realpath, realpath@GLIBC_2.2.5");

  3. Preload the malicious library:
     LD_PRELOAD=./evil.so ./victim

  4. When victim calls realpath@GLIBC_2.2.5:
     → Our evil_realpath is called instead!
```

---

## Attack Technique 2: Version Downgrade Attack

Force a program to use an older, vulnerable version of a function:

```
SCENARIO: memcpy behavior change
─────────────────────────────────────────────────────────────────

  memcpy@GLIBC_2.2.5  → Old behavior (overlapping allowed?)
  memcpy@GLIBC_2.14   → New behavior (optimized, stricter)

ATTACK:
  1. Binary links to memcpy@GLIBC_2.14
  2. Attacker provides library with memcpy@GLIBC_2.14
     that actually has old behavior
  3. Preload or RPATH to load attacker's library first
  4. Program gets old (potentially vulnerable) behavior
```

### Real-World Examples

```
CASE: realpath() vulnerability
─────────────────────────────────────────────────────────────────
  realpath@GLIBC_2.2.5 had buffer overflow vulnerability
  realpath@GLIBC_2.3 was fixed

  Attack: Force program to use old version behavior

CASE: memcpy() direction
─────────────────────────────────────────────────────────────────
  Old memcpy: copied in one direction
  New memcpy: optimized, may copy in different order

  Some programs accidentally relied on copy direction
  Providing "old" memcpy could trigger bugs or vulnerabilities
```

---

## Attack Technique 3: Version Mismatch Exploitation

Exploit programs that don't properly check version requirements:

```
ATTACK SCENARIO:
─────────────────────────────────────────────────────────────────

  1. Binary requires: function@VERSION_2.0
  2. Attacker provides: function@VERSION_1.0 (different behavior)
  3. If linker doesn't strictly check, VERSION_1.0 might be used
  4. Program gets unexpected behavior

PREVENTION:
  - Use VERNEED strictly
  - Check --no-undefined when linking
  - Verify library versions at runtime
```

---

## Creating Versioned Libraries

### Source Code Example

```c
/* versioned_lib.c */

/* Old version - compatibility */
int old_process(const char *data) {
    return strlen(data);  /* Simple, potentially buggy */
}

/* New version - fixed */
int new_process(const char *data, size_t max) {
    if (strlen(data) > max) return -1;  /* Bounds check */
    return strlen(data);
}

/* Version symbol definitions */
__asm__(".symver old_process, process@VERS_1.0");
__asm__(".symver new_process, process@@VERS_2.0");
```

### Version Script

```
/* versioned_lib.map */
VERS_1.0 {
    global:
        process;
    local:
        *;
};

VERS_2.0 {
    global:
        process;
} VERS_1.0;
```

### Compilation

```bash
gcc -shared -fPIC \
    -Wl,--version-script=versioned_lib.map \
    -o libversioned.so versioned_lib.c
```

---

## Inspecting Symbol Versions

### Using readelf

```bash
# Show version sections
readelf -V binary

# Output:
Version needs section '.gnu.version_r' contains 1 entry:
 Addr: 0x...  Offset: 0x...  Link: 5 (.dynstr)
  000000: Version: 1  File: libc.so.6  Cnt: 3
  0x0010:   Name: GLIBC_2.2.5  Flags: none  Version: 2
  0x0020:   Name: GLIBC_2.3    Flags: none  Version: 3
  0x0030:   Name: GLIBC_2.14   Flags: none  Version: 4
```

### Using objdump

```bash
# Show dynamic symbols with versions
objdump -T binary | grep GLIBC

# Output:
0000000000000000  DF *UND*  0 GLIBC_2.2.5 printf
0000000000000000  DF *UND*  0 GLIBC_2.3   realpath
0000000000000000  DF *UND*  0 GLIBC_2.14  memcpy
```

### Using nm

```bash
# Show symbols with versions
nm -D binary | grep @

# Output:
                 U printf@@GLIBC_2.2.5
                 U realpath@@GLIBC_2.3
```

---

## Defense Considerations

### For Developers

1. **Use strict version requirements**
   ```c
   /* Explicitly require specific version at compile time */
   __asm__(".symver realpath, realpath@GLIBC_2.3");
   ```

2. **Verify library versions at runtime**
   ```c
   /* Check glibc version */
   const char *version = gnu_get_libc_version();
   if (strcmp(version, "2.17") < 0) {
       abort();  /* Too old */
   }
   ```

3. **Use -Wl,--no-undefined when linking**
   ```bash
   gcc -Wl,--no-undefined -o binary source.c
   ```

### For System Administrators

1. **Monitor LD_PRELOAD usage**
2. **Check library versions on critical systems**
3. **Use integrity checking for system libraries**

---

## Comparison with Other Techniques

| Technique | Targets | Requires |
|-----------|---------|----------|
| **Version Hijacking** | Specific function versions | LD_PRELOAD or library loading |
| **LD_PRELOAD** | Any exported function | Environment control |
| **GOT Hijacking** | Resolved symbols | Write primitive |
| **RPATH** | Library loading | Write to directory |

### Why Version Attacks Are Subtle

- No obvious hooking - just providing "correct" version
- Hard to detect - symbol versions match
- Targeted - can attack specific function behaviors
- Version-specific vulnerabilities can be exploited

---

## Files in This POC

| File | Description |
|------|-------------|
| `version_explorer.c` | Explore symbol versions in loaded libraries |
| `versioned_lib.c` | Library with versioned symbols |
| `versioned_lib.map` | Version script for the library |
| `evil_versioned.c` | Malicious version hijacking library |
| `victim.c` | Target program for demonstrations |
| `Makefile` | Build and run demonstrations |

## Building and Running

```bash
# Build all components
make all

# Run all demonstrations
make demo

# Individual demonstrations
make explore          # Explore symbol versions
make hijack           # Version hijacking demo
make show-versions    # Show victim's version requirements
make show-libc-versions  # Show glibc versions on system

# Clean up
make clean
```

---

## Key Takeaways

1. **Symbol versioning enables multiple function versions** - Libraries can provide different implementations of the same function for compatibility

2. **Version resolution happens at link time and runtime** - The linker binds symbols to specific versions based on requirements

3. **Attackers can provide matching versions** - By creating libraries with the same version tags, attackers can intercept versioned symbol calls

4. **Version downgrades are possible** - Forcing use of older, vulnerable versions by providing them via LD_PRELOAD or RPATH

5. **Detection is subtle** - Unlike obvious hooks, version attacks provide "correct" versions, making detection harder

6. **glibc uses this extensively** - Understanding versioning is key to understanding glibc internals and potential attack surfaces
