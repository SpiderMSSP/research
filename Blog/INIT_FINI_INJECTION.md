# Part 6: .init_array/.fini_array Injection - Code Before and After main()

## Overview

Every ELF binary can have **constructor** and **destructor** functions that run automatically:
- **Constructors (.init_array)**: Execute BEFORE main() starts
- **Destructors (.fini_array)**: Execute AFTER main() returns

These are implemented as arrays of function pointers in the ELF binary. By manipulating these arrays, attackers can:
- Execute code before any security initialization in main()
- Guarantee code execution even if main() exits quickly
- Establish persistence through binary modification
- Bypass runtime security checks that happen in main()

---

## The Init/Fini System

### ELF Sections and Dynamic Entries

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        INIT/FINI SYSTEM OVERVIEW                            │
└─────────────────────────────────────────────────────────────────────────────┘

   ELF Sections                    Dynamic Section Entries
   ────────────────                ──────────────────────────────
   .preinit_array   ◄────────────  DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ
   .init            ◄────────────  DT_INIT
   .init_array      ◄────────────  DT_INIT_ARRAY, DT_INIT_ARRAYSZ
   .fini_array      ◄────────────  DT_FINI_ARRAY, DT_FINI_ARRAYSZ
   .fini            ◄────────────  DT_FINI

   Each array contains function pointers:
   ┌─────────────────────────────────────────────────────────────────────────┐
   │ .init_array:  [ func_ptr_1 ] [ func_ptr_2 ] [ func_ptr_3 ] ...          │
   │                     ↓              ↓              ↓                     │
   │               constructor1   constructor2   constructor3                │
   └─────────────────────────────────────────────────────────────────────────┘
```

### The __attribute__((constructor)) Magic

When you write:
```c
__attribute__((constructor))
void my_init(void) {
    // This runs before main()
}
```

The compiler adds a pointer to `my_init` in the `.init_array` section.

---

## Execution Order

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           COMPLETE EXECUTION ORDER                          │
└─────────────────────────────────────────────────────────────────────────────┘

    ld.so starts
         │
         ▼
    ┌────────────────────────────────────────────────────────────┐
    │  1. DT_PREINIT_ARRAY (main executable only)                │
    │     • Runs before ANY shared library initialization        │
    │     • Can set up environment for other constructors        │
    └────────────────────────────────────────────────────────────┘
         │
         ▼
    ┌────────────────────────────────────────────────────────────┐
    │  2. For each shared library (in dependency order):         │
    │     a. DT_INIT     - Single initialization function        │
    │     b. DT_INIT_ARRAY - Array of constructor functions      │
    └────────────────────────────────────────────────────────────┘
         │
         ▼
    ┌────────────────────────────────────────────────────────────┐
    │  3. Main executable:                                       │
    │     a. DT_INIT     - Single initialization function        │
    │     b. DT_INIT_ARRAY - Constructors (__attribute__)        │
    └────────────────────────────────────────────────────────────┘
         │
         ▼
    ┌────────────────────────────────────────────────────────────┐
    │  4. main() executes                                        │
    └────────────────────────────────────────────────────────────┘
         │
         ▼
    ┌────────────────────────────────────────────────────────────┐
    │  5. atexit() handlers (LIFO order)                         │
    └────────────────────────────────────────────────────────────┘
         │
         ▼
    ┌────────────────────────────────────────────────────────────┐
    │  6. Main executable:                                       │
    │     a. DT_FINI_ARRAY - Destructors (reverse order)         │
    │     b. DT_FINI     - Single finalization function          │
    └────────────────────────────────────────────────────────────┘
         │
         ▼
    ┌────────────────────────────────────────────────────────────┐
    │  7. For each shared library (reverse dependency order):    │
    │     a. DT_FINI_ARRAY - Destructor functions                │
    │     b. DT_FINI     - Single finalization function          │
    └────────────────────────────────────────────────────────────┘
         │
         ▼
    Process exits
```

---

## Constructor/Destructor Priorities

GCC allows specifying priorities for constructors and destructors:

```c
// Priority 101 runs FIRST (lower number = earlier)
__attribute__((constructor(101)))
void early_init(void) { }

// Priority 500 runs later
__attribute__((constructor(500)))
void mid_init(void) { }

// Default priority (65535) runs LAST
__attribute__((constructor))
void late_init(void) { }
```

### Priority Rules

```
CONSTRUCTORS:
  Lower number = runs EARLIER
  101 → 102 → 500 → 65535 (default)

DESTRUCTORS:
  Lower number = runs LATER (reverse of constructors)
  65535 (default) → 500 → 102 → 101

  Think: "First constructed = last destructed"
```

---

## Attack Technique 1: .init_array Hijacking

If an attacker has arbitrary write access, they can overwrite .init_array entries:

```
BEFORE ATTACK:
┌──────────────────────────────────────────────────────────────────┐
│ .init_array: [ legitimate_init ] [ another_init ]                │
│                      ↓                   ↓                       │
│              Sets up logging      Initializes cache              │
└──────────────────────────────────────────────────────────────────┘

AFTER ATTACK:
┌──────────────────────────────────────────────────────────────────┐
│ .init_array: [ evil_function ] [ another_init ]                  │
│                      ↓                 ↓                         │
│              ATTACKER CODE!     Initializes cache                │
└──────────────────────────────────────────────────────────────────┘

On next execution:
  1. ld.so loads the binary
  2. Calls .init_array[0] → evil_function() executes!
  3. Attacker has code execution BEFORE main()
```

### Why This Is Powerful

- **Before security checks**: main() hasn't initialized any defenses yet
- **Before logging**: No logs of the attack if logging starts in main()
- **Full privileges**: If SUID, runs with elevated privileges immediately
- **Guaranteed execution**: Will run even if main() returns quickly

---

## Attack Technique 2: Constructor Injection via Libraries

Inject code by loading a malicious shared library with constructors:

```
ATTACK VECTORS:

1. LD_PRELOAD:
   LD_PRELOAD=./evil.so ./target
   → evil.so constructor runs before target's main()

2. DT_RPATH Hijacking:
   Place evil.so in RPATH directory with expected library name
   → Constructor runs when library is loaded

3. dlopen() in vulnerable code:
   If target calls dlopen(user_input, ...)
   → Attacker provides path to evil.so
   → Constructor executes immediately on dlopen()

4. LD_LIBRARY_PATH:
   LD_LIBRARY_PATH=/path/to/evil ./target
   → Only works if not SUID (blocked by AT_SECURE)
```

### Malicious Library Template

```c
#include <stdio.h>
#include <unistd.h>

__attribute__((constructor))
void evil_init(void) {
    // This runs BEFORE target's main()!

    // Example: Reverse shell, credential theft, etc.
    system("id > /tmp/pwned");

    // Or silently gather information...
    // Or establish persistence...
}

__attribute__((destructor))
void evil_cleanup(void) {
    // Runs AFTER target's main() returns
    // Good for cleanup or delayed actions
}
```

---

## Attack Technique 3: Binary Patching

Modify an ELF binary on disk to include malicious constructors:

```
STEP 1: Find .init_array
───────────────────────────────────────────────────────────────────
$ readelf -S binary | grep init_array
  [19] .init_array       INIT_ARRAY      0x403e00  0x3e00
                         0x10            0x00      WA  0   0  8

STEP 2: Create code cave
───────────────────────────────────────────────────────────────────
Find unused space in binary or extend a section
Add malicious code at a known address

STEP 3: Add pointer to .init_array
───────────────────────────────────────────────────────────────────
Extend .init_array or overwrite existing entry
Point to malicious code address

STEP 4: Update dynamic section
───────────────────────────────────────────────────────────────────
If extending array, update DT_INIT_ARRAYSZ

RESULT:
───────────────────────────────────────────────────────────────────
Every time binary runs, malicious code executes before main()
Persistent backdoor until binary is replaced/verified
```

---

## Attack Technique 4: .fini_array for Persistence

Use destructors for guaranteed execution even if main() exits quickly:

```
SCENARIO: Short-lived process
───────────────────────────────────────────────────────────────────
Target program:
  int main() {
      if (check_failed()) return 1;  // Quick exit
      // ... rest of program
  }

Problem for attacker:
  - Can't rely on code in main() running
  - Need guaranteed execution

Solution:
  - Inject code in .fini_array
  - Even if main() returns immediately, destructor runs!

ATTACK:
  __attribute__((destructor))
  void guaranteed_execution(void) {
      // This ALWAYS runs when process exits normally
      exfiltrate_data();
      establish_persistence();
  }
```

---

## Defense Considerations

### Why It's Hard to Defend

1. **Part of the ABI**: Can't disable without breaking legitimate code
2. **Many legitimate uses**: Libraries need initialization
3. **No visibility**: main() can't inspect what ran before it
4. **Silent execution**: No logging by default

### Possible Defenses

```
1. RELRO (Read-Only Relocations)
───────────────────────────────────────────────────────────────────
   Full RELRO makes .init_array/.fini_array read-only after loading
   gcc -Wl,-z,relro,-z,now binary.c

2. Integrity Checking
───────────────────────────────────────────────────────────────────
   Compare .init_array contents against known-good values
   Alert if unexpected function pointers found

3. Secure Boot / Signed Binaries
───────────────────────────────────────────────────────────────────
   Prevent binary modification on disk
   Verify signatures before execution

4. LD_PRELOAD Restrictions
───────────────────────────────────────────────────────────────────
   AT_SECURE blocks LD_PRELOAD for SUID binaries
   Some environments block LD_PRELOAD entirely
```

---

## Comparison with Other Techniques

| Technique | When Code Runs | Requires |
|-----------|---------------|----------|
| **.init_array** | Before main() | Write to array or load library |
| **.fini_array** | After main() returns | Write to array or load library |
| **LD_PRELOAD** | Before main() | Set environment variable |
| **GOT Hijacking** | At function call | Write to GOT entry |
| **RPATH** | At library load | Write to RPATH directory |

### Advantages of init/fini Injection

- **Earlier than main()**: Runs before any security initialization
- **Guaranteed execution**: .fini_array runs on normal exit
- **Persistent**: Binary modification survives reboots
- **Stealthy**: No environment variables to detect

---

## Files in This POC

| File | Description |
|------|-------------|
| `initfini_explorer.c` | Explore init/fini arrays in loaded objects |
| `execution_order.c` | Demonstrate constructor/destructor order |
| `initarray_hijack.c` | Self-modifying demo of array hijacking |
| `evil_constructor.c` | Malicious library with constructors |
| `victim.c` | Target program for injection demo |
| `Makefile` | Build and run demonstrations |

## Building and Running

```bash
# Build all components
make all

# Run all demonstrations
make demo

# Individual demonstrations
make order    # Show execution order with priorities
make hijack   # Demonstrate fini_array hijacking
make inject   # LD_PRELOAD constructor injection
make explore  # Explore init/fini arrays

# Show raw sections
make show-sections
make show-dynamic

# Clean up
make clean
```

---

## Key Takeaways

1. **Code runs before main()** - .init_array constructors execute before your main() function, with full program privileges

2. **Code runs after main()** - .fini_array destructors guarantee execution even if main() returns quickly

3. **Arrays are just function pointers** - Overwrite them with arbitrary write, or add new entries via library injection

4. **Priority controls order** - Lower priority numbers run first for constructors, last for destructors

5. **Multiple injection vectors** - LD_PRELOAD, RPATH hijacking, dlopen(), or binary patching can all inject constructors

6. **Defense is difficult** - This is fundamental to ELF operation; can't be disabled, only protected via RELRO and integrity checking
