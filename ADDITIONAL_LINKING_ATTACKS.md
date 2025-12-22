# Additional Loader/Linker Level Attacks

**Supplement to the Linking Attacks Series**

These attacks extend the original 8-part series with additional techniques in the same category.

---

## Category Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    COMPLETE LOADER/LINKER ATTACK TAXONOMY                        │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   ALREADY COVERED (Parts 1-8):                                                  │
│   ────────────────────────────                                                  │
│   1. Trojanized Loader (PT_INTERP)                                              │
│   2. LD_PRELOAD Injection                                                       │
│   3. GOT/PLT Hijacking                                                          │
│   4. .init_array / .preinit_array Attacks                                       │
│   5. DT_RPATH / DT_RUNPATH Poisoning                                            │
│   6. DT_NEEDED Injection                                                        │
│   7. LD_AUDIT Interface Abuse                                                   │
│   8. IFUNC Resolver Hijacking                                                   │
│                                                                                 │
│   ═══════════════════════════════════════════════════════════════════════════   │
│                                                                                 │
│   ADDITIONAL ATTACKS (New):                                                     │
│   ─────────────────────────                                                     │
│                                                                                 │
│   ENVIRONMENT-BASED:                                                            │
│   ├── 9.  LD_LIBRARY_PATH Poisoning                                             │
│   ├── 10. LD_DEBUG Information Disclosure                                       │
│   ├── 11. GLIBC_TUNABLES Exploitation (CVE-2023-4911 Looney Tunables)           │
│   └── 12. LD_HWCAP_MASK Abuse                                                   │
│                                                                                 │
│   ELF STRUCTURE-BASED:                                                          │
│   ├── 13. DT_FINI_ARRAY Attacks (exit-time execution)                           │
│   ├── 14. DT_DEBUG / r_debug Manipulation                                       │
│   ├── 15. DT_TEXTREL Abuse (writable code)                                      │
│   ├── 16. Symbol Versioning Attacks                                             │
│   └── 17. GNU_UNIQUE Symbol Exploitation                                        │
│                                                                                 │
│   RUNTIME LINKER STRUCTURES:                                                    │
│   ├── 18. link_map Chain Manipulation                                           │
│   ├── 19. TLS (Thread Local Storage) / DTV Attacks                              │
│   └── 20. Lazy Binding Race Conditions (TOCTOU)                                 │
│                                                                                 │
│   DLOPEN/RUNTIME:                                                               │
│   ├── 21. RTLD_GLOBAL / RTLD_DEEPBIND Abuse                                     │
│   └── 22. dlopen() Path Traversal                                               │
│                                                                                 │
│   KERNEL/VDSO:                                                                  │
│   ├── 23. VDSO/VSYSCALL Hijacking                                               │
│   └── 24. Auxiliary Vector (auxv) Manipulation                                  │
│                                                                                 │
│   BUILD-TIME:                                                                   │
│   ├── 25. Malicious Linker Scripts                                              │
│   └── 26. Constructor Priority Attacks                                          │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 9. LD_LIBRARY_PATH Poisoning

### Overview
Similar to DT_RPATH but controlled via environment variable. The linker searches these paths for shared libraries.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    LIBRARY SEARCH ORDER                                          │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   When resolving "libfoo.so", linker searches in order:                         │
│                                                                                 │
│   1. DT_RPATH (if DT_RUNPATH not present) ← Compile-time                        │
│   2. LD_LIBRARY_PATH                       ← ATTACKER CONTROLLED                │
│   3. DT_RUNPATH                            ← Compile-time                       │
│   4. /etc/ld.so.cache                      ← System cache                       │
│   5. /lib, /usr/lib                        ← Default paths                      │
│                                                                                 │
│   Attack: Place evil libfoo.so in controlled path, set LD_LIBRARY_PATH          │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Attack Example
```bash
# Create malicious library
gcc -shared -fPIC -o /tmp/evil/libc.so.6 evil.c

# Hijack library loading
LD_LIBRARY_PATH=/tmp/evil ./target
# Target loads attacker's libc instead of system libc!
```

### Restrictions
- Ignored for SUID/SGID binaries
- Ignored when AT_SECURE is set

---

## 10. LD_DEBUG Information Disclosure

### Overview
`LD_DEBUG` causes the linker to print detailed information about its operations - useful for reconnaissance.

```bash
# Dump all linker operations
LD_DEBUG=all ./target 2>&1 | head -100

# Specific debug categories
LD_DEBUG=bindings ./target    # Symbol bindings
LD_DEBUG=libs ./target        # Library search paths
LD_DEBUG=symbols ./target     # Symbol resolution
LD_DEBUG=versions ./target    # Version dependencies
LD_DEBUG=reloc ./target       # Relocation processing
```

### Attack Use
- Discover library load order for hijacking
- Find symbol resolution for GOT attacks
- Identify ASLR offsets in some cases
- Map out application dependencies

---

## 11. GLIBC_TUNABLES Exploitation (Looney Tunables - CVE-2023-4911)

### Overview
**Critical vulnerability discovered in October 2023.** Buffer overflow in glibc's handling of the `GLIBC_TUNABLES` environment variable leads to local privilege escalation.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    LOONEY TUNABLES (CVE-2023-4911)                               │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   Affected: glibc 2.34 - 2.38 (most modern Linux distros in 2023)               │
│   Impact:   Local Privilege Escalation to ROOT                                  │
│   Type:     Buffer overflow in ld.so tunable parsing                            │
│                                                                                 │
│   Vulnerable Code Path:                                                         │
│   ─────────────────────                                                         │
│                                                                                 │
│   GLIBC_TUNABLES=glibc.malloc.check=AAAA...                                     │
│        │                                                                        │
│        ▼                                                                        │
│   ld.so parses tunables during startup                                          │
│        │                                                                        │
│        ▼                                                                        │
│   Buffer overflow in __tunables_init()                                          │
│        │                                                                        │
│        ▼                                                                        │
│   Overwrite linker's internal structures                                        │
│        │                                                                        │
│        ▼                                                                        │
│   Achieve code execution AS ROOT (for SUID binaries)                            │
│                                                                                 │
│   ═══════════════════════════════════════════════════════════════════════════   │
│                                                                                 │
│   KEY INSIGHT: Unlike LD_PRELOAD, GLIBC_TUNABLES was NOT filtered               │
│                for SUID binaries before the fix!                                │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Exploit Concept
```bash
# Simplified concept (actual exploit is more complex)
GLIBC_TUNABLES="glibc.malloc.mxfast=AAAA...[overflow]" /usr/bin/su
```

### Status
- Patched in glibc 2.38-5 and backported
- Check: `ldd --version` and compare to CVE database

---

## 12. LD_HWCAP_MASK Abuse

### Overview
Controls which hardware capability subdirectories are searched for optimized libraries.

```bash
# Normal behavior - linker searches for CPU-optimized libs
/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v3/libc.so.6
/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v2/libc.so.6

# Attack: Mask out capabilities to force loading of specific version
LD_HWCAP_MASK=0 ./target
```

### Attack Use
- Force loading of less optimized (possibly vulnerable) library versions
- Combine with other attacks for specific library targeting

---

## 13. DT_FINI_ARRAY Attacks

### Overview
Like `.init_array` but executes at **program exit**. Useful for post-exploitation persistence.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    INIT vs FINI ARRAYS                                           │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   .preinit_array  ──▶ Before library init (main executable only)                │
│         │                                                                       │
│         ▼                                                                       │
│   .init_array     ──▶ Library/program initialization                            │
│         │                                                                       │
│         ▼                                                                       │
│   main()          ──▶ Program execution                                         │
│         │                                                                       │
│         ▼                                                                       │
│   .fini_array     ──▶ Cleanup at exit() ★ ATTACK HERE FOR PERSISTENCE ★         │
│                                                                                 │
│   Use Case: Exfiltrate data collected during program execution                  │
│             Run cleanup/anti-forensics at exit                                  │
│             Chain to next stage of attack                                       │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Attack Example
```c
// In malicious shared library
__attribute__((destructor))
void evil_cleanup(void) {
    // Executes when program exits
    // Exfiltrate stolen credentials
    // Delete evidence
    // Trigger next stage
}
```

---

## 14. DT_DEBUG / r_debug Manipulation

### Overview
The dynamic linker exposes debug information via the `r_debug` structure, accessible through `DT_DEBUG`. This contains the linked list of all loaded libraries.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    r_debug STRUCTURE                                             │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   struct r_debug {                                                              │
│       int r_version;              // Version                                    │
│       struct link_map *r_map;     // HEAD OF LOADED LIBRARIES LIST              │
│       ElfW(Addr) r_brk;           // Breakpoint address for debuggers           │
│       enum { ... } r_state;       // State of the linker                        │
│       ElfW(Addr) r_ldbase;        // Base address of ld-linux.so                │
│   };                                                                            │
│                                                                                 │
│   Attack Uses:                                                                  │
│   ────────────                                                                  │
│   1. Enumerate all loaded libraries (bypass ASLR partially)                     │
│   2. Find library base addresses                                                │
│   3. Locate GOT/PLT of any library                                              │
│   4. MODIFY link_map chain to hide injected libraries                           │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Access Method
```c
// Find DT_DEBUG in .dynamic section
ElfW(Dyn) *dyn = _DYNAMIC;
struct r_debug *debug = NULL;

for (; dyn->d_tag != DT_NULL; dyn++) {
    if (dyn->d_tag == DT_DEBUG) {
        debug = (struct r_debug *)dyn->d_un.d_ptr;
        break;
    }
}

// Walk the link_map chain
struct link_map *map = debug->r_map;
while (map) {
    printf("Library: %s @ %p\n", map->l_name, (void*)map->l_addr);
    map = map->l_next;
}
```

---

## 15. DT_TEXTREL Abuse

### Overview
When a binary has `DT_TEXTREL`, the TEXT segment must be made **temporarily writable** for relocations. This weakens W^X protections.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    DT_TEXTREL IMPLICATIONS                                       │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   Normal Binary (No TEXTREL):                                                   │
│   ───────────────────────────                                                   │
│   TEXT segment: R-X (read, execute, NO WRITE) - always                          │
│                                                                                 │
│   Binary with DT_TEXTREL:                                                       │
│   ───────────────────────                                                       │
│   1. Linker starts                                                              │
│   2. TEXT segment marked RWX temporarily                                        │
│   3. Relocations applied (writes to code)                                       │
│   4. TEXT segment marked R-X again                                              │
│                                                                                 │
│   Attack Window:                                                                │
│   ──────────────                                                                │
│   During steps 2-4, code is WRITABLE                                            │
│   Race condition possible if attacker can:                                      │
│   - Inject code during this window                                              │
│   - Exploit before permissions are restored                                     │
│                                                                                 │
│   Detection:                                                                    │
│   $ readelf -d binary | grep TEXTREL                                            │
│   $ scanelf -qT binary                                                          │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 16. Symbol Versioning Attacks

### Overview
Glibc uses symbol versioning (e.g., `puts@GLIBC_2.2.5`). Attackers can exploit version mismatches or create fake versioned symbols.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    SYMBOL VERSIONING                                             │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   $ readelf -V /lib/x86_64-linux-gnu/libc.so.6 | head -20                       │
│                                                                                 │
│   Version symbols section '.gnu.version':                                       │
│    0000:   0 (*local*)       2 (GLIBC_2.2.5)    2 (GLIBC_2.2.5)                 │
│    ...                                                                          │
│                                                                                 │
│   Attack Concept:                                                               │
│   ───────────────                                                               │
│   1. Create library with same symbol but DIFFERENT version                      │
│   2. Force linker to bind to attacker's version                                 │
│   3. Especially dangerous with symbol interposition                             │
│                                                                                 │
│   Example: Override getenv@GLIBC_2.2.5 with attacker's version                  │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 17. GNU_UNIQUE Symbol Exploitation

### Overview
Symbols with `STB_GNU_UNIQUE` binding are only resolved ONCE across all loaded objects. This creates a single point of control.

```c
// In library A
__attribute__((visibility("default")))
int unique_var __attribute__((unique)) = 0;

// ALL libraries see the SAME unique_var
// First library to define it controls it for everyone
```

### Attack Use
- First-loaded library controls unique symbols system-wide
- Can affect C++ vtables and type_info
- Combine with LD_PRELOAD for first-load advantage

---

## 18. link_map Chain Manipulation

### Overview
The runtime linker maintains a doubly-linked list of all loaded objects. With write access, you can:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    link_map MANIPULATION                                         │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   Normal Chain:                                                                 │
│   ld-linux.so ←→ program ←→ libc.so ←→ libpthread.so ←→ ...                    │
│                                                                                 │
│   Attack 1: HIDE MALICIOUS LIBRARY                                              │
│   ─────────────────────────────────                                             │
│   Unlink evil.so from chain:                                                    │
│   ld-linux.so ←→ program ←→ libc.so ←→ libpthread.so                           │
│                     ↑                                                           │
│                 evil.so (hidden from /proc/PID/maps enumeration)                │
│                                                                                 │
│   Attack 2: INJECT FAKE LIBRARY ENTRY                                           │
│   ──────────────────────────────────                                            │
│   Add fake link_map pointing to attacker-controlled memory                      │
│                                                                                 │
│   Attack 3: MODIFY EXISTING ENTRY                                               │
│   ────────────────────────────────                                              │
│   Change l_addr to point to different base address                              │
│   Modify l_info[DT_*] pointers to fake dynamic entries                          │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 19. TLS (Thread Local Storage) / DTV Attacks

### Overview
Thread-local variables use a Dynamic Thread Vector (DTV) managed by the linker. Corrupting TLS structures can lead to code execution.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    TLS ARCHITECTURE                                              │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   Thread Control Block (TCB):                                                   │
│   ┌────────────────────────────┐                                                │
│   │ DTV pointer               ├──────▶ Dynamic Thread Vector                   │
│   │ Stack canary              │        ┌─────────────────────┐                  │
│   │ Thread pointer (self)     │        │ Module 1 TLS block  │                  │
│   │ ...                       │        │ Module 2 TLS block  │                  │
│   └────────────────────────────┘        │ ...                 │                  │
│                                         └─────────────────────┘                  │
│                                                                                 │
│   Attack Vectors:                                                               │
│   ───────────────                                                               │
│   1. Overflow into TLS area (adjacent to stack)                                 │
│   2. Corrupt DTV pointers to fake TLS blocks                                    │
│   3. Overwrite stack canary stored in TCB                                       │
│   4. Corrupt __thread variables used for security                               │
│                                                                                 │
│   Access TLS:                                                                   │
│   fs:[0] on x86_64 points to TCB                                                │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 20. Lazy Binding Race Conditions (TOCTOU)

### Overview
Between checking the GOT and using the resolved address, there's a small window for race conditions.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    LAZY BINDING RACE                                             │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   Thread 1: Normal Execution          Thread 2: Attacker                        │
│   ─────────────────────────────       ────────────────────                      │
│                                                                                 │
│   call puts@plt                                                                 │
│        │                                                                        │
│        ▼                                                                        │
│   jmp [puts@got]                                                                │
│        │                                                                        │
│        ▼                                                                        │
│   (GOT points to resolver)                                                      │
│        │                                                                        │
│        ▼                                                                        │
│   _dl_runtime_resolve()                                                         │
│        │                                                                        │
│        ▼                                                                        │
│   Found puts @ 0x7ffff...                                                       │
│        │                              ┌───────────────────────┐                 │
│        ▼                              │ Overwrite puts@got    │                 │
│   Write to puts@got ◄─────────────────│ with evil address!    │                 │
│        │              RACE!           └───────────────────────┘                 │
│        ▼                                                                        │
│   Jump to resolved address                                                      │
│   (could be evil if race won)                                                   │
│                                                                                 │
│   Mitigation: Full RELRO (resolves all at load time)                            │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 21. RTLD_GLOBAL / RTLD_DEEPBIND Abuse

### Overview
Flags passed to `dlopen()` control symbol resolution scope. Abusing these can affect global symbol resolution.

```c
// RTLD_GLOBAL: Symbols available for subsequently loaded libraries
void *h = dlopen("evil.so", RTLD_NOW | RTLD_GLOBAL);
// evil.so's symbols now override for future loads!

// RTLD_DEEPBIND: Library's symbols take precedence over global
void *h = dlopen("evil.so", RTLD_NOW | RTLD_DEEPBIND);
// evil.so can have its own private versions of libc functions
```

### Attack Use
- Plugin systems that use dlopen()
- Force symbol resolution to attacker's library
- Isolate malicious code from detection

---

## 22. dlopen() Path Traversal

### Overview
If application doesn't sanitize library paths passed to `dlopen()`, attacker can load arbitrary libraries.

```c
// Vulnerable code
char libpath[256];
snprintf(libpath, sizeof(libpath), "/app/plugins/%s.so", user_input);
dlopen(libpath, RTLD_NOW);

// Attack
user_input = "../../../tmp/evil"
// Loads /tmp/evil.so instead of /app/plugins/...
```

---

## 23. VDSO/VSYSCALL Hijacking

### Overview
The kernel maps virtual dynamic shared objects (vDSO) into every process for fast syscalls. Compromising these affects all processes.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    VDSO ARCHITECTURE                                             │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   $ cat /proc/self/maps | grep vdso                                             │
│   7ffff7fc3000-7ffff7fc7000 r-xp ... [vdso]                                     │
│                                                                                 │
│   Contains:                                                                     │
│   - clock_gettime()                                                             │
│   - gettimeofday()                                                              │
│   - time()                                                                      │
│   - getcpu()                                                                    │
│                                                                                 │
│   Attack Concepts:                                                              │
│   ────────────────                                                              │
│   1. vDSO as ROP gadget source (always at known relative offset)                │
│   2. If writable (exploit), modify vDSO functions                               │
│   3. vDSO parsing vulnerabilities (CVE-2014-9585)                               │
│                                                                                 │
│   Modern Status:                                                                │
│   - vDSO is READ-ONLY in modern kernels                                         │
│   - ASLR randomizes vDSO location                                               │
│   - Still useful for gadgets if address leaked                                  │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 24. Auxiliary Vector (auxv) Manipulation

### Overview
The kernel passes auxiliary information to the process via the auxiliary vector. Key entries affect security.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    AUXILIARY VECTOR                                              │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   $ LD_SHOW_AUXV=1 /bin/true                                                    │
│                                                                                 │
│   AT_SYSINFO_EHDR: 0x7ffff7fc3000    ← vDSO location                            │
│   AT_HWCAP:        0x...             ← CPU capabilities                         │
│   AT_PAGESZ:       4096              ← Page size                                │
│   AT_PHDR:         0x...             ← Program header location                  │
│   AT_ENTRY:        0x...             ← Entry point                              │
│   AT_UID/GID:      1000/1000         ← User/Group IDs                           │
│   AT_EUID/EGID:    1000/1000         ← Effective IDs                            │
│   AT_SECURE:       0                 ← SECURITY FLAG!                           │
│   AT_RANDOM:       0x...             ← Stack canary source                      │
│   AT_PLATFORM:     x86_64            ← Architecture string                      │
│                                                                                 │
│   Critical Entry - AT_SECURE:                                                   │
│   ────────────────────────────                                                  │
│   AT_SECURE=1 when:                                                             │
│   - SUID/SGID binary                                                            │
│   - Capabilities set                                                            │
│   - SELinux domain transition                                                   │
│                                                                                 │
│   When AT_SECURE=1:                                                             │
│   - LD_PRELOAD ignored                                                          │
│   - LD_LIBRARY_PATH ignored                                                     │
│   - LD_AUDIT ignored                                                            │
│   - Other dangerous env vars stripped                                           │
│                                                                                 │
│   Attack: Bypass AT_SECURE check (e.g., Looney Tunables)                        │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 25. Malicious Linker Scripts

### Overview
Custom linker scripts can define memory layout, symbol placement, and code injection points at compile time.

```
/* evil.ld - Malicious linker script */
SECTIONS {
    /* Inject code at program start */
    .evil_init : {
        *(.evil_init)
    }

    /* Make .text writable for self-modification */
    .text : {
        *(.text)
    } :text_rw

    /* Hide malicious section from normal tools */
    .hidden : {
        *(.hidden)
    } :hidden
}

PHDRS {
    text_rw PT_LOAD FLAGS(7);  /* RWX! */
    hidden PT_NULL;            /* Won't show in normal readelf */
}
```

### Attack Use
- Supply chain attacks (compromised build systems)
- Backdoor binaries at compile time
- Create unusual memory layouts

---

## 26. Constructor Priority Attacks

### Overview
GCC allows specifying constructor priority (101-65535). Lower numbers run FIRST.

```c
// This runs BEFORE normal constructors
__attribute__((constructor(101)))
void very_early_evil(void) {
    // Runs before most library initialization
    // Even before some libc internal setup!
}

// Normal priority (default = 65535)
__attribute__((constructor))
void normal_constructor(void) {
    // Runs after priority constructors
}
```

### Attack Use
- Ensure malicious code runs before security initialization
- Priority 101 runs before most user constructors
- Combine with LD_PRELOAD for earliest possible execution

---

## Suggested Series Extension

Based on these additional attacks, I recommend extending the series:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    EXTENDED SERIES ROADMAP                                       │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   ORIGINAL SERIES (Parts 1-8):                                                  │
│   1. Trojanized Loader ✓                                                        │
│   2. LD_PRELOAD Injection                                                       │
│   3. GOT/PLT Hijacking                                                          │
│   4. .init_array Attacks                                                        │
│   5. DT_RPATH Poisoning                                                         │
│   6. DT_NEEDED Injection                                                        │
│   7. LD_AUDIT Abuse                                                             │
│   8. IFUNC Hijacking                                                            │
│                                                                                 │
│   RECOMMENDED ADDITIONS:                                                        │
│   ───────────────────────                                                       │
│   9.  CVE Deep Dive: Looney Tunables (GLIBC_TUNABLES)   ★ HIGH PRIORITY ★       │
│   10. Runtime Linker Internals: link_map & r_debug                              │
│   11. TLS/DTV Exploitation                                                      │
│   12. Symbol Versioning & GNU_UNIQUE                                            │
│   13. VDSO/Auxv Attack Surface                                                  │
│   14. Defense & Detection Compendium                                            │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Priority Recommendations

| Attack | Priority | Reason |
|--------|----------|--------|
| **GLIBC_TUNABLES (CVE-2023-4911)** | Critical | Recent CVE, real-world privesc |
| **link_map / r_debug** | High | Foundation for advanced attacks |
| **TLS/DTV Attacks** | High | Underexplored, complex |
| **Symbol Versioning** | Medium | Niche but powerful |
| **VDSO/Auxv** | Medium | Kernel boundary knowledge |
| **Constructor Priority** | Medium | Simple but effective |
| **LD_LIBRARY_PATH** | Low | Similar to RPATH (covered) |
| **DT_TEXTREL** | Low | Rare in modern binaries |

---

**Last Updated:** 2025-12-21
