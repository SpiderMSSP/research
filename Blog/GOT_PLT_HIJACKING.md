# Part 3: GOT/PLT Hijacking - Redirecting Library Calls at Runtime

## Overview

GOT/PLT Hijacking is a powerful technique that redirects function calls by overwriting entries in the **Global Offset Table (GOT)**. Unlike LD_PRELOAD (which works at load time), GOT hijacking occurs at **runtime** by writing to memory locations that hold function pointers.

This attack exploits the fundamental mechanism Linux uses for calling shared library functions efficiently.

---

## The Problem: How Does a Program Call Library Functions?

When you write `puts("Hello")` in C, the compiler doesn't know where `puts()` will be in memory at runtime. Shared libraries like libc can be loaded at different addresses due to **ASLR (Address Space Layout Randomization)**.

The solution? **Lazy binding** through the PLT and GOT.

---

## Understanding PLT and GOT

### The Procedure Linkage Table (PLT)

The PLT is a table of **small code stubs** in your program. Each external function gets its own PLT entry.

```
.plt section (code - executable, read-only):

puts@plt:
    jmp    *puts@got        ; Jump to address stored in GOT
    push   $0x0             ; Push relocation index (for resolver)
    jmp    plt_resolver     ; Jump to dynamic linker resolver
```

### The Global Offset Table (GOT)

The GOT is a table of **pointers** that the PLT jumps through. Initially, these point back to PLT stubs; after resolution, they point to actual library functions.

```
.got.plt section (data - initially writable):

got[0]: address of .dynamic section
got[1]: address of link_map (filled by ld.so)
got[2]: address of _dl_runtime_resolve
got[3]: puts   → initially points to puts@plt+6 (stub)
got[4]: printf → initially points to printf@plt+6 (stub)
...
```

---

## Lazy Binding: Step by Step

### First Call to puts()

```
    Your Code                 PLT                         GOT
   ┌─────────────┐      ┌──────────────┐         ┌──────────────────┐
   │             │      │              │         │                  │
   │ call puts@plt ────→│ jmp *got[3]  │────────→│ got[3] = plt+6   │
   │             │      │              │         │ (stub address)   │
   └─────────────┘      └──────────────┘         └────────┬─────────┘
                                                          │
                               ┌──────────────────────────┘
                               ▼
                        ┌──────────────┐
                        │ push $0      │  ← Relocation index for puts
                        │ jmp resolver │
                        └──────┬───────┘
                               │
                               ▼
                        ┌──────────────────────────────────────┐
                        │     _dl_runtime_resolve()            │
                        │                                      │
                        │  1. Look up "puts" in libc           │
                        │  2. Write libc:puts addr to got[3]   │
                        │  3. Jump to puts() in libc           │
                        └──────────────────────────────────────┘
```

### Subsequent Calls to puts()

```
    Your Code                 PLT                         GOT
   ┌─────────────┐      ┌──────────────┐         ┌──────────────────┐
   │             │      │              │         │                  │
   │ call puts@plt ────→│ jmp *got[3]  │────────→│ got[3] = libc:puts│
   │             │      │              │         │                  │
   └─────────────┘      └──────────────┘         └────────┬─────────┘
                                                          │
                                                          │ DIRECT!
                                                          ▼
                                                 ┌──────────────────┐
                                                 │                  │
                                                 │  libc: puts()    │
                                                 │                  │
                                                 └──────────────────┘
```

**Key Insight**: After resolution, GOT[3] contains the **actual address of puts() in libc**. If we can overwrite this address, we control where the program jumps!

---

## The Attack: GOT Hijacking

### Attack Visualization

```
    BEFORE HIJACKING                      AFTER HIJACKING

    ┌──────────────────┐                  ┌──────────────────┐
    │ call puts@plt    │                  │ call puts@plt    │
    └────────┬─────────┘                  └────────┬─────────┘
             │                                     │
             ▼                                     ▼
    ┌──────────────────┐                  ┌──────────────────┐
    │ jmp *GOT[puts]   │                  │ jmp *GOT[puts]   │
    └────────┬─────────┘                  └────────┬─────────┘
             │                                     │
             ▼                                     ▼
    ┌──────────────────┐                  ┌──────────────────┐
    │ GOT[puts] =      │                  │ GOT[puts] =      │
    │ 0x7f...libc:puts │                  │ 0x401234:evil()  │ ← OVERWRITTEN!
    └────────┬─────────┘                  └────────┬─────────┘
             │                                     │
             ▼                                     ▼
    ┌──────────────────┐                  ┌──────────────────┐
    │ libc: puts()     │                  │ evil_puts()      │
    │ Normal output    │                  │ Attacker code!   │
    └──────────────────┘                  └──────────────────┘
```

### What You Need for GOT Hijacking

1. **Write primitive**: Ability to write arbitrary data to arbitrary addresses
   - Buffer overflow
   - Format string vulnerability
   - Use-after-free
   - Or... direct memory access (like in our demo)

2. **Writable GOT**: The GOT must not be read-only (no Full RELRO)

3. **Target address**: Know where your malicious function is located

---

## Memory Layout with GOT/PLT

```
Virtual Memory Layout:

    Low Addresses
    ┌────────────────────────────────────────┐ 0x400000
    │            .text (CODE)                │
    │  - Your main() function                │
    │  - Other functions                     │
    │  - PLT stubs live here                 │
    ├────────────────────────────────────────┤
    │            .plt                        │
    │  puts@plt:   jmp *got[puts]            │
    │  printf@plt: jmp *got[printf]          │
    │  ...                                   │
    ├────────────────────────────────────────┤
    │            .rodata                     │
    │  String constants, etc.                │
    ├────────────────────────────────────────┤
    │            .got                        │ ← May be read-only (Partial RELRO)
    │  Global variables' addresses           │
    ├────────────────────────────────────────┤
    │            .got.plt                    │ ← ATTACK TARGET!
    │  got[0]: .dynamic                      │
    │  got[1]: link_map                      │
    │  got[2]: _dl_runtime_resolve           │
    │  got[3]: puts address     ← HIJACK THIS│
    │  got[4]: printf address                │
    │  ...                                   │
    ├────────────────────────────────────────┤
    │            .data / .bss                │
    │  Global/static variables               │
    ├────────────────────────────────────────┤
    │            HEAP                        │
    │              ↓                         │
    │                                        │
    │              ↑                         │
    │            STACK                       │
    └────────────────────────────────────────┘
    High Addresses
```

---

## RELRO: The Defense Mechanism

**RELRO (RELocation Read-Only)** is a security feature that can protect the GOT.

### No RELRO
```
Compile: gcc -Wl,-z,norelro program.c

.got.plt: WRITABLE
Status:   Fully vulnerable to GOT hijacking
```

### Partial RELRO (Default)
```
Compile: gcc program.c  (or -Wl,-z,relro)

.got:     READ-ONLY (protected)
.got.plt: WRITABLE  (still vulnerable after resolution!)
Status:   Vulnerable after first function call
```

### Full RELRO
```
Compile: gcc -Wl,-z,relro,-z,now program.c

.got:     READ-ONLY
.got.plt: READ-ONLY
All symbols resolved at load time (no lazy binding)
Status:   Protected against GOT hijacking
```

### Visual Comparison

```
                    NO RELRO        PARTIAL RELRO      FULL RELRO

    .got            [WRITABLE]      [READ-ONLY]        [READ-ONLY]
                         │               │                  │
                         ▼               ▼                  ▼
                    ┌─────────┐     ┌─────────┐        ┌─────────┐
                    │ rw-p    │     │ r--p    │        │ r--p    │
                    └─────────┘     └─────────┘        └─────────┘

    .got.plt        [WRITABLE]      [WRITABLE]         [READ-ONLY]
                         │               │                  │
                         ▼               ▼                  ▼
                    ┌─────────┐     ┌─────────┐        ┌─────────┐
                    │ rw-p    │     │ rw-p    │        │ r--p    │
                    │HIJACKABLE│    │HIJACKABLE│       │PROTECTED│
                    └─────────┘     └─────────┘        └─────────┘
```

---

## The Hijacking Code Explained

### Step 1: Locate the GOT Entry

```c
/* The GOT entry is in the program's data segment */
/* We can find it by scanning memory for known libc addresses */

void *real_puts = dlsym(RTLD_NEXT, "puts");  /* Get libc address */

/* Scan writable memory regions for this address */
for (addr = data_start; addr < data_end; addr += 8) {
    if (*(void **)addr == real_puts) {
        got_entry = (void **)addr;  /* Found it! */
        break;
    }
}
```

### Step 2: Make GOT Writable (if needed)

```c
/* For Partial RELRO, GOT.PLT is already writable */
/* For Full RELRO, this would fail */

uintptr_t page = (uintptr_t)got_entry & ~0xFFF;
mprotect((void *)page, 0x1000, PROT_READ | PROT_WRITE);
```

### Step 3: Overwrite the GOT Entry

```c
/* The actual hijack - one pointer write! */
*got_entry = evil_puts;  /* Redirect puts to our function */
```

### Step 4: All Subsequent Calls Are Hijacked

```c
/* Now when the victim calls puts()... */
puts("Hello");  /* Actually calls evil_puts("Hello")! */
```

---

## Attack Scenarios

### Scenario 1: Credential Theft via puts() Hook

```c
int evil_puts(const char *s) {
    /* Log everything printed - might contain secrets */
    log_to_attacker(s);

    /* Call real puts so program works normally */
    return real_puts(s);
}
```

### Scenario 2: Code Execution via system() Redirect

```c
/* Redirect strlen to system - dangerous! */
/* When program calls strlen(user_input)... */
/* It actually calls system(user_input)! */

*got_strlen = system;  /* strlen("ls") → system("ls") */
```

### Scenario 3: Authentication Bypass via strcmp() Hook

```c
int evil_strcmp(const char *s1, const char *s2) {
    /* Always return 0 = strings match */
    /* Bypasses: if (strcmp(input, password) == 0) */
    return 0;
}
```

---

## Detecting GOT Hijacking

### Method 1: Compare GOT Values to Expected Addresses

```c
void *expected = dlsym(RTLD_NEXT, "puts");
void *actual = *got_puts;

if (expected != actual) {
    alert("GOT hijacking detected!");
}
```

### Method 2: Monitor GOT Memory Region

```c
/* Use mprotect to make GOT read-only after initialization */
/* Any write attempt will cause SIGSEGV */
mprotect(got_page, size, PROT_READ);
```

### Method 3: Use Full RELRO

```bash
# Compile with Full RELRO
gcc -Wl,-z,relro,-z,now program.c

# Verify protection
readelf -d program | grep BIND_NOW
checksec --file=program
```

---

## Comparison with LD_PRELOAD

| Aspect | LD_PRELOAD | GOT Hijacking |
|--------|------------|---------------|
| **When** | Load time (before main) | Runtime (any time) |
| **How** | Environment variable | Memory write |
| **Requires** | Control of LD_PRELOAD | Write primitive |
| **Scope** | All calls system-wide | Per-GOT entry |
| **Defenses** | AT_SECURE for SUID | Full RELRO |
| **Detection** | Check env variables | Monitor GOT values |
| **Persistence** | Only for that process | Only while running |

---

## Defense Recommendations

### For Developers

1. **Enable Full RELRO**
   ```bash
   gcc -Wl,-z,relro,-z,now program.c
   ```

2. **Enable PIE (Position Independent Executable)**
   ```bash
   gcc -pie -fPIE program.c
   ```

3. **Validate function pointers**
   ```c
   if (func_ptr < libc_base || func_ptr > libc_end) {
       abort();  /* Suspicious pointer */
   }
   ```

### For System Administrators

1. **Check binary protections**
   ```bash
   checksec --file=/path/to/binary
   ```

2. **Enforce Full RELRO in build systems**

3. **Use AddressSanitizer during development**
   ```bash
   gcc -fsanitize=address program.c
   ```

---

## Files in This POC

| File | Description |
|------|-------------|
| `victim.c` | Target program making library calls |
| `got_hijack_demo.c` | Self-contained hijacking demonstration |
| `got_inspector.c` | Utility to analyze GOT/PLT of any binary |
| `Makefile` | Build with different RELRO levels |

## Building and Running

```bash
# Build all components
make all

# Run the GOT hijacking demonstration
make demo

# Inspect a binary's GOT
make inspect

# Compare RELRO protection levels
make compare

# Show raw GOT/PLT entries
make show-got

# Clean up
make clean
```

---

## Key Takeaways

1. **PLT/GOT is an indirection layer** - Programs don't call libc directly; they jump through function pointers in the GOT

2. **GOT entries are writable by default** - After lazy resolution, GOT contains libc addresses that can be overwritten

3. **One write = complete control** - Overwriting a GOT entry with a single pointer write redirects all subsequent calls

4. **Full RELRO prevents this** - Making GOT read-only and resolving all symbols at load time eliminates the attack surface

5. **This is why you need write primitives** - GOT hijacking requires the ability to write to specific memory locations, typically obtained through other vulnerabilities
