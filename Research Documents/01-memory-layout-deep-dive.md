# Memory Layout Deep Dive - The Foundation of Exploitation

**Lesson 1 of Phase 1**
**Estimated Study Time:** 2-3 hours for theory, 2-3 hours for hands-on practice

---

## Why Memory Layout Matters

Before you can exploit a program, you MUST understand how it lives in memory. Every exploit - buffer overflows, heap exploits, format strings, ROP chains - depends on understanding:

1. **WHERE** things are stored in memory
2. **HOW** they are organized
3. **WHAT** protections exist
4. **WHY** certain memory regions are writable/executable

Think of memory as a building with different floors. Each floor has a purpose, and understanding the layout tells you where the valuables (return addresses, function pointers) are kept.

---

## The Virtual Address Space

When a program runs, the operating system creates a **virtual address space** for it. This is an abstraction - your program thinks it has access to a huge contiguous block of memory, but the OS maps this to physical RAM as needed.

### 32-bit vs 64-bit Address Space

```
32-bit process: 0x00000000 to 0xFFFFFFFF (4 GB total)
                - User space: 0x00000000 to 0x7FFFFFFF (2 GB)  [or 3 GB with special config]
                - Kernel space: 0x80000000 to 0xFFFFFFFF (2 GB) [or 1 GB]

64-bit process: 0x0000000000000000 to 0x00007FFFFFFFFFFF (128 TB user space)
                Kernel space starts at 0xFFFF800000000000
```

**Key insight:** Your exploits typically work in user space. Kernel exploitation is Phase 3.

---

## Memory Segments Explained

A typical Linux process has these segments (from LOW addresses to HIGH addresses):

```
+---------------------------+ 0x00000000 (lowest address)
|          NULL PAGE        |  <- Unmapped, accessing causes SEGFAULT
+---------------------------+
|                           |
|      TEXT (Code)          |  <- Your program's machine code
|      (Read + Execute)     |     Functions live here
|                           |
+---------------------------+
|                           |
|      RODATA               |  <- Read-Only Data (string literals)
|      (Read Only)          |     "Hello World" strings
|                           |
+---------------------------+
|                           |
|      DATA                 |  <- Initialized global/static variables
|      (Read + Write)       |     int global_var = 42;
|                           |
+---------------------------+
|                           |
|      BSS                  |  <- Uninitialized global/static variables
|      (Read + Write)       |     int global_array[1000];
|                           |
+---------------------------+
|                           |
|       HEAP                |  <- Dynamic memory (malloc/new)
|       (Read + Write)      |     Grows UPWARD (toward higher addresses)
|           |               |
|           v               |
|                           |
|        (unused)           |
|                           |
|           ^               |
|           |               |
|       STACK               |  <- Local variables, return addresses
|       (Read + Write)      |     Grows DOWNWARD (toward lower addresses)
|                           |
+---------------------------+
|    Kernel Space           |  <- Off limits to user programs
+---------------------------+ 0x7FFFFFFF (highest user address, 32-bit)
```

---

## Segment Details - Why Each Matters for Exploitation

### 1. TEXT Segment (Code)

```
Permissions: r-x (Read + Execute, NO Write)
Contains:    Compiled machine code (your functions)
```

**What's here:**
- The `main()` function
- All other functions in your program
- Imported library function stubs (PLT entries)

**Why it matters:**
- **CANNOT be modified** (unless you exploit the loader)
- This is where your **ROP gadgets** live (Phase 2)
- Function addresses are here (for ret2plt attacks)

**Example - Finding TEXT segment:**
```bash
# Compile a simple program
echo 'int main() { return 0; }' | gcc -x c - -o simple

# View memory map
readelf -l simple | grep -A1 "LOAD"

# Runtime view (run and check /proc/PID/maps)
cat /proc/self/maps | grep "r-xp"
```

---

### 2. RODATA Segment (Read-Only Data)

```
Permissions: r-- (Read Only)
Contains:    String literals, const data
```

**What's here:**
```c
printf("Hello World");  // "Hello World" is stored in RODATA
const int magic = 0xDEADBEEF;  // May be in RODATA
```

**Why it matters:**
- Strings used in format string attacks can be found here
- Useful for finding "win" conditions or useful strings

---

### 3. DATA Segment (Initialized Data)

```
Permissions: rw- (Read + Write)
Contains:    Initialized global and static variables
```

**What's here:**
```c
int global_counter = 100;        // DATA segment
static char buffer[64] = "test"; // DATA segment
```

**Why it matters:**
- **Writable!** Can be target of overwrites
- Function pointers stored here can be hijacked
- GOT (Global Offset Table) lives here - critical for exploitation!

---

### 4. BSS Segment (Uninitialized Data)

```
Permissions: rw- (Read + Write)
Contains:    Uninitialized global and static variables
```

**What's here:**
```c
int global_array[1000];     // BSS - not initialized, no space in binary
static char huge_buffer[4096]; // BSS
```

**Why it matters:**
- Zero-initialized at runtime by OS
- Large arrays go here
- Same exploitation potential as DATA

---

### 5. HEAP Segment (Dynamic Memory) - CRITICAL FOR EXPLOITATION

```
Permissions: rw- (Read + Write)
Contains:    malloc()'d memory, new objects
Growth:      UPWARD (toward higher addresses)
```

**What's here:**
```c
char *buf = malloc(100);     // Allocated on HEAP
int *arr = calloc(10, sizeof(int));  // HEAP
struct Node *n = new Node(); // HEAP (C++)
```

**Why it matters for exploitation:**

1. **Heap metadata** - malloc stores bookkeeping info next to your data
2. **Use-after-free** - freed memory can be reused
3. **Heap overflow** - overwrite adjacent allocations
4. **Double free** - corrupt heap structures

**Heap internals preview (glibc malloc):**
```
+------------------+
| prev_size (8 bytes)|  <- Size of previous chunk (if free)
+------------------+
| size | flags     |  <- Size of this chunk + 3 flag bits
+------------------+
|                  |
|   User data      |  <- What malloc() returns points HERE
|                  |
+------------------+
| next chunk...    |
```

The `size` field contains the chunk size + 3 bits:
- Bit 0 (P): PREV_INUSE - previous chunk is in use
- Bit 1 (M): IS_MMAPPED - chunk obtained via mmap()
- Bit 2 (A): NON_MAIN_ARENA - chunk from thread arena

**This is why heap exploits work** - corrupt these fields to manipulate allocator behavior!

---

### 6. STACK Segment - MOST EXPLOITED REGION

```
Permissions: rw- (Read + Write)
Contains:    Local variables, function arguments, return addresses
Growth:      DOWNWARD (toward lower addresses)
```

**Why the stack is exploitation gold:**

Every function call creates a **stack frame**:

```
HIGH ADDRESSES
+---------------------------+
| Caller's Stack Frame      |
+---------------------------+
| Arguments (if passed on   |  <- Right-to-left in cdecl
|   stack)                  |
+---------------------------+
| Return Address (RIP/EIP)  |  <- WHERE execution returns - TARGET!
+---------------------------+
| Saved Base Pointer (RBP)  |  <- Previous frame pointer
+---------------------------+ <- Current RBP points here
| Local Variable 1          |
+---------------------------+
| Local Variable 2          |
+---------------------------+
| Local Buffer[64]          |  <- Buffer overflow source!
+---------------------------+ <- Current RSP points here
LOW ADDRESSES
```

**The classic buffer overflow:**
```c
void vulnerable() {
    char buffer[64];      // On stack
    gets(buffer);         // No bounds checking!
    // Input > 64 bytes overwrites saved RBP and return address
}
```

**Stack smashing attack:**
```
User input: [64 bytes of padding][8 bytes new RBP][8 bytes new return address]
                                                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                                                    This controls execution!
```

---

## Viewing Memory Layout in Practice

### Method 1: /proc/PID/maps (Runtime)

```bash
# For current shell
cat /proc/self/maps

# Example output:
# 555555554000-555555555000 r--p 00000000 08:01 1234  /path/to/binary  <- ELF header
# 555555555000-555555556000 r-xp 00001000 08:01 1234  /path/to/binary  <- TEXT
# 555555556000-555555557000 r--p 00002000 08:01 1234  /path/to/binary  <- RODATA
# 555555557000-555555558000 rw-p 00003000 08:01 1234  /path/to/binary  <- DATA/BSS
# 555555558000-555555579000 rw-p 00000000 00:00 0     [heap]           <- HEAP
# 7ffff7c00000-7ffff7c28000 r--p 00000000 08:01 5678  /lib/libc.so.6   <- libc
# ...
# 7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0     [stack]          <- STACK
```

**Permission flags:**
- `r` = readable
- `w` = writable
- `x` = executable
- `p` = private (copy-on-write)
- `s` = shared

### Method 2: readelf (Static Analysis)

```bash
readelf -S binary      # Section headers
readelf -l binary      # Program headers (segments)
readelf --segments binary  # Same as -l
```

### Method 3: GDB with pwndbg/GEF

```bash
gdb ./binary
(gdb) start           # Run until main
(gdb) vmmap           # pwndbg command - shows memory map
(gdb) info proc mappings  # GDB native
```

### Method 4: objdump

```bash
objdump -h binary     # Section headers with addresses
```

---

## Hands-On Exercise 1: Explore Memory Layout

Create this program and analyze it:

```c
/* File: phase1-foundation/c-cpp-practice/memory_explorer.c */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// BSS segment - uninitialized
int bss_var;
char bss_buffer[256];

// DATA segment - initialized
int data_var = 42;
char data_string[] = "I'm in DATA";

// RODATA - const/string literal
const char *rodata_string = "I'm in RODATA";

void function_in_text() {
    printf("I'm a function in TEXT segment\n");
}

int main() {
    // Stack variables
    int stack_var = 100;
    char stack_buffer[64];

    // Heap variables
    char *heap_buffer = malloc(128);
    int *heap_array = malloc(10 * sizeof(int));

    printf("\n=== MEMORY LAYOUT EXPLORER ===\n\n");

    printf("TEXT Segment:\n");
    printf("  main() is at:              %p\n", (void*)main);
    printf("  function_in_text() is at:  %p\n", (void*)function_in_text);
    printf("  printf() is at:            %p\n", (void*)printf);

    printf("\nRODATA Segment:\n");
    printf("  rodata_string points to:   %p\n", (void*)rodata_string);
    printf("  String literal \"Hello\":    %p\n", (void*)"Hello");

    printf("\nDATA Segment:\n");
    printf("  data_var is at:            %p\n", (void*)&data_var);
    printf("  data_string is at:         %p\n", (void*)data_string);

    printf("\nBSS Segment:\n");
    printf("  bss_var is at:             %p\n", (void*)&bss_var);
    printf("  bss_buffer is at:          %p\n", (void*)bss_buffer);

    printf("\nHEAP Segment:\n");
    printf("  heap_buffer is at:         %p\n", (void*)heap_buffer);
    printf("  heap_array is at:          %p\n", (void*)heap_array);

    printf("\nSTACK Segment:\n");
    printf("  stack_var is at:           %p\n", (void*)&stack_var);
    printf("  stack_buffer is at:        %p\n", (void*)stack_buffer);
    printf("  main's frame (approx):     %p\n", (void*)&stack_var);

    printf("\n=== OBSERVATIONS ===\n");
    printf("Notice how:\n");
    printf("  - TEXT addresses are lowest (start with 0x55... on 64-bit)\n");
    printf("  - HEAP grows upward (heap_array > heap_buffer if allocated after)\n");
    printf("  - STACK is at high addresses (0x7fff...)\n");
    printf("  - STACK grows downward (lower addresses)\n");

    // Wait so we can check /proc/PID/maps
    printf("\nProcess PID: %d\n", getpid());
    printf("Run: cat /proc/%d/maps\n", getpid());
    printf("Press Enter to exit...\n");
    getchar();

    free(heap_buffer);
    free(heap_array);

    return 0;
}
```

**Compile and run:**
```bash
cd /home/spider/offensive-security-mastery/phase1-foundation/c-cpp-practice
gcc -g -o memory_explorer memory_explorer.c
./memory_explorer

# In another terminal while it's waiting:
cat /proc/$(pgrep memory_explorer)/maps
```

---

## Hands-On Exercise 2: Stack Frame Analysis

Create this to understand stack frames:

```c
/* File: phase1-foundation/c-cpp-practice/stack_frames.c */

#include <stdio.h>

void innermost(int a) {
    int local = 0xDEAD;
    printf("=== INNERMOST FUNCTION ===\n");
    printf("  Parameter 'a' at:     %p (value: %d)\n", (void*)&a, a);
    printf("  Local 'local' at:     %p (value: 0x%X)\n", (void*)&local, local);
    printf("  Note: local is at LOWER address than parameter\n");
    printf("        (stack grows DOWN)\n");
}

void middle(int x, int y) {
    int mid_local = 0xBEEF;
    printf("\n=== MIDDLE FUNCTION ===\n");
    printf("  Parameter 'x' at:     %p (value: %d)\n", (void*)&x, x);
    printf("  Parameter 'y' at:     %p (value: %d)\n", (void*)&y, y);
    printf("  Local 'mid_local' at: %p (value: 0x%X)\n", (void*)&mid_local, mid_local);

    innermost(42);
}

void outer(void) {
    int outer_local = 0xCAFE;
    char buffer[32];

    printf("\n=== OUTER FUNCTION ===\n");
    printf("  Local 'outer_local' at: %p (value: 0x%X)\n", (void*)&outer_local, outer_local);
    printf("  Buffer[32] starts at:   %p\n", (void*)buffer);
    printf("  Buffer[32] ends at:     %p\n", (void*)(buffer + 31));

    middle(100, 200);
}

int main() {
    printf("=== STACK FRAME EXPLORER ===\n");
    printf("\nmain() is at: %p\n", (void*)main);

    outer();

    printf("\n=== STACK LAYOUT (HIGH TO LOW) ===\n");
    printf("  main's frame\n");
    printf("  |\n");
    printf("  v  (stack grows down)\n");
    printf("  outer's frame\n");
    printf("  |\n");
    printf("  v\n");
    printf("  middle's frame\n");
    printf("  |\n");
    printf("  v\n");
    printf("  innermost's frame (lowest addresses)\n");

    return 0;
}
```

**Compile and run:**
```bash
gcc -g -fno-stack-protector -o stack_frames stack_frames.c
./stack_frames
```

---

## Key Takeaways

1. **Memory is organized in segments** with different purposes and permissions
2. **TEXT is read-only and executable** - you can't write shellcode there (unless you bypass NX)
3. **STACK grows DOWN** - this is why buffer overflows overwrite return addresses at HIGHER addresses
4. **HEAP grows UP** - heap exploits work differently than stack exploits
5. **The return address is the classic target** - controlling it means controlling execution
6. **GOT/PLT are in writable memory** - they can be overwritten (GOT overwrite attacks)

---

## What's Next

Now that you understand memory layout, the next lessons will cover:
1. **Compilation flags and protections** (ASLR, NX, Stack Canaries, PIE)
2. **Buffer overflows** - exploiting the stack
3. **Format string vulnerabilities** - arbitrary read/write
4. **Heap exploitation basics** - corrupting dynamic memory

---

## Self-Test Questions

1. Which direction does the stack grow?
2. Where is the return address stored relative to local variables?
3. What's the difference between DATA and BSS segments?
4. Why can't you write to the TEXT segment?
5. What's stored in the GOT and why is it exploitable?

**Answers are in the next lesson's introduction.**

---

**Last Updated:** 2025-12-20
**Next Lesson:** [02-compilation-and-protections.md](./02-compilation-and-protections.md)
