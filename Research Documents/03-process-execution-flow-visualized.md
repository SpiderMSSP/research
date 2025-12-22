# Process Execution Flow - Visualized Step by Step

**Understanding How a Program Actually Runs**

---

## The Big Picture

When you run `./program`, here's what happens across all segments:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         PROCESS EXECUTION TIMELINE                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  YOU TYPE: ./program                                                        │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │   KERNEL    │───▶│   LOADER    │───▶│   LINKER    │───▶│  YOUR CODE  │  │
│  │  (execve)   │    │ (ld-linux)  │    │  (resolves) │    │   (main)    │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
│                                                                             │
│  1. Load ELF       2. Map segments    3. Resolve         4. Jump to        │
│     into memory       into memory        symbols            _start         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: You Type `./program`

### Step 1.1: Shell Calls execve()

```
┌──────────────────────────────────────────────────────────────────┐
│                           SHELL (bash)                           │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│   You type: ./program                                            │
│                                                                  │
│   Shell does:                                                    │
│       1. fork()     → Creates child process                      │
│       2. execve()   → Replaces child with your program           │
│                                                                  │
│   execve("./program", argv[], envp[])                            │
│       │                                                          │
│       └──────────────────────────────────────────────────────┐   │
│                                                              │   │
└──────────────────────────────────────────────────────────────│───┘
                                                               │
                                                               ▼
┌──────────────────────────────────────────────────────────────────┐
│                           KERNEL                                 │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│   1. Open the file "./program"                                   │
│   2. Read ELF header (first 64 bytes)                            │
│   3. Check: Is it executable? Correct architecture?              │
│   4. Read program headers (LOAD segments)                        │
│   5. Create new memory space for process                         │
│   6. Map segments into memory                                    │
│   7. Find INTERP segment → "/lib64/ld-linux-x86-64.so.2"         │
│   8. Load the dynamic linker                                     │
│   9. Jump to dynamic linker's entry point                        │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Step 1.2: Kernel Maps the Binary

```
                    ELF FILE (on disk)
                    ┌────────────────────┐
                    │ ELF Header         │
                    │ Program Headers    │──────┐
                    ├────────────────────┤      │
                    │ .text (code)       │      │
                    │ .rodata            │      │     KERNEL READS
                    ├────────────────────┤      │     PROGRAM HEADERS
                    │ .data              │      │
                    │ .bss               │      │
                    └────────────────────┘      │
                                                │
                    ┌───────────────────────────┘
                    │
                    ▼
    ╔══════════════════════════════════════════════════════════════════╗
    ║              PROGRAM HEADERS SAY:                                ║
    ╠══════════════════════════════════════════════════════════════════╣
    ║  LOAD  offset=0x0000  vaddr=0x400000  size=0x1000  flags=R       ║
    ║  LOAD  offset=0x1000  vaddr=0x401000  size=0x500   flags=R+X     ║ ← CODE
    ║  LOAD  offset=0x2000  vaddr=0x402000  size=0x200   flags=R       ║ ← RODATA
    ║  LOAD  offset=0x3000  vaddr=0x404000  size=0x100   flags=R+W     ║ ← DATA
    ║  INTERP → "/lib64/ld-linux-x86-64.so.2"                          ║
    ╚══════════════════════════════════════════════════════════════════╝
                    │
                    │ KERNEL MAPS EACH LOAD SEGMENT
                    ▼
    ┌──────────────────────────────────────────────────────────────────┐
    │                     VIRTUAL MEMORY                               │
    ├──────────────────────────────────────────────────────────────────┤
    │                                                                  │
    │  0x400000 ┌─────────────────┐                                    │
    │           │ ELF Headers (R) │                                    │
    │  0x401000 ├─────────────────┤                                    │
    │           │ .text CODE (RX) │ ← Your functions go here           │
    │  0x402000 ├─────────────────┤                                    │
    │           │ .rodata (R)     │ ← String literals                  │
    │  0x404000 ├─────────────────┤                                    │
    │           │ .data/.bss (RW) │ ← Global variables                 │
    │           └─────────────────┘                                    │
    │                                                                  │
    │           (big gap - unmapped)                                   │
    │                                                                  │
    │  0x7ffff7... ┌─────────────────┐                                 │
    │              │ ld-linux.so     │ ← Dynamic linker loaded here    │
    │              └─────────────────┘                                 │
    │                                                                  │
    └──────────────────────────────────────────────────────────────────┘
```

---

## Phase 2: Dynamic Linker Takes Over

### Step 2.1: ld-linux.so Starts

```
┌──────────────────────────────────────────────────────────────────┐
│                    DYNAMIC LINKER (ld-linux.so)                  │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Kernel jumps here first, NOT to your main()!                   │
│                                                                  │
│   Tasks:                                                         │
│   ┌────────────────────────────────────────────────────────────┐ │
│   │ 1. Read DYNAMIC segment from your binary                  │ │
│   │    - Find list of needed libraries (DT_NEEDED)            │ │
│   │    - Find symbol tables (DT_SYMTAB)                       │ │
│   │    - Find relocation tables (DT_RELA)                     │ │
│   └────────────────────────────────────────────────────────────┘ │
│                           │                                      │
│                           ▼                                      │
│   ┌────────────────────────────────────────────────────────────┐ │
│   │ 2. Load required shared libraries                         │ │
│   │    - libc.so.6 (printf, malloc, etc.)                     │ │
│   │    - libpthread.so (if threaded)                          │ │
│   │    - Any other libraries your program needs               │ │
│   └────────────────────────────────────────────────────────────┘ │
│                           │                                      │
│                           ▼                                      │
│   ┌────────────────────────────────────────────────────────────┐ │
│   │ 3. Perform relocations                                    │ │
│   │    - Fill in GOT entries (for lazy binding)               │ │
│   │    - Or resolve all symbols now (if BIND_NOW)             │ │
│   └────────────────────────────────────────────────────────────┘ │
│                           │                                      │
│                           ▼                                      │
│   ┌────────────────────────────────────────────────────────────┐ │
│   │ 4. Jump to your program's _start                          │ │
│   └────────────────────────────────────────────────────────────┘ │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Step 2.2: Memory After Libraries Loaded

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    VIRTUAL MEMORY (After Loading)                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   LOW ADDRESSES                                                         │
│                                                                         │
│   0x400000    ┌──────────────────────────────────────┐                  │
│               │         YOUR BINARY                  │                  │
│               │  ┌────────────────────────────────┐  │                  │
│               │  │ .text    (your code)      R-X │  │                  │
│               │  │ .rodata  (strings)        R-- │  │                  │
│               │  │ .data    (initialized)    RW- │  │                  │
│               │  │ .bss     (uninitialized)  RW- │  │                  │
│               │  │ .got     (GOT table)      RW- │  │ ← IMPORTANT!     │
│               │  │ .plt     (PLT stubs)      R-X │  │ ← IMPORTANT!     │
│               │  └────────────────────────────────┘  │                  │
│               └──────────────────────────────────────┘                  │
│                                                                         │
│               (unmapped gap)                                            │
│                                                                         │
│   0x7ffff7c00000  ┌──────────────────────────────────────┐              │
│                   │         LIBC.SO.6                    │              │
│                   │  ┌────────────────────────────────┐  │              │
│                   │  │ .text (printf, malloc...)  R-X │  │              │
│                   │  │ .data                      RW- │  │              │
│                   │  └────────────────────────────────┘  │              │
│                   └──────────────────────────────────────┘              │
│                                                                         │
│   0x7ffff7fc5000  ┌──────────────────────────────────────┐              │
│                   │         LD-LINUX.SO                  │              │
│                   └──────────────────────────────────────┘              │
│                                                                         │
│               (unmapped gap)                                            │
│                                                                         │
│   0x7ffffffde000  ┌──────────────────────────────────────┐              │
│                   │         STACK                        │              │
│                   │         (grows downward ↓)           │              │
│                   └──────────────────────────────────────┘              │
│                                                                         │
│   HIGH ADDRESSES                                                        │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Phase 3: Your Program Starts (_start → main)

### Step 3.1: _start Function

```
┌──────────────────────────────────────────────────────────────────┐
│                     EXECUTION FLOW                               │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Dynamic linker jumps to: _start (NOT main!)                    │
│                                                                  │
│   ┌────────────────────────────────────────────────────────────┐ │
│   │  _start:                      ; Entry point                │ │
│   │      xor ebp, ebp             ; Clear frame pointer        │ │
│   │      mov rdi, [rsp]           ; argc                       │ │
│   │      lea rsi, [rsp+8]         ; argv                       │ │
│   │      call __libc_start_main   ; ──┐                        │ │
│   └────────────────────────────────────│────────────────────────┘ │
│                                        │                         │
│                                        ▼                         │
│   ┌────────────────────────────────────────────────────────────┐ │
│   │  __libc_start_main:           ; In libc                    │ │
│   │      - Set up thread-local storage                         │ │
│   │      - Initialize libc internals                           │ │
│   │      - Call constructors (.init_array)                     │ │
│   │      - call main(argc, argv, envp)  ; ──┐                  │ │
│   │      - Call destructors (.fini_array)   │                  │ │
│   │      - exit()                           │                  │ │
│   └─────────────────────────────────────────│──────────────────┘ │
│                                             │                    │
│                                             ▼                    │
│   ┌────────────────────────────────────────────────────────────┐ │
│   │  main:                        ; YOUR CODE FINALLY!         │ │
│   │      push rbp                                              │ │
│   │      mov rbp, rsp                                          │ │
│   │      ... your code ...                                     │ │
│   └────────────────────────────────────────────────────────────┘ │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Step 3.2: Stack at main() Entry

```
┌──────────────────────────────────────────────────────────────────┐
│                 STACK WHEN main() STARTS                         │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│   HIGH ADDRESSES                                                 │
│                                                                  │
│   ┌─────────────────────────────────────────┐                    │
│   │ Environment variables (envp[])          │                    │
│   │   "PATH=/usr/bin:..."                   │                    │
│   │   "HOME=/home/user"                     │                    │
│   │   "SHELL=/bin/bash"                     │                    │
│   │   NULL                                  │                    │
│   ├─────────────────────────────────────────┤                    │
│   │ Argument strings (argv[])               │                    │
│   │   "./program"                           │                    │
│   │   "arg1"                                │                    │
│   │   "arg2"                                │                    │
│   │   NULL                                  │                    │
│   ├─────────────────────────────────────────┤                    │
│   │ envp[] pointers                         │                    │
│   ├─────────────────────────────────────────┤                    │
│   │ argv[] pointers                         │                    │
│   ├─────────────────────────────────────────┤                    │
│   │ argc (argument count)                   │                    │
│   ├─────────────────────────────────────────┤ ← Initial RSP      │
│   │                                         │                    │
│   │ (stack frames will grow here)           │                    │
│   │           ↓                             │                    │
│   │                                         │                    │
│   └─────────────────────────────────────────┘                    │
│                                                                  │
│   LOW ADDRESSES                                                  │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## Phase 4: Calling a Library Function (PLT/GOT)

This is where it gets interesting! When your code calls `printf()`:

### Step 4.1: First Call to printf() (Lazy Binding)

```
YOUR CODE                         PLT                              GOT
─────────────────────────────────────────────────────────────────────────────

┌─────────────────┐
│ main:           │
│   ...           │
│   call printf   │──────┐
│   ...           │      │
└─────────────────┘      │
                         │
                         ▼
              ┌─────────────────────────────────────┐
              │ printf@plt:                         │
              │   jmp [printf@got]  ────────────────│────┐
              │   push 0            ; reloc index   │    │
              │   jmp resolver      ────────────────│──┐ │
              └─────────────────────────────────────┘  │ │
                                                       │ │
                              ┌─────────────────────────┘ │
                              │                           │
                              ▼                           ▼
              ┌──────────────────────────────────────────────┐
              │ GOT (initially):                             │
              │                                              │
              │   printf@got: [points back to PLT+6]  ───────│──┐
              │                                              │  │
              └──────────────────────────────────────────────┘  │
                              │                                 │
                              │ First time: GOT points back     │
                              │ to PLT, triggering resolver     │
                              │                                 │
                              ▼                                 │
              ┌──────────────────────────────────────────────┐  │
              │ _dl_runtime_resolve:                         │  │
              │   1. Look up "printf" in libc                │  │
              │   2. Find address: 0x7ffff7c60100            │  │
              │   3. Write address to GOT                    │  │
              │   4. Jump to printf                          │  │
              └──────────────────────────────────────────────┘  │
                              │                                 │
                              ▼                                 │
              ┌──────────────────────────────────────────────┐  │
              │ GOT (after resolution):                      │  │
              │                                              │  │
              │   printf@got: 0x7ffff7c60100  ──────────────────│──┐
              │               (actual printf address)        │  │  │
              └──────────────────────────────────────────────┘  │  │
                                                                │  │
                         ┌──────────────────────────────────────┘  │
                         │                                         │
                         ▼                                         │
              ┌──────────────────────────────────────────────┐     │
              │ printf (in libc):                            │ ←───┘
              │   push rbp                                   │
              │   ...actual printf code...                   │
              │   ret                                        │
              └──────────────────────────────────────────────┘
```

### Step 4.2: Second Call to printf() (Fast Path)

```
YOUR CODE                         PLT                              GOT
─────────────────────────────────────────────────────────────────────────────

┌─────────────────┐
│ main:           │
│   ...           │
│   call printf   │──────┐
│   ...           │      │
└─────────────────┘      │
                         │
                         ▼
              ┌─────────────────────────────────────┐
              │ printf@plt:                         │
              │   jmp [printf@got]  ────────────────│───────────────┐
              │   push 0                            │               │
              │   jmp resolver                      │               │
              └─────────────────────────────────────┘               │
                                                                    │
                                                                    │
                              ┌──────────────────────────────────────┐
                              │ GOT (already resolved):             │
                              │                                     │
                              │   printf@got: 0x7ffff7c60100  ──────│───┐
                              │               (direct to printf!)   │   │
                              └──────────────────────────────────────┘   │
                                                                         │
                                        DIRECT JUMP! No resolver!        │
                                                                         │
                              ┌──────────────────────────────────────────┘
                              │
                              ▼
              ┌──────────────────────────────────────────────┐
              │ printf (in libc):                            │
              │   push rbp                                   │
              │   ...actual printf code...                   │
              │   ret                                        │
              └──────────────────────────────────────────────┘
```

### Why This Matters for Exploitation:

```
╔═══════════════════════════════════════════════════════════════════════════╗
║                         GOT OVERWRITE ATTACK                              ║
╠═══════════════════════════════════════════════════════════════════════════╣
║                                                                           ║
║   If you can OVERWRITE a GOT entry:                                       ║
║                                                                           ║
║   BEFORE:  printf@got → 0x7ffff7c60100 (real printf)                      ║
║                                                                           ║
║   AFTER:   printf@got → 0x401234 (your malicious function!)               ║
║                                                                           ║
║   Next time printf() is called → YOUR code runs!                          ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
```

---

## Phase 5: Memory Allocation (malloc)

### Step 5.1: First malloc() Call

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     HEAP ALLOCATION FLOW                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   YOUR CODE:  char *buf = malloc(100);                                  │
│                     │                                                   │
│                     ▼                                                   │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │ malloc() in libc:                                               │   │
│   │                                                                 │   │
│   │   1. Check free lists (bins) for suitable chunk                 │   │
│   │      └─ No free chunks first time                               │   │
│   │                                                                 │   │
│   │   2. Extend heap by calling sbrk() or mmap()                    │   │
│   │      └─ Kernel allocates more pages                             │   │
│   │                                                                 │   │
│   │   3. Carve out a chunk from the heap                            │   │
│   │      └─ Add metadata (size, flags)                              │   │
│   │                                                                 │   │
│   │   4. Return pointer to user data area                           │   │
│   │                                                                 │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     HEAP MEMORY STRUCTURE                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   BEFORE malloc(100):                                                   │
│                                                                         │
│   0x555555559000  ┌────────────────────────────────────┐                │
│                   │  (nothing - heap doesn't exist)    │                │
│                   └────────────────────────────────────┘                │
│                                                                         │
│   ─────────────────────────────────────────────────────────────────     │
│                                                                         │
│   AFTER malloc(100):                                                    │
│                                                                         │
│   0x555555559000  ┌────────────────────────────────────┐                │
│                   │ Chunk Header (16 bytes)            │                │
│                   │  ├─ prev_size: 0                   │                │
│                   │  └─ size: 0x71 (112 + flags)       │                │
│   0x555555559010  ├────────────────────────────────────┤ ← malloc       │
│                   │                                    │   returns      │
│                   │ User Data (100 bytes requested)    │   THIS         │
│                   │                                    │   address      │
│                   │                                    │                │
│   0x555555559080  ├────────────────────────────────────┤                │
│                   │ Top Chunk (wilderness)             │                │
│                   │  └─ Remaining heap space           │                │
│                   └────────────────────────────────────┘                │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Step 5.2: Multiple Allocations

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     HEAP AFTER MULTIPLE malloc()                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   Code:                                                                 │
│     char *a = malloc(32);                                               │
│     char *b = malloc(64);                                               │
│     char *c = malloc(128);                                              │
│                                                                         │
│   Heap Layout:                                                          │
│                                                                         │
│   0x555555559000  ┌────────────────────────────────────┐                │
│                   │ Chunk A Header                     │                │
│                   │  size: 0x31 (48 bytes total)       │                │
│   0x555555559010  ├────────────────────────────────────┤ ← a            │
│                   │ Chunk A Data (32 bytes)            │                │
│   0x555555559030  ├────────────────────────────────────┤                │
│                   │ Chunk B Header                     │                │
│                   │  size: 0x51 (80 bytes total)       │                │
│   0x555555559040  ├────────────────────────────────────┤ ← b            │
│                   │ Chunk B Data (64 bytes)            │                │
│   0x555555559080  ├────────────────────────────────────┤                │
│                   │ Chunk C Header                     │                │
│                   │  size: 0x91 (144 bytes total)      │                │
│   0x555555559090  ├────────────────────────────────────┤ ← c            │
│                   │ Chunk C Data (128 bytes)           │                │
│   0x555555559110  ├────────────────────────────────────┤                │
│                   │ Top Chunk                          │                │
│                   └────────────────────────────────────┘                │
│                                                                         │
│   HEAP GROWS UPWARD →                                                   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Step 5.3: Free and Reallocation

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     HEAP AFTER free(b)                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   Code:                                                                 │
│     free(b);  // Free the middle chunk                                  │
│                                                                         │
│   Heap Layout:                                                          │
│                                                                         │
│   0x555555559000  ┌────────────────────────────────────┐                │
│                   │ Chunk A (IN USE)                   │                │
│   0x555555559010  ├────────────────────────────────────┤                │
│                   │ Chunk A Data                       │                │
│   0x555555559030  ├────────────────────────────────────┤                │
│                   │ Chunk B (FREE!)                    │                │
│                   │  ┌──────────────────────────────┐  │                │
│                   │  │ fd: next free chunk          │  │                │
│                   │  │ bk: prev free chunk          │  │                │
│                   │  └──────────────────────────────┘  │                │
│   0x555555559080  ├────────────────────────────────────┤                │
│                   │ Chunk C (IN USE)                   │                │
│   0x555555559090  ├────────────────────────────────────┤                │
│                   │ Chunk C Data                       │                │
│                   └────────────────────────────────────┘                │
│                                                                         │
│   FREE CHUNK IS LINKED INTO A BIN:                                      │
│                                                                         │
│   ┌─────────┐     ┌─────────┐                                           │
│   │ tcache  │────▶│ Chunk B │                                           │
│   │ bin[3]  │     │ (free)  │                                           │
│   └─────────┘     └─────────┘                                           │
│                                                                         │
│   Next malloc(64) will return Chunk B's address!                        │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Phase 6: Function Call (Stack Frame Creation)

### Step 6.1: Before Call

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     CALLING A FUNCTION                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   Code:  result = calculate(10, 5, 3);                                  │
│                                                                         │
│   ═══════════════════════════════════════════════════════════════════   │
│   STEP 1: Set up arguments (in registers)                               │
│   ═══════════════════════════════════════════════════════════════════   │
│                                                                         │
│   mov edi, 10      ; First arg  → RDI                                   │
│   mov esi, 5       ; Second arg → RSI                                   │
│   mov edx, 3       ; Third arg  → RDX                                   │
│                                                                         │
│   Registers:                                                            │
│   ┌─────────────────────────────────────────────┐                       │
│   │ RDI = 10  │ RSI = 5  │ RDX = 3              │                       │
│   └─────────────────────────────────────────────┘                       │
│                                                                         │
│   ═══════════════════════════════════════════════════════════════════   │
│   STEP 2: CALL instruction                                              │
│   ═══════════════════════════════════════════════════════════════════   │
│                                                                         │
│   call calculate                                                        │
│     │                                                                   │
│     ├─ Push return address onto stack                                   │
│     └─ Jump to calculate                                                │
│                                                                         │
│   Stack BEFORE call:              Stack AFTER call:                     │
│   ┌────────────────────┐          ┌────────────────────┐                │
│   │ main's locals      │          │ main's locals      │                │
│   ├────────────────────┤          ├────────────────────┤                │
│   │ ...                │          │ ...                │                │
│   └────────────────────┘ ← RSP    ├────────────────────┤                │
│                                   │ RETURN ADDRESS     │ ← RSP          │
│                                   │ (addr after call)  │                │
│                                   └────────────────────┘                │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Step 6.2: Inside calculate()

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     FUNCTION PROLOGUE                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   calculate:                                                            │
│       push rbp           ; Save caller's frame pointer                  │
│       mov rbp, rsp       ; Set up our frame pointer                     │
│       sub rsp, 32        ; Allocate space for locals                    │
│                                                                         │
│   Stack transformation:                                                 │
│                                                                         │
│   After CALL:             After PUSH RBP:           After SUB RSP:      │
│   ┌──────────────┐        ┌──────────────┐         ┌──────────────┐     │
│   │ main's frame │        │ main's frame │         │ main's frame │     │
│   ├──────────────┤        ├──────────────┤         ├──────────────┤     │
│   │ return addr  │ ← RSP  │ return addr  │         │ return addr  │     │
│   └──────────────┘        ├──────────────┤         ├──────────────┤     │
│                           │ saved RBP    │ ← RSP   │ saved RBP    │ ← RBP
│                           └──────────────┘   RBP   ├──────────────┤     │
│                                                    │ local: sum   │     │
│                                                    │ local: diff  │     │
│                                                    │ local: prod  │     │
│                                                    │ (padding)    │ ← RSP
│                                                    └──────────────┘     │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Step 6.3: Complete Stack Frame Visualization

```
┌─────────────────────────────────────────────────────────────────────────┐
│            COMPLETE STACK DURING calculate() EXECUTION                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   HIGH ADDRESSES                                                        │
│   ─────────────────────────────────────────────────────────────────     │
│                                                                         │
│   ┌────────────────────────────────────────────────────────────────┐    │
│   │                    main()'s STACK FRAME                        │    │
│   │  ┌─────────────────────────────────────────────────────────┐   │    │
│   │  │ local variables of main                                 │   │    │
│   │  │ (choice, input_buffer, etc.)                            │   │    │
│   │  └─────────────────────────────────────────────────────────┘   │    │
│   ├────────────────────────────────────────────────────────────────┤    │
│   │  RETURN ADDRESS (where to go after calculate returns)         │    │
│   │  → Points back into main() code                               │    │
│   ├────────────────────────────────────────────────────────────────┤    │
│   │  SAVED RBP (main's frame pointer)                        ← RBP │    │
│   │  → Points to main's saved RBP                                 │    │
│   ├────────────────────────────────────────────────────────────────┤    │
│   │                    calculate()'s STACK FRAME                   │    │
│   │  ┌─────────────────────────────────────────────────────────┐   │    │
│   │  │ int sum       [RBP - 4]                                 │   │    │
│   │  │ int diff      [RBP - 8]                                 │   │    │
│   │  │ int product   [RBP - 12]                                │   │    │
│   │  │ (alignment padding)                                     │   │    │
│   │  └─────────────────────────────────────────────────────────┘   │    │
│   ├────────────────────────────────────────────────────────────────┤    │
│   │  (If calculate calls add(), return addr would go here)   ← RSP │    │
│   └────────────────────────────────────────────────────────────────┘    │
│                                                                         │
│   LOW ADDRESSES                                                         │
│   ─────────────────────────────────────────────────────────────────     │
│                                                                         │
│                                                                         │
│   ACCESSING LOCALS:                                                     │
│   ─────────────────                                                     │
│   Arguments:  RDI=10 (x), RSI=5 (y), RDX=3 (z) - passed in registers    │
│   Locals:     mov [rbp-4], eax    ; Store to sum                        │
│               mov eax, [rbp-8]    ; Load from diff                      │
│                                                                         │
│                                                                         │
│   OVERFLOW VISUALIZATION:                                               │
│   ───────────────────────                                               │
│   If a buffer overflows, it writes UPWARD:                              │
│                                                                         │
│   ┌─────────────────┐                                                   │
│   │ RETURN ADDRESS  │ ← OVERWRITTEN! (attacker controls this)          │
│   ├─────────────────┤                                                   │
│   │ SAVED RBP       │ ← Also overwritten                               │
│   ├─────────────────┤                                                   │
│   │ local_var       │ ← Also overwritten                               │
│   ├─────────────────┤                                                   │
│   │ buffer[64]      │ ← Overflow starts here, goes UP                  │
│   │ AAAAAAAAAAAAA.. │                                                   │
│   └─────────────────┘                                                   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Phase 7: Function Return

### Step 7.1: Return Sequence

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     FUNCTION EPILOGUE & RETURN                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   End of calculate():                                                   │
│                                                                         │
│   mov eax, [rbp-12]   ; Put return value in EAX                         │
│   leave               ; mov rsp, rbp; pop rbp                           │
│   ret                 ; Pop return address, jump there                  │
│                                                                         │
│   ═══════════════════════════════════════════════════════════════════   │
│                                                                         │
│   STEP 1: MOV EAX, [rbp-12]                                             │
│   ───────────────────────────                                           │
│   Loads product (return value) into EAX                                 │
│                                                                         │
│   EAX = result value                                                    │
│                                                                         │
│   ═══════════════════════════════════════════════════════════════════   │
│                                                                         │
│   STEP 2: LEAVE                                                         │
│   ──────────────                                                        │
│   Equivalent to: mov rsp, rbp; pop rbp                                  │
│                                                                         │
│   Before LEAVE:              After LEAVE:                               │
│   ┌──────────────┐           ┌──────────────┐                           │
│   │ main's frame │           │ main's frame │                           │
│   ├──────────────┤           ├──────────────┤                           │
│   │ return addr  │           │ return addr  │ ← RSP                     │
│   ├──────────────┤           └──────────────┘                           │
│   │ saved RBP    │ ← RBP                                                │
│   ├──────────────┤           RBP now points to main's frame             │
│   │ locals       │                                                      │
│   └──────────────┘ ← RSP                                                │
│                                                                         │
│   ═══════════════════════════════════════════════════════════════════   │
│                                                                         │
│   STEP 3: RET                                                           │
│   ───────────                                                           │
│   Pops return address into RIP, execution continues in main()           │
│                                                                         │
│   Before RET:                After RET:                                 │
│   ┌──────────────┐           ┌──────────────┐                           │
│   │ main's frame │           │ main's frame │                           │
│   ├──────────────┤           └──────────────┘ ← RSP                     │
│   │ return addr  │ ← RSP                                                │
│   └──────────────┘           RIP = return address (back in main)        │
│                                                                         │
│   RIP now points to instruction after "call calculate" in main()        │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Complete Flow Summary

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        COMPLETE EXECUTION FLOW                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ./program                                                                 │
│       │                                                                     │
│       ▼                                                                     │
│   ┌─────────┐    ┌─────────────┐    ┌───────────────────────────────────┐   │
│   │ KERNEL  │───▶│ Load ELF    │───▶│ Map LOAD segments to memory       │   │
│   │ execve  │    │ headers     │    │ (TEXT, DATA, BSS, etc.)           │   │
│   └─────────┘    └─────────────┘    └───────────────────────────────────┘   │
│                                                    │                        │
│                                                    ▼                        │
│                        ┌───────────────────────────────────────────────┐    │
│                        │ DYNAMIC LINKER (ld-linux.so)                  │    │
│                        │  - Load libc.so, other libraries              │    │
│                        │  - Set up PLT/GOT for lazy binding            │    │
│                        │  - Jump to _start                             │    │
│                        └───────────────────────────────────────────────┘    │
│                                                    │                        │
│                                                    ▼                        │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                          YOUR PROGRAM                               │   │
│   │                                                                     │   │
│   │  _start ──▶ __libc_start_main ──▶ main()                            │   │
│   │                                      │                              │   │
│   │                                      ▼                              │   │
│   │                              ┌─────────────┐                        │   │
│   │                              │ Your code   │                        │   │
│   │                              │ runs here   │                        │   │
│   │                              └─────────────┘                        │   │
│   │                                      │                              │   │
│   │              ┌───────────────────────┼───────────────────────┐      │   │
│   │              ▼                       ▼                       ▼      │   │
│   │   ┌──────────────────┐    ┌──────────────────┐    ┌──────────────┐  │   │
│   │   │ Call library     │    │ Allocate heap    │    │ Use stack    │  │   │
│   │   │ function         │    │ memory           │    │ for locals   │  │   │
│   │   │ (printf, etc.)   │    │ (malloc)         │    │              │  │   │
│   │   └────────┬─────────┘    └────────┬─────────┘    └──────────────┘  │   │
│   │            │                       │                                │   │
│   │            ▼                       ▼                                │   │
│   │   ┌──────────────────┐    ┌──────────────────┐                      │   │
│   │   │ PLT ──▶ GOT ──▶  │    │ sbrk/mmap ──▶    │                      │   │
│   │   │ libc function    │    │ Heap grows       │                      │   │
│   │   └──────────────────┘    └──────────────────┘                      │   │
│   │                                                                     │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                      │                                      │
│                                      ▼                                      │
│                              ┌─────────────┐                                │
│                              │ exit()      │                                │
│                              │ Return to   │                                │
│                              │ kernel      │                                │
│                              └─────────────┘                                │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Quick Reference: Which Segment Does What?

| Segment | Address Range | Permissions | Contains | When Used |
|---------|---------------|-------------|----------|-----------|
| **TEXT** | 0x400000 | R-X | Code | Every instruction executed |
| **PLT** | 0x400xxx | R-X | Jump stubs | Every library call |
| **GOT** | 0x404xxx | RW- | Resolved addresses | Every library call |
| **DATA** | 0x404xxx | RW- | Initialized globals | When globals accessed |
| **BSS** | 0x404xxx | RW- | Zero-init globals | When globals accessed |
| **HEAP** | 0x555xxx | RW- | malloc'd data | Dynamic allocation |
| **LIBC** | 0x7ffff7xxx | R-X/RW- | printf, malloc... | Library functions |
| **STACK** | 0x7fffffffxxx | RW- | Locals, returns | Every function call |

---

**Last Updated:** 2025-12-20
