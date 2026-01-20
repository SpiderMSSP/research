#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>

#define HIDDEN_DIR "/tmp/.system_data"
#define MAX_FILENAME 256

typedef struct {
    time_t timestamp;
    char source[32];
    char data[512];
} hidden_entry_t;

void create_hidden_directory() {
    struct stat st = {0};
    if (stat(HIDDEN_DIR, &st) == -1) {
        mkdir(HIDDEN_DIR, 0700);
    }
}

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

void obfuscate_data(char* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= 0xAA;
    }
}

int store_hidden_data(const char* source, const char* data) {
    create_hidden_directory();
    
    hidden_entry_t entry;
    entry.timestamp = time(NULL);
    strncpy(entry.source, source, sizeof(entry.source) - 1);
    entry.source[sizeof(entry.source) - 1] = '\0';
    strncpy(entry.data, data, sizeof(entry.data) - 1);
    entry.data[sizeof(entry.data) - 1] = '\0';
    
    obfuscate_data((char*)&entry, sizeof(entry));
    
    char* filename = generate_filename();
    int fd = open(filename, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd == -1) {
        return -1;
    }
    
    write(fd, &entry, sizeof(entry));
    close(fd);
    
    return 0;
}

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
    
    printf("Timestamp: %s", ctime(&entry.timestamp));
    printf("Source: %s\n", entry.source);
    printf("Data: %s\n", entry.data);
    
    return 0;
}

void list_hidden_files() {
    char command[512];
    snprintf(command, sizeof(command), "find %s -name '*.dat' 2>/dev/null", HIDDEN_DIR);
    system(command);
}

void hide_credential(const char* username, const char* password, const char* target) {
    char data[512];
    snprintf(data, sizeof(data), "USER:%s|PASS:%s|TARGET:%s", 
             username ? username : "unknown",
             password ? password : "unknown", 
             target ? target : "unknown");
    
    store_hidden_data("CREDENTIAL", data);
}

void hide_system_info() {
    char data[512];
    snprintf(data, sizeof(data), "PID:%d|USER:%s|CWD:%s", 
             getpid(), getlogin(), getcwd(NULL, 0));
    
    store_hidden_data("SYSINFO", data);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <command> [args]\n", argv[0]);
        printf("Commands:\n");
        printf("  store <source> <data>    - Store hidden data\n");
        printf("  retrieve <filename>      - Retrieve hidden data\n");
        printf("  list                     - List hidden files\n");
        printf("  cred <user> <pass> <target> - Hide credential\n");
        printf("  sysinfo                  - Hide system info\n");
        return 1;
    }
    
    if (strcmp(argv[1], "store") == 0 && argc >= 4) {
        if (store_hidden_data(argv[2], argv[3]) == 0) {
            printf("Data stored successfully\n");
        } else {
            printf("Failed to store data\n");
        }
    }
    else if (strcmp(argv[1], "retrieve") == 0 && argc >= 3) {
        if (retrieve_hidden_data(argv[2]) != 0) {
            printf("Failed to retrieve data\n");
        }
    }
    else if (strcmp(argv[1], "list") == 0) {
        list_hidden_files();
    }
    else if (strcmp(argv[1], "cred") == 0 && argc >= 5) {
        hide_credential(argv[2], argv[3], argv[4]);
        printf("Credential hidden\n");
    }
    else if (strcmp(argv[1], "sysinfo") == 0) {
        hide_system_info();
        printf("System info hidden\n");
    }
    else {
        printf("Invalid command or insufficient arguments\n");
        return 1;
    }
    
    return 0;
}