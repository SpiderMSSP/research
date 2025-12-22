/*
 * victim.c - Target program for LD_PRELOAD demonstration
 *
 * This innocent program makes various library calls that we'll intercept.
 * It simulates a program that:
 *   - Reads environment variables
 *   - Opens and reads files
 *   - Makes network-related calls
 *   - Outputs to console
 *
 * Compile: gcc -o victim victim.c
 * Normal:  ./victim
 * Attack:  LD_PRELOAD=./evil_preload.so ./victim
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>

void display_banner(void) {
    puts("");
    puts("╔════════════════════════════════════════════════════════╗");
    puts("║          SECURE CONFIGURATION MANAGER v1.0             ║");
    puts("╚════════════════════════════════════════════════════════╝");
    puts("");
}

void load_config(void) {
    FILE *fp;
    char buffer[256];

    printf("[CONFIG] Loading configuration...\n");

    /* Try to read a config file */
    fp = fopen("/etc/hostname", "r");
    if (fp) {
        if (fgets(buffer, sizeof(buffer), fp)) {
            buffer[strcspn(buffer, "\n")] = 0;  /* Remove newline */
            printf("[CONFIG] Hostname: %s\n", buffer);
        }
        fclose(fp);
    }
}

void check_environment(void) {
    char *user, *home, *path, *secret;

    printf("[ENV] Checking environment variables...\n");

    user = getenv("USER");
    home = getenv("HOME");
    path = getenv("PATH");
    secret = getenv("SECRET_API_KEY");  /* Sensitive! */

    if (user) printf("[ENV] USER: %s\n", user);
    if (home) printf("[ENV] HOME: %s\n", home);
    if (secret) printf("[ENV] SECRET_API_KEY: %s\n", secret);

    /* Don't print PATH - too long */
    if (path) printf("[ENV] PATH: (set, %zu chars)\n", strlen(path));
}

void get_user_info(void) {
    struct passwd *pw;
    uid_t uid;

    printf("[USER] Retrieving user information...\n");

    uid = getuid();
    pw = getpwuid(uid);

    if (pw) {
        printf("[USER] Username: %s\n", pw->pw_name);
        printf("[USER] UID: %d\n", pw->pw_uid);
        printf("[USER] Home: %s\n", pw->pw_dir);
        printf("[USER] Shell: %s\n", pw->pw_shell);
    }
}

void simulate_network(void) {
    printf("[NET] Simulating network operations...\n");
    printf("[NET] Connecting to api.example.com:443...\n");
    printf("[NET] Sending authentication token...\n");
    printf("[NET] Response: 200 OK\n");
}

void cleanup(void) {
    printf("[SYS] Cleaning up resources...\n");
    printf("[SYS] Shutdown complete.\n");
    puts("");
}

int main(int argc, char *argv[]) {
    display_banner();

    printf("[SYS] PID: %d\n", getpid());
    printf("[SYS] Starting secure configuration manager...\n\n");

    load_config();
    puts("");

    check_environment();
    puts("");

    get_user_info();
    puts("");

    simulate_network();
    puts("");

    cleanup();

    return 0;
}
