/*
 * got_hijack_demo.c - GOT/PLT Hijacking Demonstration
 *
 * This program demonstrates GOT hijacking by:
 *   1. Locating GOT entries for libc functions
 *   2. Showing the current GOT values (resolved addresses)
 *   3. Overwriting GOT entries with our malicious function
 *   4. Demonstrating the hijacked behavior
 *
 * This simulates what an attacker could do with a write-what-where primitive.
 *
 * Compile: gcc -no-pie -Wl,-z,norelro -o got_hijack_demo got_hijack_demo.c -ldl
 *
 * EDUCATIONAL PURPOSES ONLY
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <link.h>

/* Color codes for terminal output */
#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define BLUE    "\033[1;34m"
#define MAGENTA "\033[1;35m"
#define CYAN    "\033[1;36m"
#define RESET   "\033[0m"

/* ═══════════════════════════════════════════════════════════════════════════
 * MALICIOUS REPLACEMENT FUNCTIONS
 * ═══════════════════════════════════════════════════════════════════════════
 * These functions will replace the original libc functions after GOT hijacking
 */

/* Our evil puts replacement */
int evil_puts(const char *s) {
    /* Get the REAL puts to actually output something */
    static int (*real_puts)(const char *) = NULL;
    if (!real_puts) {
        real_puts = dlsym(RTLD_NEXT, "puts");
    }

    real_puts(RED "  [HIJACKED] " RESET "puts() was called with:");
    real_puts(YELLOW "  → " RESET);

    /* Show original message but mark it as captured */
    char hijacked_msg[512];
    snprintf(hijacked_msg, sizeof(hijacked_msg),
             MAGENTA "    \"%s\"" RESET, s);
    real_puts(hijacked_msg);

    return 0;
}

/* Our evil strlen replacement - could be used to leak data */
size_t evil_strlen(const char *s) {
    static size_t (*real_strlen)(const char *) = NULL;
    if (!real_strlen) {
        real_strlen = dlsym(RTLD_NEXT, "strlen");
    }

    size_t len = real_strlen(s);

    fprintf(stderr, RED "  [HIJACKED] " RESET "strlen(\"%.*s%s\") = %zu\n",
            (int)(len > 20 ? 20 : len), s,
            len > 20 ? "..." : "",
            len);

    return len;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * GOT ENTRY LOCATOR
 * ═══════════════════════════════════════════════════════════════════════════
 * Finds the GOT entry for a given function by scanning the PLT
 */

/* Structure to hold GOT information */
typedef struct {
    void **got_entry;       /* Pointer to the GOT slot */
    void *current_value;    /* Current value in GOT (resolved address) */
    const char *name;       /* Function name */
} got_info_t;

/*
 * Find GOT entry by comparing resolved addresses
 * This works by knowing that the GOT entry will contain the resolved
 * address of the function after the first call.
 */
void **find_got_entry(const char *func_name, void *expected_addr) {
    /*
     * The GOT is typically located near the program's data segment.
     * We can find it by:
     * 1. Reading /proc/self/maps to find the program's memory regions
     * 2. Scanning for pointers that match known libc addresses
     *
     * For this demo, we'll use a simpler approach: scan a known range
     * based on the program's load address.
     */

    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return NULL;

    char line[256];
    uintptr_t start = 0, end = 0;

    /* Find the program's writable data segment (where GOT lives) */
    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, "got_hijack_demo") && strstr(line, "rw-p")) {
            sscanf(line, "%lx-%lx", &start, &end);
            break;
        }
    }
    fclose(maps);

    if (!start) return NULL;

    /* Scan the region for our target address */
    for (uintptr_t addr = start; addr < end; addr += sizeof(void *)) {
        void **ptr = (void **)addr;
        if (*ptr == expected_addr) {
            return ptr;
        }
    }

    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * MEMORY PROTECTION MANIPULATION
 * ═══════════════════════════════════════════════════════════════════════════
 */

int make_writable(void *addr) {
    uintptr_t page = (uintptr_t)addr & ~0xFFF;  /* Align to page boundary */
    if (mprotect((void *)page, 0x1000, PROT_READ | PROT_WRITE) != 0) {
        perror("mprotect");
        return -1;
    }
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * GOT VISUALIZATION
 * ═══════════════════════════════════════════════════════════════════════════
 */

void print_got_entry(const char *name, void **got_entry, void *original, void *current) {
    printf("  ├─ %-12s │ GOT @ " CYAN "%p" RESET, name, (void *)got_entry);

    if (original == current) {
        printf(" │ Value: " GREEN "%p" RESET " (original)\n", current);
    } else {
        printf(" │ Value: " RED "%p" RESET " (HIJACKED!)\n", current);
        printf("  │              │ Was:   " GREEN "%p" RESET " (original)\n", original);
    }
}

void display_got_diagram(void **puts_got, void *orig_puts,
                         void **strlen_got, void *orig_strlen) {
    printf("\n");
    printf(YELLOW "  ╔═══════════════════════════════════════════════════════════════════╗\n" RESET);
    printf(YELLOW "  ║" RESET "                     GOT/PLT MEMORY LAYOUT                        " YELLOW "║\n" RESET);
    printf(YELLOW "  ╚═══════════════════════════════════════════════════════════════════╝\n" RESET);
    printf("\n");
    printf("     Code Section (.text)           GOT Section (.got.plt)\n");
    printf("    ┌───────────────────┐          ┌────────────────────────┐\n");
    printf("    │                   │          │                        │\n");
    printf("    │  call puts@plt ───┼──────────┼──→ ");

    if (puts_got) {
        if (*puts_got == orig_puts) {
            printf(GREEN "[puts addr]" RESET);
        } else {
            printf(RED "[EVIL addr]" RESET);
        }
        printf(" ────────┤\n");
    } else {
        printf("[???]           │\n");
    }

    printf("    │                   │          │          │             │\n");
    printf("    │  call strlen@plt ─┼──────────┼──→ ");

    if (strlen_got) {
        if (*strlen_got == orig_strlen) {
            printf(GREEN "[strlen addr]" RESET);
        } else {
            printf(RED "[EVIL addr]" RESET);
        }
        printf(" ──────┤\n");
    } else {
        printf("[???]           │\n");
    }

    printf("    │                   │          │          │             │\n");
    printf("    │  ...              │          │          ▼             │\n");
    printf("    │                   │          │    ┌─────────────┐     │\n");
    printf("    └───────────────────┘          │    │   libc.so   │     │\n");
    printf("                                   │    │             │     │\n");
    printf("                                   │    │  puts()     │     │\n");
    printf("                                   │    │  strlen()   │     │\n");
    printf("                                   │    │  ...        │     │\n");
    printf("                                   │    └─────────────┘     │\n");
    printf("                                   └────────────────────────┘\n");
    printf("\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * DEMONSTRATION FUNCTIONS
 * ═══════════════════════════════════════════════════════════════════════════
 */

void demo_normal_behavior(void) {
    printf("\n");
    printf(BLUE "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf(BLUE "  PHASE 1: Normal Behavior (Before Hijacking)\n" RESET);
    printf(BLUE "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf("\n");

    printf("[*] Calling puts() normally:\n");
    puts("    Hello from the normal puts() function!");

    printf("\n[*] Calling strlen() normally:\n");
    const char *test = "This is a test string";
    size_t len = strlen(test);
    printf("    strlen(\"%s\") = %zu\n", test, len);
}

void demo_hijacked_behavior(void) {
    printf("\n");
    printf(RED "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf(RED "  PHASE 3: Hijacked Behavior (After GOT Overwrite)\n" RESET);
    printf(RED "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf("\n");

    printf("[*] Calling puts() - NOW HIJACKED:\n");
    puts("    Hello from the normal puts() function!");

    printf("\n[*] Calling strlen() - NOW HIJACKED:\n");
    const char *test = "This is a test string";
    size_t len = strlen(test);
    printf("    Returned length: %zu\n", len);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * MAIN
 * ═══════════════════════════════════════════════════════════════════════════
 */

int main(void) {
    printf("\n");
    printf(RED "╔════════════════════════════════════════════════════════════════════╗\n" RESET);
    printf(RED "║" YELLOW "              GOT/PLT HIJACKING DEMONSTRATION                       " RED "║\n" RESET);
    printf(RED "║" RESET "                                                                    " RED "║\n" RESET);
    printf(RED "║" RESET "  This demonstrates how overwriting GOT entries redirects calls     " RED "║\n" RESET);
    printf(RED "║" RESET "  from legitimate library functions to attacker-controlled code     " RED "║\n" RESET);
    printf(RED "╚════════════════════════════════════════════════════════════════════╝\n" RESET);
    printf("\n");

    /* Force resolution of PLT entries by calling the functions once */
    puts("");  /* Resolve puts */
    strlen(""); /* Resolve strlen */

    /* Get the real addresses from libc */
    void *real_puts = dlsym(RTLD_NEXT, "puts");
    void *real_strlen = dlsym(RTLD_NEXT, "strlen");

    printf("[*] Resolved libc addresses:\n");
    printf("    puts   @ " GREEN "%p" RESET "\n", real_puts);
    printf("    strlen @ " GREEN "%p" RESET "\n", real_strlen);

    /* Find the GOT entries */
    void **puts_got = find_got_entry("puts", real_puts);
    void **strlen_got = find_got_entry("strlen", real_strlen);

    printf("\n[*] Located GOT entries:\n");
    if (puts_got) {
        printf("    puts   GOT @ " CYAN "%p" RESET " → " GREEN "%p" RESET "\n",
               (void *)puts_got, *puts_got);
    } else {
        printf("    puts   GOT @ " RED "NOT FOUND" RESET "\n");
    }
    if (strlen_got) {
        printf("    strlen GOT @ " CYAN "%p" RESET " → " GREEN "%p" RESET "\n",
               (void *)strlen_got, *strlen_got);
    } else {
        printf("    strlen GOT @ " RED "NOT FOUND" RESET "\n");
    }

    /* Store original values */
    void *orig_puts = puts_got ? *puts_got : NULL;
    void *orig_strlen = strlen_got ? *strlen_got : NULL;

    /* Display the memory layout */
    display_got_diagram(puts_got, orig_puts, strlen_got, orig_strlen);

    /* Phase 1: Normal behavior */
    demo_normal_behavior();

    /* Phase 2: Perform the hijack */
    printf("\n");
    printf(YELLOW "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf(YELLOW "  PHASE 2: Hijacking GOT Entries\n" RESET);
    printf(YELLOW "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf("\n");

    if (puts_got) {
        printf("[*] Overwriting puts GOT entry...\n");
        printf("    Before: " GREEN "%p" RESET " (libc puts)\n", *puts_got);

        /* Make GOT writable if needed (for partial RELRO) */
        make_writable(puts_got);

        /* THE HIJACK: Overwrite GOT entry */
        *puts_got = (void *)evil_puts;

        printf("    After:  " RED "%p" RESET " (evil_puts)\n", *puts_got);
        printf("    " GREEN "✓" RESET " puts() hijacked!\n");
    }

    if (strlen_got) {
        printf("\n[*] Overwriting strlen GOT entry...\n");
        printf("    Before: " GREEN "%p" RESET " (libc strlen)\n", *strlen_got);

        make_writable(strlen_got);
        *strlen_got = (void *)evil_strlen;

        printf("    After:  " RED "%p" RESET " (evil_strlen)\n", *strlen_got);
        printf("    " GREEN "✓" RESET " strlen() hijacked!\n");
    }

    /* Display updated memory layout */
    display_got_diagram(puts_got, orig_puts, strlen_got, orig_strlen);

    /* Phase 3: Demonstrate hijacked behavior */
    demo_hijacked_behavior();

    /* Restore original GOT entries */
    printf("\n");
    printf(GREEN "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf(GREEN "  PHASE 4: Restoring Original GOT Entries\n" RESET);
    printf(GREEN "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf("\n");

    if (puts_got && orig_puts) {
        *puts_got = orig_puts;
        printf("[*] Restored puts GOT → " GREEN "%p" RESET "\n", *puts_got);
    }
    if (strlen_got && orig_strlen) {
        *strlen_got = orig_strlen;
        printf("[*] Restored strlen GOT → " GREEN "%p" RESET "\n", *strlen_got);
    }

    printf("\n[*] Calling puts() after restoration:\n");
    puts("    Back to normal puts() behavior!");

    printf("\n" GREEN "[✓] Demonstration complete.\n" RESET);

    return 0;
}
