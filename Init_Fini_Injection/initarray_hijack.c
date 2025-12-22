/*
 * initarray_hijack.c - Init Array Hijacking Demonstration
 *
 * This program demonstrates how .init_array entries can be:
 *   1. Located via the dynamic section
 *   2. Read to see what constructors will run
 *   3. Overwritten to hijack execution
 *
 * In a real attack, the attacker would:
 *   - Have arbitrary write access (buffer overflow, format string, etc.)
 *   - Write to init_array to gain code execution on next run
 *
 * This demo simulates that by modifying its own .fini_array
 * (since .init_array has already run by the time main() starts)
 *
 * Compile: gcc -no-pie -Wl,-z,norelro -o initarray_hijack initarray_hijack.c
 *          (Need writable sections for demo)
 *
 * EDUCATIONAL PURPOSES ONLY
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <link.h>
#include <elf.h>

/* Color codes */
#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define BLUE    "\033[1;34m"
#define MAGENTA "\033[1;35m"
#define CYAN    "\033[1;36m"
#define RESET   "\033[0m"

/* ═══════════════════════════════════════════════════════════════════════════
 * LEGITIMATE FUNCTIONS
 * ═══════════════════════════════════════════════════════════════════════════ */

__attribute__((constructor))
void legitimate_constructor(void) {
    fprintf(stderr, GREEN "[LEGIT CONSTRUCTOR] " RESET "Normal initialization code\n");
}

__attribute__((destructor))
void legitimate_destructor(void) {
    fprintf(stderr, GREEN "[LEGIT DESTRUCTOR]  " RESET "Normal cleanup code\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * MALICIOUS FUNCTION (what attacker wants to run)
 * ═══════════════════════════════════════════════════════════════════════════ */

void evil_destructor(void) {
    fprintf(stderr, "\n");
    fprintf(stderr, RED "╔════════════════════════════════════════════════════════════════╗\n" RESET);
    fprintf(stderr, RED "║" YELLOW "           ★ HIJACKED DESTRUCTOR EXECUTED! ★                   " RED "║\n" RESET);
    fprintf(stderr, RED "║" RESET "                                                                " RED "║\n" RESET);
    fprintf(stderr, RED "║" RESET "  This function was NOT in the original .fini_array!            " RED "║\n" RESET);
    fprintf(stderr, RED "║" RESET "  It was injected by overwriting a fini_array entry.            " RED "║\n" RESET);
    fprintf(stderr, RED "║" RESET "                                                                " RED "║\n" RESET);
    fprintf(stderr, RED "║" RESET "  In a real attack, this would be arbitrary code execution!     " RED "║\n" RESET);
    fprintf(stderr, RED "╚════════════════════════════════════════════════════════════════╝\n" RESET);
    fprintf(stderr, "\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * FIND INIT/FINI ARRAYS
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef void (*init_func_t)(void);

typedef struct {
    init_func_t *init_array;
    size_t init_arraysz;
    init_func_t *fini_array;
    size_t fini_arraysz;
} arrays_info_t;

int find_arrays(arrays_info_t *info) {
    extern ElfW(Dyn) _DYNAMIC[];

    memset(info, 0, sizeof(*info));

    for (ElfW(Dyn) *dyn = _DYNAMIC; dyn->d_tag != DT_NULL; dyn++) {
        switch (dyn->d_tag) {
            case DT_INIT_ARRAY:
                info->init_array = (init_func_t *)dyn->d_un.d_ptr;
                break;
            case DT_INIT_ARRAYSZ:
                info->init_arraysz = dyn->d_un.d_val;
                break;
            case DT_FINI_ARRAY:
                info->fini_array = (init_func_t *)dyn->d_un.d_ptr;
                break;
            case DT_FINI_ARRAYSZ:
                info->fini_arraysz = dyn->d_un.d_val;
                break;
        }
    }

    return (info->fini_array != NULL) ? 0 : -1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * MAKE MEMORY WRITABLE
 * ═══════════════════════════════════════════════════════════════════════════ */

int make_writable(void *addr, size_t size) {
    uintptr_t page_start = (uintptr_t)addr & ~0xFFF;
    size_t page_size = ((uintptr_t)addr + size - page_start + 0xFFF) & ~0xFFF;

    if (mprotect((void *)page_start, page_size, PROT_READ | PROT_WRITE) != 0) {
        perror("mprotect");
        return -1;
    }
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * DISPLAY ARRAY CONTENTS
 * ═══════════════════════════════════════════════════════════════════════════ */

void display_array(const char *name, init_func_t *array, size_t size) {
    size_t count = size / sizeof(init_func_t);

    printf("  %s @ " CYAN "0x%016lx" RESET " (%zu entries):\n", name, (uintptr_t)array, count);

    for (size_t i = 0; i < count; i++) {
        printf("    [%zu] " GREEN "0x%016lx" RESET, i, (uintptr_t)array[i]);

        /* Check if it's our known functions */
        if (array[i] == legitimate_constructor) {
            printf(" → legitimate_constructor");
        } else if (array[i] == legitimate_destructor) {
            printf(" → legitimate_destructor");
        } else if (array[i] == evil_destructor) {
            printf(" → " RED "evil_destructor (INJECTED!)" RESET);
        }
        printf("\n");
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * MAIN
 * ═══════════════════════════════════════════════════════════════════════════ */

int main(void) {
    printf("\n");
    printf(RED "╔════════════════════════════════════════════════════════════════════╗\n" RESET);
    printf(RED "║" YELLOW "              .INIT_ARRAY / .FINI_ARRAY HIJACKING                   " RED "║\n" RESET);
    printf(RED "║" RESET "                                                                    " RED "║\n" RESET);
    printf(RED "║" RESET "  Demonstrating how function pointer arrays can be overwritten      " RED "║\n" RESET);
    printf(RED "║" RESET "  to gain code execution before/after main()                        " RED "║\n" RESET);
    printf(RED "╚════════════════════════════════════════════════════════════════════╝\n" RESET);
    printf("\n");

    /* Find the arrays */
    arrays_info_t info;
    if (find_arrays(&info) < 0) {
        printf(RED "[!] Could not find fini_array\n" RESET);
        return 1;
    }

    printf(CYAN "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf(CYAN "  STEP 1: Locate the arrays\n" RESET);
    printf(CYAN "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf("\n");

    if (info.init_array) {
        display_array(".init_array", info.init_array, info.init_arraysz);
        printf("\n");
    }

    display_array(".fini_array", info.fini_array, info.fini_arraysz);

    printf("\n");
    printf(YELLOW "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf(YELLOW "  STEP 2: Make fini_array writable (bypass RELRO if needed)\n" RESET);
    printf(YELLOW "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf("\n");

    if (make_writable(info.fini_array, info.fini_arraysz) == 0) {
        printf("  " GREEN "✓" RESET " Successfully made fini_array writable\n");
    } else {
        printf("  " RED "✗" RESET " Failed to make fini_array writable\n");
        printf("  (Try compiling with -Wl,-z,norelro)\n");
        return 1;
    }

    printf("\n");
    printf(RED "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf(RED "  STEP 3: Hijack fini_array[0]\n" RESET);
    printf(RED "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf("\n");

    /* Store original for display */
    init_func_t original = info.fini_array[0];
    printf("  Original fini_array[0]: " GREEN "0x%016lx" RESET "\n", (uintptr_t)original);
    printf("  Evil function address:  " RED "0x%016lx" RESET "\n", (uintptr_t)evil_destructor);

    /* THE HIJACK: Overwrite fini_array entry */
    info.fini_array[0] = evil_destructor;

    printf("\n");
    printf("  " RED "★ fini_array[0] OVERWRITTEN!" RESET "\n");
    printf("  New fini_array[0]:      " RED "0x%016lx" RESET "\n", (uintptr_t)info.fini_array[0]);

    printf("\n");
    display_array(".fini_array (AFTER HIJACK)", info.fini_array, info.fini_arraysz);

    printf("\n");
    printf(GREEN "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf(GREEN "  STEP 4: Return from main() - watch what happens!\n" RESET);
    printf(GREEN "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf("\n");

    printf("[MAIN] About to return from main()...\n");
    printf("[MAIN] The hijacked fini_array entry will execute!\n\n");

    /* When we return, the hijacked destructor will run! */
    return 0;
}
