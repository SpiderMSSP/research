/*
 * initfini_explorer.c - .init_array/.fini_array Explorer
 *
 * This tool demonstrates:
 *   1. How to find .init_array and .fini_array sections
 *   2. The execution order of constructors/destructors
 *   3. How DT_INIT_ARRAY/DT_FINI_ARRAY work
 *   4. Potential hijacking targets
 *
 * The init/fini arrays contain function pointers that are called:
 *   - .init_array: BEFORE main() starts
 *   - .fini_array: AFTER main() returns
 *
 * Compile: gcc -o initfini_explorer initfini_explorer.c -ldl
 *
 * EDUCATIONAL PURPOSES ONLY
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <link.h>
#include <elf.h>
#include <dlfcn.h>

/* Color codes */
#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define BLUE    "\033[1;34m"
#define MAGENTA "\033[1;35m"
#define CYAN    "\033[1;36m"
#define RESET   "\033[0m"

/* ═══════════════════════════════════════════════════════════════════════════
 * STRUCTURE TO HOLD INIT/FINI INFO
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    uintptr_t init;              /* DT_INIT function */
    uintptr_t fini;              /* DT_FINI function */
    uintptr_t *init_array;       /* DT_INIT_ARRAY pointer */
    size_t init_arraysz;         /* DT_INIT_ARRAYSZ */
    uintptr_t *fini_array;       /* DT_FINI_ARRAY pointer */
    size_t fini_arraysz;         /* DT_FINI_ARRAYSZ */
    uintptr_t *preinit_array;    /* DT_PREINIT_ARRAY pointer */
    size_t preinit_arraysz;      /* DT_PREINIT_ARRAYSZ */
    uintptr_t base;              /* Base address */
} initfini_info_t;

/* ═══════════════════════════════════════════════════════════════════════════
 * PARSE DYNAMIC SECTION FOR INIT/FINI
 * ═══════════════════════════════════════════════════════════════════════════ */

int parse_initfini(struct link_map *lm, initfini_info_t *info) {
    if (!lm || !lm->l_ld) return -1;

    memset(info, 0, sizeof(*info));
    info->base = lm->l_addr;

    for (ElfW(Dyn) *dyn = lm->l_ld; dyn->d_tag != DT_NULL; dyn++) {
        switch (dyn->d_tag) {
            case DT_INIT:
                info->init = dyn->d_un.d_ptr;
                break;
            case DT_FINI:
                info->fini = dyn->d_un.d_ptr;
                break;
            case DT_INIT_ARRAY:
                info->init_array = (uintptr_t *)dyn->d_un.d_ptr;
                break;
            case DT_INIT_ARRAYSZ:
                info->init_arraysz = dyn->d_un.d_val;
                break;
            case DT_FINI_ARRAY:
                info->fini_array = (uintptr_t *)dyn->d_un.d_ptr;
                break;
            case DT_FINI_ARRAYSZ:
                info->fini_arraysz = dyn->d_un.d_val;
                break;
            case DT_PREINIT_ARRAY:
                info->preinit_array = (uintptr_t *)dyn->d_un.d_ptr;
                break;
            case DT_PREINIT_ARRAYSZ:
                info->preinit_arraysz = dyn->d_un.d_val;
                break;
        }
    }

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * FIND R_DEBUG
 * ═══════════════════════════════════════════════════════════════════════════ */

struct r_debug *get_r_debug(void) {
    extern ElfW(Dyn) _DYNAMIC[];
    for (ElfW(Dyn) *dyn = _DYNAMIC; dyn->d_tag != DT_NULL; dyn++) {
        if (dyn->d_tag == DT_DEBUG) {
            return (struct r_debug *)dyn->d_un.d_ptr;
        }
    }
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * DISPLAY FUNCTIONS
 * ═══════════════════════════════════════════════════════════════════════════ */

void print_function_array(const char *name, uintptr_t *array, size_t size, uintptr_t base) {
    if (!array || size == 0) {
        printf("  %s: " YELLOW "Not present" RESET "\n", name);
        return;
    }

    size_t count = size / sizeof(uintptr_t);
    printf("  %s @ " CYAN "0x%016lx" RESET " (%zu entries):\n", name, (uintptr_t)array, count);

    for (size_t i = 0; i < count; i++) {
        uintptr_t func = array[i];
        if (func == 0 || func == (uintptr_t)-1) {
            printf("    [%zu] " YELLOW "0x%016lx (NULL/invalid)" RESET "\n", i, func);
        } else {
            /* Try to get symbol name */
            Dl_info info;
            if (dladdr((void *)func, &info) && info.dli_sname) {
                printf("    [%zu] " GREEN "0x%016lx" RESET " → %s\n", i, func, info.dli_sname);
            } else {
                printf("    [%zu] " GREEN "0x%016lx" RESET "\n", i, func);
            }
        }
    }
}

void analyze_object(struct link_map *lm) {
    const char *name = lm->l_name;
    if (!name || name[0] == '\0') name = "(main executable)";

    printf("\n");
    printf(CYAN "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf(CYAN "  %s\n" RESET, name);
    printf(CYAN "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf("\n");
    printf("  Base address: " GREEN "0x%016lx" RESET "\n\n", lm->l_addr);

    initfini_info_t info;
    if (parse_initfini(lm, &info) < 0) {
        printf("  " RED "Could not parse dynamic section" RESET "\n");
        return;
    }

    /* DT_PREINIT_ARRAY (only in main executable) */
    if (info.preinit_array) {
        print_function_array("DT_PREINIT_ARRAY", info.preinit_array, info.preinit_arraysz, info.base);
        printf("\n");
    }

    /* DT_INIT */
    if (info.init) {
        printf("  DT_INIT:       " MAGENTA "0x%016lx" RESET "\n", info.base + info.init);
    } else {
        printf("  DT_INIT:       " YELLOW "Not present" RESET "\n");
    }

    /* DT_INIT_ARRAY */
    print_function_array("DT_INIT_ARRAY", info.init_array, info.init_arraysz, info.base);
    printf("\n");

    /* DT_FINI */
    if (info.fini) {
        printf("  DT_FINI:       " MAGENTA "0x%016lx" RESET "\n", info.base + info.fini);
    } else {
        printf("  DT_FINI:       " YELLOW "Not present" RESET "\n");
    }

    /* DT_FINI_ARRAY */
    print_function_array("DT_FINI_ARRAY", info.fini_array, info.fini_arraysz, info.base);

    /* Exploitation notes */
    if (info.init_array || info.fini_array) {
        printf("\n");
        printf("  " RED "★ Hijacking potential:" RESET "\n");
        if (info.init_array) {
            printf("    • Overwrite init_array[0] to execute code BEFORE main()\n");
        }
        if (info.fini_array) {
            printf("    • Overwrite fini_array[0] to execute code AFTER main()\n");
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * EXECUTION ORDER VISUALIZATION
 * ═══════════════════════════════════════════════════════════════════════════ */

void print_execution_order(void) {
    printf("\n");
    printf(YELLOW "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf(YELLOW "  EXECUTION ORDER OF INIT/FINI FUNCTIONS\n" RESET);
    printf(YELLOW "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf("\n");
    printf("  ┌─────────────────────────────────────────────────────────────────┐\n");
    printf("  │                      PROGRAM STARTUP                            │\n");
    printf("  └─────────────────────────────────────────────────────────────────┘\n");
    printf("                               │\n");
    printf("                               ▼\n");
    printf("  ┌─────────────────────────────────────────────────────────────────┐\n");
    printf("  │ " MAGENTA "1. DT_PREINIT_ARRAY" RESET " (main executable only)                    │\n");
    printf("  │    Called before any shared library initialization              │\n");
    printf("  └─────────────────────────────────────────────────────────────────┘\n");
    printf("                               │\n");
    printf("                               ▼\n");
    printf("  ┌─────────────────────────────────────────────────────────────────┐\n");
    printf("  │ " CYAN "2. Shared libraries initialized (dependency order)" RESET "            │\n");
    printf("  │    For each library:                                            │\n");
    printf("  │      a. DT_INIT function                                        │\n");
    printf("  │      b. DT_INIT_ARRAY functions (in order)                      │\n");
    printf("  └─────────────────────────────────────────────────────────────────┘\n");
    printf("                               │\n");
    printf("                               ▼\n");
    printf("  ┌─────────────────────────────────────────────────────────────────┐\n");
    printf("  │ " GREEN "3. Main executable DT_INIT" RESET "                                     │\n");
    printf("  └─────────────────────────────────────────────────────────────────┘\n");
    printf("                               │\n");
    printf("                               ▼\n");
    printf("  ┌─────────────────────────────────────────────────────────────────┐\n");
    printf("  │ " GREEN "4. Main executable DT_INIT_ARRAY" RESET "                               │\n");
    printf("  │    __attribute__((constructor)) functions go here              │\n");
    printf("  └─────────────────────────────────────────────────────────────────┘\n");
    printf("                               │\n");
    printf("                               ▼\n");
    printf("  ┌─────────────────────────────────────────────────────────────────┐\n");
    printf("  │ " GREEN "5. main()" RESET "                                                      │\n");
    printf("  └─────────────────────────────────────────────────────────────────┘\n");
    printf("                               │\n");
    printf("                               ▼\n");
    printf("  ┌─────────────────────────────────────────────────────────────────┐\n");
    printf("  │ " RED "6. Main executable DT_FINI_ARRAY" RESET " (reverse order)                │\n");
    printf("  │    __attribute__((destructor)) functions go here               │\n");
    printf("  └─────────────────────────────────────────────────────────────────┘\n");
    printf("                               │\n");
    printf("                               ▼\n");
    printf("  ┌─────────────────────────────────────────────────────────────────┐\n");
    printf("  │ " RED "7. Main executable DT_FINI" RESET "                                       │\n");
    printf("  └─────────────────────────────────────────────────────────────────┘\n");
    printf("                               │\n");
    printf("                               ▼\n");
    printf("  ┌─────────────────────────────────────────────────────────────────┐\n");
    printf("  │ " CYAN "8. Shared libraries finalized (reverse dependency order)" RESET "       │\n");
    printf("  │    For each library (reverse):                                  │\n");
    printf("  │      a. DT_FINI_ARRAY functions (reverse order)                 │\n");
    printf("  │      b. DT_FINI function                                        │\n");
    printf("  └─────────────────────────────────────────────────────────────────┘\n");
    printf("                               │\n");
    printf("                               ▼\n");
    printf("  ┌─────────────────────────────────────────────────────────────────┐\n");
    printf("  │                      PROGRAM EXIT                               │\n");
    printf("  └─────────────────────────────────────────────────────────────────┘\n");
    printf("\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ATTACK SCENARIOS
 * ═══════════════════════════════════════════════════════════════════════════ */

void print_attack_scenarios(void) {
    printf("\n");
    printf(RED "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf(RED "  ATTACK SCENARIOS\n" RESET);
    printf(RED "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf("\n");

    printf("  " YELLOW "SCENARIO 1: Init Array Hijacking" RESET "\n");
    printf("  ─────────────────────────────────────────────────────────────────\n");
    printf("  If attacker has write access to .init_array:\n");
    printf("    1. Find .init_array address via DT_INIT_ARRAY\n");
    printf("    2. Overwrite first entry with malicious function pointer\n");
    printf("    3. On next execution, malicious code runs BEFORE main()\n");
    printf("\n");
    printf("  " RED "Impact:" RESET " Code execution with full program privileges\n");
    printf("          before any security initialization in main()\n");
    printf("\n");

    printf("  " YELLOW "SCENARIO 2: Fini Array for Persistence" RESET "\n");
    printf("  ─────────────────────────────────────────────────────────────────\n");
    printf("  If attacker has write access to .fini_array:\n");
    printf("    1. Add malicious function to fini_array\n");
    printf("    2. Code executes on program exit\n");
    printf("    3. Can be used for cleanup/persistence after main() exits\n");
    printf("\n");
    printf("  " RED "Impact:" RESET " Guaranteed execution even if main() is short-lived\n");
    printf("\n");

    printf("  " YELLOW "SCENARIO 3: Shared Library Constructor" RESET "\n");
    printf("  ─────────────────────────────────────────────────────────────────\n");
    printf("  Create malicious .so with constructor:\n");
    printf("    __attribute__((constructor)) void evil() { /* payload */ }\n");
    printf("  \n");
    printf("  Load via:\n");
    printf("    • LD_PRELOAD\n");
    printf("    • DT_RPATH hijacking\n");
    printf("    • dlopen() in vulnerable code\n");
    printf("\n");
    printf("  " RED "Impact:" RESET " Code runs before main() in target process\n");
    printf("\n");

    printf("  " YELLOW "SCENARIO 4: Binary Patching" RESET "\n");
    printf("  ─────────────────────────────────────────────────────────────────\n");
    printf("  Modify ELF binary on disk:\n");
    printf("    1. Parse ELF headers to find .init_array section\n");
    printf("    2. Add code cave with malicious payload\n");
    printf("    3. Patch .init_array to include pointer to payload\n");
    printf("    4. Payload runs on every execution\n");
    printf("\n");
    printf("  " RED "Impact:" RESET " Persistent backdoor in binary\n");
    printf("\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * MAIN
 * ═══════════════════════════════════════════════════════════════════════════ */

int main(void) {
    printf("\n");
    printf(RED "╔════════════════════════════════════════════════════════════════════╗\n" RESET);
    printf(RED "║" YELLOW "           .INIT_ARRAY / .FINI_ARRAY EXPLORER                       " RED "║\n" RESET);
    printf(RED "║" RESET "                                                                    " RED "║\n" RESET);
    printf(RED "║" RESET "  Exploring constructor/destructor arrays in ELF binaries           " RED "║\n" RESET);
    printf(RED "║" RESET "  These run BEFORE main() and AFTER main() returns                  " RED "║\n" RESET);
    printf(RED "╚════════════════════════════════════════════════════════════════════╝\n" RESET);

    /* Print execution order */
    print_execution_order();

    /* Find r_debug */
    struct r_debug *debug = get_r_debug();
    if (!debug) {
        printf(RED "[!] Could not find r_debug\n" RESET);
        return 1;
    }

    /* Analyze each loaded object */
    printf(YELLOW "\n═══════════════════════════════════════════════════════════════════\n" RESET);
    printf(YELLOW "  ANALYZING LOADED OBJECTS\n" RESET);
    printf(YELLOW "═══════════════════════════════════════════════════════════════════\n" RESET);

    for (struct link_map *lm = debug->r_map; lm != NULL; lm = lm->l_next) {
        analyze_object(lm);
    }

    /* Print attack scenarios */
    print_attack_scenarios();

    printf(GREEN "[✓] Analysis complete.\n" RESET);
    printf("\n");

    return 0;
}
