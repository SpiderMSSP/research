/*
 * execution_order.c - Demonstrate Init/Fini Execution Order
 *
 * This program shows exactly when different types of
 * constructors and destructors run:
 *
 *   - __attribute__((constructor)) with priorities
 *   - __attribute__((destructor)) with priorities
 *   - atexit() handlers
 *
 * Compile: gcc -o execution_order execution_order.c
 *
 * EDUCATIONAL PURPOSES ONLY
 */

#include <stdio.h>
#include <stdlib.h>

/* Color codes */
#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define BLUE    "\033[1;34m"
#define MAGENTA "\033[1;35m"
#define CYAN    "\033[1;36m"
#define RESET   "\033[0m"

/* ═══════════════════════════════════════════════════════════════════════════
 * CONSTRUCTORS - Run BEFORE main()
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Priority: Lower number = runs FIRST (101 is before 102)
 * Range: 101-65535 (0-100 reserved for implementation)
 */

/* Highest priority constructor (runs first) */
__attribute__((constructor(101)))
void constructor_priority_101(void) {
    fprintf(stderr, CYAN "[CONSTRUCTOR] " GREEN "Priority 101" RESET " - Highest priority (runs first)\n");
}

__attribute__((constructor(102)))
void constructor_priority_102(void) {
    fprintf(stderr, CYAN "[CONSTRUCTOR] " GREEN "Priority 102" RESET "\n");
}

__attribute__((constructor(500)))
void constructor_priority_500(void) {
    fprintf(stderr, CYAN "[CONSTRUCTOR] " GREEN "Priority 500" RESET " - Medium priority\n");
}

/* Default priority constructor (no number) */
__attribute__((constructor))
void constructor_default(void) {
    fprintf(stderr, CYAN "[CONSTRUCTOR] " GREEN "Default priority" RESET " (65535 - runs last among constructors)\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * DESTRUCTORS - Run AFTER main() returns
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Priority: Lower number = runs LAST (reversed from constructors!)
 * Think of it as: constructed first = destructed last
 */

/* Highest priority destructor (runs LAST) */
__attribute__((destructor(101)))
void destructor_priority_101(void) {
    fprintf(stderr, RED "[DESTRUCTOR]  " YELLOW "Priority 101" RESET " - Highest priority (runs LAST)\n");
}

__attribute__((destructor(102)))
void destructor_priority_102(void) {
    fprintf(stderr, RED "[DESTRUCTOR]  " YELLOW "Priority 102" RESET "\n");
}

__attribute__((destructor(500)))
void destructor_priority_500(void) {
    fprintf(stderr, RED "[DESTRUCTOR]  " YELLOW "Priority 500" RESET " - Medium priority\n");
}

/* Default priority destructor (runs first among destructors) */
__attribute__((destructor))
void destructor_default(void) {
    fprintf(stderr, RED "[DESTRUCTOR]  " YELLOW "Default priority" RESET " (runs first among destructors)\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ATEXIT HANDLERS
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * atexit() handlers run in REVERSE order of registration
 * They run BEFORE destructors
 */

void atexit_first(void) {
    fprintf(stderr, MAGENTA "[ATEXIT]      " RESET "First registered (runs last of atexit)\n");
}

void atexit_second(void) {
    fprintf(stderr, MAGENTA "[ATEXIT]      " RESET "Second registered (runs second-to-last)\n");
}

void atexit_third(void) {
    fprintf(stderr, MAGENTA "[ATEXIT]      " RESET "Third registered (runs first of atexit)\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * MAIN
 * ═══════════════════════════════════════════════════════════════════════════ */

int main(void) {
    fprintf(stderr, "\n");
    fprintf(stderr, YELLOW "╔════════════════════════════════════════════════════════════════════╗\n" RESET);
    fprintf(stderr, YELLOW "║" RESET "              INIT/FINI EXECUTION ORDER DEMONSTRATION               " YELLOW "║\n" RESET);
    fprintf(stderr, YELLOW "╚════════════════════════════════════════════════════════════════════╝\n" RESET);
    fprintf(stderr, "\n");

    /* The constructors have already run by this point! */
    fprintf(stderr, BLUE "════════════════════════════════════════════════════════════════════\n" RESET);
    fprintf(stderr, BLUE "  MAIN() STARTING\n" RESET);
    fprintf(stderr, BLUE "════════════════════════════════════════════════════════════════════\n" RESET);
    fprintf(stderr, "\n");

    fprintf(stderr, "[MAIN]        Registering atexit handlers...\n");
    atexit(atexit_first);   /* Will run last */
    atexit(atexit_second);  /* Will run second */
    atexit(atexit_third);   /* Will run first (LIFO) */

    fprintf(stderr, "[MAIN]        Doing main program work...\n");
    fprintf(stderr, "[MAIN]        About to return from main()\n");

    fprintf(stderr, "\n");
    fprintf(stderr, BLUE "════════════════════════════════════════════════════════════════════\n" RESET);
    fprintf(stderr, BLUE "  MAIN() RETURNING\n" RESET);
    fprintf(stderr, BLUE "════════════════════════════════════════════════════════════════════\n" RESET);
    fprintf(stderr, "\n");

    /* Now the atexit handlers and destructors will run */
    return 0;
}
