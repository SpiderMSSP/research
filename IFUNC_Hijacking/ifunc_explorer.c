/*
 * ifunc_explorer.c - IFUNC Mechanism Explorer
 *
 * This program demonstrates how GNU IFUNC (Indirect Functions) work:
 *
 *   1. IFUNC allows runtime selection of function implementation
 *   2. A "resolver" function chooses which implementation to use
 *   3. The resolver runs DURING dynamic linking (before main!)
 *   4. Common use: CPU-specific optimizations (SSE vs AVX)
 *
 * Attack implications:
 *   - Resolver code runs before constructors
 *   - Can be used for early code execution
 *   - Can redirect function calls
 *
 * Compile: gcc -o ifunc_explorer ifunc_explorer.c
 *
 * EDUCATIONAL PURPOSES ONLY
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <cpuid.h>

/* Color codes */
#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define BLUE    "\033[1;34m"
#define MAGENTA "\033[1;35m"
#define CYAN    "\033[1;36m"
#define RESET   "\033[0m"

/* Track when resolver runs */
static int resolver_called = 0;
static int resolver_call_time = 0;  /* 0 = not yet, 1 = before main, 2 = after main */

/* ═══════════════════════════════════════════════════════════════════════════
 * IFUNC EXAMPLE: Multiple implementations of the same function
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Implementation 1: Simple/fallback version */
static int my_function_simple(int x) {
    return x * 2;
}

/* Implementation 2: "Optimized" version */
static int my_function_optimized(int x) {
    return (x << 1);  /* Same result, different implementation */
}

/* Implementation 3: "Special" version */
static int my_function_special(int x) {
    return x * 2 + 1;  /* Slightly different for demonstration */
}

/*
 * RESOLVER FUNCTION
 *
 * This function is called by the dynamic linker to determine
 * which implementation of my_function to use.
 *
 * CRITICAL: This runs BEFORE main(), during symbol resolution!
 */
static void *my_function_resolver(void) {
    resolver_called = 1;

    /* Check if main has started (it hasn't - resolver runs first!) */
    /* We can't easily detect this, but we know it runs before main */

    /*
     * In real code, this would check CPU features:
     *
     * unsigned int eax, ebx, ecx, edx;
     * __cpuid(1, eax, ebx, ecx, edx);
     *
     * if (ecx & (1 << 28)) {  // AVX support
     *     return my_function_optimized;
     * }
     */

    /* For demo, just return the optimized version */
    return my_function_optimized;
}

/* Declare the IFUNC symbol */
int my_function(int x) __attribute__((ifunc("my_function_resolver")));

/* ═══════════════════════════════════════════════════════════════════════════
 * DEMONSTRATION OF RESOLVER TIMING
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * This constructor runs before main(), but AFTER the resolver
 */
__attribute__((constructor))
static void check_resolver_timing(void) {
    if (resolver_called) {
        resolver_call_time = 1;  /* Resolver ran before this constructor */
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * PRINT EXPLANATION
 * ═══════════════════════════════════════════════════════════════════════════ */

void print_explanation(void) {
    printf("\n");
    printf(RED "╔════════════════════════════════════════════════════════════════════╗\n" RESET);
    printf(RED "║" YELLOW "                  IFUNC MECHANISM EXPLORER                         " RED "║\n" RESET);
    printf(RED "║" RESET "                                                                    " RED "║\n" RESET);
    printf(RED "║" RESET "  GNU Indirect Functions (IFUNC) allow runtime implementation      " RED "║\n" RESET);
    printf(RED "║" RESET "  selection via a resolver function that runs during linking!      " RED "║\n" RESET);
    printf(RED "╚════════════════════════════════════════════════════════════════════╝\n" RESET);
    printf("\n");

    printf(CYAN "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf(CYAN "  HOW IFUNC WORKS\n" RESET);
    printf(CYAN "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf("\n");

    printf(YELLOW "  DECLARATION:\n" RESET);
    printf("  ─────────────────────────────────────────────────────────────────\n");
    printf("    /* Multiple implementations */\n");
    printf("    static int func_v1(int x) { return x * 2; }      /* Fallback */\n");
    printf("    static int func_v2(int x) { return x << 1; }     /* Optimized */\n");
    printf("\n");
    printf("    /* Resolver chooses implementation */\n");
    printf("    static void *func_resolver(void) {\n");
    printf("        if (cpu_has_avx()) return func_v2;\n");
    printf("        return func_v1;\n");
    printf("    }\n");
    printf("\n");
    printf("    /* IFUNC declaration */\n");
    printf("    int func(int) __attribute__((ifunc(\"func_resolver\")));\n");
    printf("\n");

    printf(YELLOW "  EXECUTION TIMELINE:\n" RESET);
    printf("  ─────────────────────────────────────────────────────────────────\n");
    printf("\n");
    printf("    execve(\"./program\")\n");
    printf("         │\n");
    printf("         ▼\n");
    printf("    ┌─────────────────────────────────────────────────────────────┐\n");
    printf("    │  Dynamic Linker (ld.so)                                     │\n");
    printf("    │                                                             │\n");
    printf("    │  1. Load libraries                                          │\n");
    printf("    │  2. For each IFUNC symbol:                                  │\n");
    printf("    │     " RED "→ CALL RESOLVER FUNCTION ←" RESET "                          │\n");
    printf("    │     → Store returned address in GOT                         │\n");
    printf("    │  3. Run .init_array (constructors)                          │\n");
    printf("    │  4. Call main()                                             │\n");
    printf("    └─────────────────────────────────────────────────────────────┘\n");
    printf("\n");
    printf("    " RED "Resolver runs BEFORE constructors and main()!" RESET "\n");
    printf("\n");

    printf(YELLOW "  ATTACK SURFACE:\n" RESET);
    printf("  ─────────────────────────────────────────────────────────────────\n");
    printf("    1. " RED "Early code execution" RESET " - Resolver runs during linking\n");
    printf("    2. " RED "Function redirection" RESET " - Return address of malicious function\n");
    printf("    3. " RED "Symbol shadowing" RESET " - IFUNC in LD_PRELOAD shadows libc\n");
    printf("    4. " RED "No constructors needed" RESET " - Code runs even earlier\n");
    printf("\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * MAIN
 * ═══════════════════════════════════════════════════════════════════════════ */

int main(void) {
    print_explanation();

    printf(CYAN "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf(CYAN "  LIVE DEMONSTRATION\n" RESET);
    printf(CYAN "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf("\n");

    /* Check when resolver was called */
    printf("  Resolver timing check:\n");
    printf("    Resolver was called: " GREEN "%s" RESET "\n",
           resolver_called ? "YES" : "NO");
    printf("    Resolver ran before constructor: " GREEN "%s" RESET "\n",
           resolver_call_time == 1 ? "YES" : "NO");
    printf("\n");

    /* Call the IFUNC */
    printf("  Calling my_function(5):\n");
    int result = my_function(5);
    printf("    Result: " GREEN "%d" RESET "\n", result);
    printf("    (The resolver chose which implementation to use)\n");
    printf("\n");

    /* Show how glibc uses IFUNC */
    printf(CYAN "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf(CYAN "  IFUNC IN THE WILD (glibc)\n" RESET);
    printf(CYAN "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf("\n");

    printf("  glibc uses IFUNC extensively for CPU-optimized functions:\n\n");
    printf("    • memcpy   - SSE2, SSSE3, AVX, AVX512 versions\n");
    printf("    • memset   - Multiple optimized versions\n");
    printf("    • strcmp   - CPU-specific implementations\n");
    printf("    • strlen   - Vectorized implementations\n");
    printf("\n");
    printf("  Check with: " YELLOW "objdump -T /lib/x86_64-linux-gnu/libc.so.6 | grep IFUNC" RESET "\n");
    printf("\n");

    printf(GREEN "[✓] Explorer complete.\n" RESET);
    printf("\n");

    return 0;
}
