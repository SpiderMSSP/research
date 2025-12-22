/*
 * dt_needed_explorer.c - DT_NEEDED Entry Explorer
 *
 * This tool explores DT_NEEDED entries in ELF binaries:
 *   1. Lists all required shared libraries
 *   2. Shows the order libraries are loaded
 *   3. Demonstrates how DT_NEEDED affects library search
 *
 * DT_NEEDED entries tell the dynamic linker which shared libraries
 * a binary requires. The linker loads these BEFORE main() runs.
 *
 * Compile: gcc -o dt_needed_explorer dt_needed_explorer.c -ldl
 *
 * EDUCATIONAL PURPOSES ONLY
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <elf.h>
#include <link.h>

/* Color codes */
#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define BLUE    "\033[1;34m"
#define MAGENTA "\033[1;35m"
#define CYAN    "\033[1;36m"
#define RESET   "\033[0m"

/* ═══════════════════════════════════════════════════════════════════════════
 * PRINT EXPLANATION
 * ═══════════════════════════════════════════════════════════════════════════ */

void print_explanation(void) {
    printf("\n");
    printf(RED "╔════════════════════════════════════════════════════════════════════╗\n" RESET);
    printf(RED "║" YELLOW "                 DT_NEEDED ENTRY EXPLORER                          " RED "║\n" RESET);
    printf(RED "║" RESET "                                                                    " RED "║\n" RESET);
    printf(RED "║" RESET "  Exploring library dependencies in ELF binaries                    " RED "║\n" RESET);
    printf(RED "║" RESET "  DT_NEEDED entries specify required shared libraries               " RED "║\n" RESET);
    printf(RED "╚════════════════════════════════════════════════════════════════════╝\n" RESET);
    printf("\n");

    printf(CYAN "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf(CYAN "  HOW DT_NEEDED WORKS\n" RESET);
    printf(CYAN "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf("\n");

    printf("  The " YELLOW "DT_NEEDED" RESET " entry in the ELF dynamic section specifies\n");
    printf("  shared libraries that must be loaded for the binary to run.\n\n");

    printf(YELLOW "  DYNAMIC SECTION STRUCTURE:\n" RESET);
    printf("  ─────────────────────────────────────────────────────────────────\n");
    printf("    typedef struct {\n");
    printf("        Elf64_Sxword d_tag;    /* Entry type (DT_NEEDED = 1) */\n");
    printf("        union {\n");
    printf("            Elf64_Xword d_val; /* Integer value */\n");
    printf("            Elf64_Addr d_ptr;  /* Address value */\n");
    printf("        } d_un;\n");
    printf("    } Elf64_Dyn;\n\n");

    printf("    For DT_NEEDED: d_val = offset into .dynstr for library name\n\n");

    printf(YELLOW "  LIBRARY LOADING ORDER:\n" RESET);
    printf("  ─────────────────────────────────────────────────────────────────\n");
    printf("\n");
    printf("    Binary's DT_NEEDED entries (in order):\n");
    printf("      [0] libfoo.so    ─┐\n");
    printf("      [1] libbar.so     │  Loaded in this order\n");
    printf("      [2] libc.so.6    ─┘  BEFORE main() runs!\n");
    printf("\n");
    printf("    Each library's DT_NEEDED entries are also processed (BFS).\n");
    printf("\n");

    printf(YELLOW "  ATTACK SURFACE:\n" RESET);
    printf("  ─────────────────────────────────────────────────────────────────\n");
    printf("    1. " RED "Inject DT_NEEDED" RESET " - Add entry for attacker's library\n");
    printf("       → Library loaded automatically, constructor runs\n\n");
    printf("    2. " RED "Reorder DT_NEEDED" RESET " - Move attacker's library first\n");
    printf("       → Symbols resolved from attacker's library\n\n");
    printf("    3. " RED "Replace DT_NEEDED" RESET " - Change library name string\n");
    printf("       → Redirect to attacker's library\n");
    printf("\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ANALYZE ELF FILE
 * ═══════════════════════════════════════════════════════════════════════════ */

int analyze_elf(const char *filename) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        return -1;
    }

    void *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return -1;
    }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)map;

    /* Verify ELF magic */
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, RED "[!] Not an ELF file\n" RESET);
        munmap(map, st.st_size);
        close(fd);
        return -1;
    }

    printf(CYAN "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf(CYAN "  ANALYZING: %s\n" RESET, filename);
    printf(CYAN "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf("\n");

    /* Find dynamic section */
    Elf64_Phdr *phdr = (Elf64_Phdr *)((char *)map + ehdr->e_phoff);
    Elf64_Dyn *dynamic = NULL;
    size_t dynamic_size = 0;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dynamic = (Elf64_Dyn *)((char *)map + phdr[i].p_offset);
            dynamic_size = phdr[i].p_filesz;
            break;
        }
    }

    if (!dynamic) {
        printf("  " YELLOW "No dynamic section found (static binary?)\n" RESET);
        munmap(map, st.st_size);
        close(fd);
        return 0;
    }

    /* Find string table */
    char *strtab = NULL;
    for (Elf64_Dyn *dyn = dynamic; dyn->d_tag != DT_NULL; dyn++) {
        if (dyn->d_tag == DT_STRTAB) {
            /* For executables, this is a virtual address; for analysis we need file offset */
            /* Find the section that contains this address */
            for (int i = 0; i < ehdr->e_phnum; i++) {
                if (phdr[i].p_type == PT_LOAD &&
                    dyn->d_un.d_ptr >= phdr[i].p_vaddr &&
                    dyn->d_un.d_ptr < phdr[i].p_vaddr + phdr[i].p_filesz) {
                    size_t offset = dyn->d_un.d_ptr - phdr[i].p_vaddr + phdr[i].p_offset;
                    strtab = (char *)map + offset;
                    break;
                }
            }
            break;
        }
    }

    if (!strtab) {
        printf("  " RED "Could not find string table\n" RESET);
        munmap(map, st.st_size);
        close(fd);
        return -1;
    }

    /* Print DT_NEEDED entries */
    printf("  " YELLOW "DT_NEEDED entries (required libraries):\n" RESET);
    printf("  ─────────────────────────────────────────────────────────────────\n\n");

    int count = 0;
    for (Elf64_Dyn *dyn = dynamic; dyn->d_tag != DT_NULL; dyn++) {
        if (dyn->d_tag == DT_NEEDED) {
            const char *libname = strtab + dyn->d_un.d_val;
            printf("    [%2d] " GREEN "%s" RESET "\n", count, libname);
            printf("         String offset: 0x%lx\n", dyn->d_un.d_val);
            count++;
        }
    }

    if (count == 0) {
        printf("    " YELLOW "(no DT_NEEDED entries)\n" RESET);
    }

    printf("\n");
    printf("  Total: " GREEN "%d" RESET " required libraries\n\n", count);

    /* Show other relevant dynamic entries */
    printf("  " YELLOW "Other relevant dynamic entries:\n" RESET);
    printf("  ─────────────────────────────────────────────────────────────────\n\n");

    for (Elf64_Dyn *dyn = dynamic; dyn->d_tag != DT_NULL; dyn++) {
        switch (dyn->d_tag) {
            case DT_RPATH:
                printf("    DT_RPATH:   " MAGENTA "%s" RESET "\n", strtab + dyn->d_un.d_val);
                break;
            case DT_RUNPATH:
                printf("    DT_RUNPATH: " MAGENTA "%s" RESET "\n", strtab + dyn->d_un.d_val);
                break;
            case DT_SONAME:
                printf("    DT_SONAME:  " BLUE "%s" RESET "\n", strtab + dyn->d_un.d_val);
                break;
        }
    }

    printf("\n");

    /* Show loading order explanation */
    printf("  " YELLOW "Library search order:\n" RESET);
    printf("  ─────────────────────────────────────────────────────────────────\n");
    printf("    1. DT_RPATH (deprecated, searched first)\n");
    printf("    2. LD_LIBRARY_PATH environment variable\n");
    printf("    3. DT_RUNPATH\n");
    printf("    4. /etc/ld.so.cache\n");
    printf("    5. /lib, /usr/lib (default paths)\n");
    printf("\n");

    munmap(map, st.st_size);
    close(fd);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * SHOW RUNTIME LIBRARIES
 * ═══════════════════════════════════════════════════════════════════════════ */

static int callback(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    int *count = (int *)data;

    const char *name = info->dlpi_name;
    if (!name || name[0] == '\0') {
        name = "(main executable)";
    }

    printf("    [%2d] " GREEN "0x%012lx" RESET "  %s\n",
           (*count)++, info->dlpi_addr, name);

    return 0;
}

void show_runtime_libraries(void) {
    printf(CYAN "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf(CYAN "  CURRENTLY LOADED LIBRARIES (this process)\n" RESET);
    printf(CYAN "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf("\n");

    printf("  These libraries were loaded due to DT_NEEDED entries:\n\n");

    int count = 0;
    dl_iterate_phdr(callback, &count);

    printf("\n");
    printf("  Total: " GREEN "%d" RESET " loaded objects\n\n", count);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * MAIN
 * ═══════════════════════════════════════════════════════════════════════════ */

int main(int argc, char *argv[]) {
    print_explanation();

    if (argc > 1) {
        /* Analyze specified file */
        analyze_elf(argv[1]);
    } else {
        /* Show currently loaded libraries */
        show_runtime_libraries();

        printf("  " YELLOW "Usage:" RESET " %s <elf-file>\n", argv[0]);
        printf("         Analyze DT_NEEDED entries in an ELF file\n\n");
    }

    printf(GREEN "[✓] Explorer complete.\n" RESET);
    printf("\n");

    return 0;
}
