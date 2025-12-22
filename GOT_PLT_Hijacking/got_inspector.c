/*
 * got_inspector.c - GOT/PLT Runtime Inspector
 *
 * This utility inspects the GOT of a running process or binary.
 * It demonstrates:
 *   1. How to read ELF headers to find GOT section
 *   2. How to dump GOT entries and their resolved values
 *   3. How to detect GOT hijacking
 *
 * Compile: gcc -o got_inspector got_inspector.c -ldl
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
#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <dlfcn.h>

/* Color codes */
#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define BLUE    "\033[1;34m"
#define CYAN    "\033[1;36m"
#define RESET   "\033[0m"

/* ═══════════════════════════════════════════════════════════════════════════
 * ELF PARSING HELPERS
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint64_t offset;    /* Offset in file */
    uint64_t vaddr;     /* Virtual address */
    uint64_t size;      /* Size of section */
    int found;
} section_info_t;

/* Find a section by name in ELF file */
int find_section(const char *filename, const char *section_name, section_info_t *info) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    struct stat st;
    fstat(fd, &st);

    void *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return -1;
    }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)map;

    /* Verify ELF magic */
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "Not an ELF file\n");
        munmap(map, st.st_size);
        close(fd);
        return -1;
    }

    /* Get section header string table */
    Elf64_Shdr *shdr = (Elf64_Shdr *)((uint8_t *)map + ehdr->e_shoff);
    Elf64_Shdr *shstrtab = &shdr[ehdr->e_shstrndx];
    char *strtab = (char *)map + shstrtab->sh_offset;

    info->found = 0;

    /* Find the requested section */
    for (int i = 0; i < ehdr->e_shnum; i++) {
        char *name = strtab + shdr[i].sh_name;
        if (strcmp(name, section_name) == 0) {
            info->offset = shdr[i].sh_offset;
            info->vaddr = shdr[i].sh_addr;
            info->size = shdr[i].sh_size;
            info->found = 1;
            break;
        }
    }

    munmap(map, st.st_size);
    close(fd);

    return info->found ? 0 : -1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * GOT ANALYSIS
 * ═══════════════════════════════════════════════════════════════════════════ */

void analyze_got(const char *filename) {
    section_info_t got_info, gotplt_info, rela_plt_info;

    printf(YELLOW "\n═══════════════════════════════════════════════════════════════════\n" RESET);
    printf(YELLOW "  GOT/PLT ANALYSIS: %s\n" RESET, filename);
    printf(YELLOW "═══════════════════════════════════════════════════════════════════\n\n" RESET);

    /* Find .got section */
    if (find_section(filename, ".got", &got_info) == 0) {
        printf(GREEN "[✓]" RESET " .got section found:\n");
        printf("    Address: " CYAN "0x%lx" RESET "\n", got_info.vaddr);
        printf("    Size:    %lu bytes (%lu entries)\n",
               got_info.size, got_info.size / 8);
    } else {
        printf(RED "[✗]" RESET " .got section not found\n");
    }

    /* Find .got.plt section */
    if (find_section(filename, ".got.plt", &gotplt_info) == 0) {
        printf("\n" GREEN "[✓]" RESET " .got.plt section found:\n");
        printf("    Address: " CYAN "0x%lx" RESET "\n", gotplt_info.vaddr);
        printf("    Size:    %lu bytes (%lu entries)\n",
               gotplt_info.size, gotplt_info.size / 8);
    } else {
        printf(RED "[✗]" RESET " .got.plt section not found\n");
    }

    /* Find .rela.plt section (contains relocation info) */
    if (find_section(filename, ".rela.plt", &rela_plt_info) == 0) {
        printf("\n" GREEN "[✓]" RESET " .rela.plt section found:\n");
        printf("    Contains PLT relocation entries\n");
    }

    /* Parse and display GOT entries from the file */
    printf(YELLOW "\n───────────────────────────────────────────────────────────────────\n" RESET);
    printf(YELLOW "  .got.plt ENTRIES (PLT function pointers)\n" RESET);
    printf(YELLOW "───────────────────────────────────────────────────────────────────\n\n" RESET);

    int fd = open(filename, O_RDONLY);
    if (fd < 0) return;

    struct stat st;
    fstat(fd, &st);
    void *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

    if (map != MAP_FAILED && gotplt_info.found) {
        uint64_t *got = (uint64_t *)((uint8_t *)map + gotplt_info.offset);
        size_t num_entries = gotplt_info.size / sizeof(uint64_t);

        printf("  Index │ Address          │ Initial Value    │ Description\n");
        printf("  ──────┼──────────────────┼──────────────────┼─────────────────\n");

        for (size_t i = 0; i < num_entries && i < 20; i++) {
            uint64_t addr = gotplt_info.vaddr + i * 8;
            uint64_t value = got[i];

            const char *desc = "";
            if (i == 0) desc = "→ .dynamic";
            else if (i == 1) desc = "→ link_map (filled by ld.so)";
            else if (i == 2) desc = "→ _dl_runtime_resolve";
            else desc = "→ PLT stub (lazy) / libc func";

            printf("  [%2zu]  │ " CYAN "0x%012lx" RESET " │ 0x%012lx   │ %s\n",
                   i, addr, value, desc);
        }

        if (num_entries > 20) {
            printf("  ...   │ (%zu more entries)\n", num_entries - 20);
        }

        munmap(map, st.st_size);
    }

    close(fd);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * RELRO CHECK
 * ═══════════════════════════════════════════════════════════════════════════ */

void check_relro(const char *filename) {
    printf(YELLOW "\n───────────────────────────────────────────────────────────────────\n" RESET);
    printf(YELLOW "  RELRO PROTECTION STATUS\n" RESET);
    printf(YELLOW "───────────────────────────────────────────────────────────────────\n\n" RESET);

    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return;
    }

    struct stat st;
    fstat(fd, &st);
    void *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

    if (map == MAP_FAILED) {
        close(fd);
        return;
    }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)map;
    Elf64_Phdr *phdr = (Elf64_Phdr *)((uint8_t *)map + ehdr->e_phoff);

    int has_relro = 0;
    int has_bind_now = 0;

    /* Check program headers for GNU_RELRO */
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_GNU_RELRO) {
            has_relro = 1;
        }
    }

    /* Check dynamic section for BIND_NOW flag */
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            Elf64_Dyn *dyn = (Elf64_Dyn *)((uint8_t *)map + phdr[i].p_offset);
            while (dyn->d_tag != DT_NULL) {
                if (dyn->d_tag == DT_FLAGS) {
                    if (dyn->d_un.d_val & DF_BIND_NOW) {
                        has_bind_now = 1;
                    }
                }
                if (dyn->d_tag == DT_FLAGS_1) {
                    if (dyn->d_un.d_val & DF_1_NOW) {
                        has_bind_now = 1;
                    }
                }
                dyn++;
            }
            break;
        }
    }

    if (has_relro && has_bind_now) {
        printf("  Protection: " GREEN "FULL RELRO" RESET "\n");
        printf("  ├─ GNU_RELRO segment: " GREEN "Present" RESET "\n");
        printf("  └─ BIND_NOW flag:     " GREEN "Enabled" RESET "\n");
        printf("\n");
        printf("  " GREEN "■" RESET " GOT is " GREEN "READ-ONLY" RESET " - hijacking NOT possible!\n");
        printf("    All symbols resolved at load time.\n");
    } else if (has_relro) {
        printf("  Protection: " YELLOW "PARTIAL RELRO" RESET "\n");
        printf("  ├─ GNU_RELRO segment: " GREEN "Present" RESET "\n");
        printf("  └─ BIND_NOW flag:     " RED "Disabled" RESET "\n");
        printf("\n");
        printf("  " YELLOW "■" RESET " .got is read-only, but " RED ".got.plt is WRITABLE" RESET "\n");
        printf("    GOT hijacking IS possible after symbols are resolved!\n");
    } else {
        printf("  Protection: " RED "NO RELRO" RESET "\n");
        printf("  ├─ GNU_RELRO segment: " RED "Missing" RESET "\n");
        printf("  └─ BIND_NOW flag:     " RED "Disabled" RESET "\n");
        printf("\n");
        printf("  " RED "■" RESET " GOT is " RED "FULLY WRITABLE" RESET " - trivially hijackable!\n");
    }

    munmap(map, st.st_size);
    close(fd);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * PLT VISUALIZATION
 * ═══════════════════════════════════════════════════════════════════════════ */

void print_plt_explanation(void) {
    printf(YELLOW "\n───────────────────────────────────────────────────────────────────\n" RESET);
    printf(YELLOW "  HOW PLT/GOT RESOLUTION WORKS\n" RESET);
    printf(YELLOW "───────────────────────────────────────────────────────────────────\n\n" RESET);

    printf("  " BLUE "First call to puts():" RESET "\n\n");
    printf("    ┌─────────────┐     ┌─────────────┐     ┌─────────────────┐\n");
    printf("    │ call puts@PLT ──→ │ PLT[puts]   │ ──→ │ GOT[puts]       │\n");
    printf("    └─────────────┘     │ jmp *GOT    │     │ = PLT+6 (stub)  │\n");
    printf("                        └─────────────┘     └────────┬────────┘\n");
    printf("                                                     │\n");
    printf("                                                     ▼\n");
    printf("                        ┌─────────────┐     ┌─────────────────┐\n");
    printf("                        │ PLT[0]      │ ←── │ push reloc_idx  │\n");
    printf("                        │ resolver    │     │ jmp PLT[0]      │\n");
    printf("                        └──────┬──────┘     └─────────────────┘\n");
    printf("                               │\n");
    printf("                               ▼\n");
    printf("                        ┌─────────────────────────────────────┐\n");
    printf("                        │ _dl_runtime_resolve()               │\n");
    printf("                        │   1. Find 'puts' in libc            │\n");
    printf("                        │   2. Write address to GOT[puts]     │\n");
    printf("                        │   3. Jump to puts()                 │\n");
    printf("                        └─────────────────────────────────────┘\n");

    printf("\n  " BLUE "Subsequent calls to puts():" RESET "\n\n");
    printf("    ┌─────────────┐     ┌─────────────┐     ┌─────────────────┐\n");
    printf("    │ call puts@PLT ──→ │ PLT[puts]   │ ──→ │ GOT[puts]       │\n");
    printf("    └─────────────┘     │ jmp *GOT    │     │ = libc:puts     │\n");
    printf("                        └─────────────┘     └────────┬────────┘\n");
    printf("                                                     │ " GREEN "DIRECT!" RESET "\n");
    printf("                                                     ▼\n");
    printf("                                            ┌─────────────────┐\n");
    printf("                                            │ libc: puts()    │\n");
    printf("                                            └─────────────────┘\n");

    printf("\n  " RED "After GOT Hijacking:" RESET "\n\n");
    printf("    ┌─────────────┐     ┌─────────────┐     ┌─────────────────┐\n");
    printf("    │ call puts@PLT ──→ │ PLT[puts]   │ ──→ │ GOT[puts]       │\n");
    printf("    └─────────────┘     │ jmp *GOT    │     │ = " RED "evil_puts" RESET "    │\n");
    printf("                        └─────────────┘     └────────┬────────┘\n");
    printf("                                                     │ " RED "HIJACKED!" RESET "\n");
    printf("                                                     ▼\n");
    printf("                                            ┌─────────────────┐\n");
    printf("                                            │ " RED "evil_puts()" RESET "     │\n");
    printf("                                            │ Attacker code!  │\n");
    printf("                                            └─────────────────┘\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * MAIN
 * ═══════════════════════════════════════════════════════════════════════════ */

int main(int argc, char *argv[]) {
    printf("\n");
    printf(CYAN "╔════════════════════════════════════════════════════════════════════╗\n" RESET);
    printf(CYAN "║" RESET "                    GOT/PLT INSPECTOR UTILITY                       " CYAN "║\n" RESET);
    printf(CYAN "╚════════════════════════════════════════════════════════════════════╝\n" RESET);

    if (argc < 2) {
        printf("\nUsage: %s <binary>\n", argv[0]);
        printf("\nExample:\n");
        printf("  %s ./victim          # Analyze victim binary\n", argv[0]);
        printf("  %s /bin/ls           # Analyze system binary\n", argv[0]);

        /* If no argument, analyze self */
        printf("\n" YELLOW "[*] No binary specified, analyzing self...\n" RESET);

        char self_path[256];
        ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
        if (len > 0) {
            self_path[len] = '\0';
            analyze_got(self_path);
            check_relro(self_path);
            print_plt_explanation();
        }
    } else {
        analyze_got(argv[1]);
        check_relro(argv[1]);
        print_plt_explanation();
    }

    printf("\n");
    return 0;
}
