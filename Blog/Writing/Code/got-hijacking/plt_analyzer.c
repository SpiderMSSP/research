#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <link.h>

typedef struct {
    char* name;
    void* original_addr;
    void* hijacked_addr;
    int is_hijacked;
} plt_entry_t;

typedef struct {
    plt_entry_t* entries;
    size_t count;
    size_t capacity;
} plt_table_t;

plt_table_t plt_table = {0};

void init_plt_table() {
    plt_table.capacity = 64;
    plt_table.entries = malloc(plt_table.capacity * sizeof(plt_entry_t));
    plt_table.count = 0;
}

void add_plt_entry(const char* name, void* original_addr) {
    if (plt_table.count >= plt_table.capacity) {
        plt_table.capacity *= 2;
        plt_table.entries = realloc(plt_table.entries, 
                                   plt_table.capacity * sizeof(plt_entry_t));
    }
    
    plt_entry_t* entry = &plt_table.entries[plt_table.count++];
    entry->name = strdup(name);
    entry->original_addr = original_addr;
    entry->hijacked_addr = NULL;
    entry->is_hijacked = 0;
}

int callback_phdr(struct dl_phdr_info *info, size_t size, void *data) {
    printf("Library: %s (Base: 0x%lx)\n", info->dlpi_name, info->dlpi_addr);
    
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *phdr = &info->dlpi_phdr[i];
        
        if (phdr->p_type == PT_DYNAMIC) {
            ElfW(Dyn) *dyn = (ElfW(Dyn) *)(info->dlpi_addr + phdr->p_vaddr);
            
            ElfW(Sym) *symtab = NULL;
            char *strtab = NULL;
            ElfW(Rela) *rela = NULL;
            size_t rela_count = 0;
            
            for (ElfW(Dyn) *d = dyn; d->d_tag != DT_NULL; d++) {
                switch (d->d_tag) {
                    case DT_SYMTAB:
                        symtab = (ElfW(Sym) *)(info->dlpi_addr + d->d_un.d_ptr);
                        break;
                    case DT_STRTAB:
                        strtab = (char *)(info->dlpi_addr + d->d_un.d_ptr);
                        break;
                    case DT_JMPREL:
                        rela = (ElfW(Rela) *)(info->dlpi_addr + d->d_un.d_ptr);
                        break;
                    case DT_PLTRELSZ:
                        rela_count = d->d_un.d_val / sizeof(ElfW(Rela));
                        break;
                }
            }
            
            if (rela && symtab && strtab) {
                printf("  PLT Relocations found: %zu\n", rela_count);
                
                for (size_t j = 0; j < rela_count; j++) {
                    ElfW(Word) sym_idx = ELF64_R_SYM(rela[j].r_info);
                    
                    if (sym_idx < 1000) {
                        char *sym_name = strtab + symtab[sym_idx].st_name;
                        void *got_addr = (void *)(info->dlpi_addr + rela[j].r_offset);
                        
                        printf("    %s @ 0x%lx -> 0x%lx\n", 
                               sym_name, (uintptr_t)got_addr, *(uintptr_t*)got_addr);
                        
                        add_plt_entry(sym_name, *(void**)got_addr);
                    }
                }
            }
        }
    }
    
    return 0;
}

void analyze_plt() {
    init_plt_table();
    
    printf("=== PLT/GOT Analysis ===\n");
    dl_iterate_phdr(callback_phdr, NULL);
    
    printf("\n=== Summary ===\n");
    printf("Found %zu PLT entries\n", plt_table.count);
    
    for (size_t i = 0; i < plt_table.count; i++) {
        plt_entry_t* entry = &plt_table.entries[i];
        printf("  %s: 0x%lx %s\n", 
               entry->name, 
               (uintptr_t)entry->original_addr,
               entry->is_hijacked ? "[HIJACKED]" : "");
    }
}

int main() {
    analyze_plt();
    return 0;
}