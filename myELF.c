#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <sys/mman.h>
#include <fcntl.h>

typedef struct{
    int degug_mode;
    char file_names[2][30];
    int file_descriptors[2];
    int sizes[2];
    int num_of_files;
    void  *mmaps[2];
}keep_maps;

void debug_mode(keep_maps *keep_map){
    if(keep_map->degug_mode == 1){
        printf("Debug mode is now on\n");
    }
    else{
        printf("Debug mode is now off\n");
    }
}

void clearInputBuffer() {
    char c;
    while ((c = getchar()) != '\n' && c != EOF);
}

void examine_ELF_file(keep_maps *keep_map) {
    if (keep_map->num_of_files == 2) {
        printf("You can only load 2 files\n");
        return;
    }
    char file_name[30];
    printf("Please enter file name you are interested in examining: ");
    //clearInputBuffer();
    fgets(file_name, 30, stdin);
    file_name[strcspn(file_name, "\n")] = 0;
    if (keep_map->degug_mode == 1) {
        printf("Debug: file name set to %s\n", file_name);
    }

    strcpy(keep_map->file_names[keep_map->num_of_files], file_name);
    keep_map->file_descriptors[keep_map->num_of_files] = open(file_name, O_RDONLY);

    if (keep_map->file_descriptors[keep_map->num_of_files] == -1) {
        printf("Error in open file\n");
        return;
    }

    keep_map->sizes[keep_map->num_of_files] = lseek(keep_map->file_descriptors[keep_map->num_of_files], 0, SEEK_END);
    lseek(keep_map->file_descriptors[keep_map->num_of_files], 0, SEEK_SET);
    keep_map->mmaps[keep_map->num_of_files] = mmap(NULL, keep_map->sizes[keep_map->num_of_files], PROT_READ, MAP_PRIVATE,
                                                   keep_map->file_descriptors[keep_map->num_of_files], 0);

    if (keep_map->mmaps[keep_map->num_of_files] == MAP_FAILED) {
        printf("Error in mmap\n");
        return;
    }

    if (keep_map->degug_mode == 1) {
        printf("Debug: File %s has been mapped\n", file_name);
    }

    Elf32_Ehdr *header = (Elf32_Ehdr *) keep_map->mmaps[keep_map->num_of_files];
    printf("The bytes 1,2,3 of the magic number are: %c %c %c\n", header->e_ident[1], header->e_ident[2],
           header->e_ident[3]);
    if (header->e_ident[1] == 'E' && header->e_ident[2] == 'L' && header->e_ident[3] == 'F') {
        printf("This is an ELF file\n");
    } else {
        printf("This is not an ELF file\n");
        return;
    }

    char data_encoding = header->e_ident[5];
    if (data_encoding == 1) {
        printf("Data encoding: 2's complement, little endian\n");
    } else if (data_encoding == 2) {
        printf("Data encoding: 2's complement, big endian\n");
    } else {
        printf("Data encoding: Invalid\n");
    }

    printf("Entry point: 0x%x\n", header->e_entry);

    printf("The section header table offset: %d\n", header->e_shoff);
    printf("The number of section header entries: %d\n", header->e_shnum);
    printf("The size of each section header entry: %d\n", header->e_shentsize);

    printf("The program header table offset: %d\n", header->e_phoff);
    printf("The number of program header entries: %d\n", header->e_phnum);
    printf("The size of each program header entry: %d\n\n", header->e_phentsize);


    keep_map->num_of_files++;
}

void print_section_names(keep_maps *keep_map) {
    if (keep_map->num_of_files == 0) {
        printf("No files have been loaded\n\n");
        return;
    }
    for(int i = 0; i<keep_map->num_of_files; i++){
        printf("File: %s\n", keep_map->file_names[i]);
        Elf32_Ehdr *header = (Elf32_Ehdr *) keep_map->mmaps[i];
        Elf32_Shdr *section = (Elf32_Shdr *) (keep_map->mmaps[i] + header->e_shoff);
        Elf32_Shdr *string_table_section = (Elf32_Shdr *) (section + header->e_shstrndx);
        char *string_table = (char *) (keep_map->mmaps[i] + string_table_section->sh_offset);
        if(keep_map->degug_mode == 1){
            printf("Debug: Section header table offset: %d\n", header->e_shoff);
            printf("Debug: Number of section header entries: %d\n", header->e_shnum);
            printf("Debug: Size of each section header entry: %d\n", header->e_shentsize);
            printf("Debug: String table section offset: %d\n", string_table_section->sh_offset);
        }
        for(int j = 0; j<header->e_shnum; j++){
            printf("[%d] \t %s \t %x \t %x \t %x \t %u \n", j, string_table + section[j].sh_name, section[j].sh_addr, section[j].sh_offset, section[j].sh_size, section[j].sh_type);
        }
    }
}

void print_symbols(keep_maps * keep_map){
    if (keep_map->num_of_files == 0) {
        printf("No files have been loaded\n\n");
        return;
    }
    for(int i = 0; i<keep_map->num_of_files; i++) {
        printf("File: %s\n\n", keep_map->file_names[i]);
        int symbol_table_index = find_symbol_table(keep_map, i);
        int symbol_string_table_index = find_string_table(keep_map, i);
        if (symbol_table_index == -1) {
            printf("No symbol table found\n");
            return;
        }
        Elf32_Ehdr *header = (Elf32_Ehdr *) keep_map->mmaps[i];
        Elf32_Shdr *section = (Elf32_Shdr * )(keep_map->mmaps[i] + header->e_shoff);
        Elf32_Shdr *string_table_section = (Elf32_Shdr * )(section + header->e_shstrndx);
        char *string_table = (char *) (keep_map->mmaps[i] + string_table_section->sh_offset);
        char *string_table_symbols =(char*) keep_map->mmaps[i] + section[symbol_string_table_index].sh_offset;
        Elf32_Sym *symbol_table = (Elf32_Sym * )(keep_map->mmaps[i] + section[symbol_table_index].sh_offset);
        int num_of_symbols = section[symbol_table_index].sh_size / section[symbol_table_index].sh_entsize;
        if (keep_map->degug_mode == 1) {
            printf("Debug: Number of symbols: %d\n", num_of_symbols);
            printf("Debug: Symbol table offset: %d\n", section[symbol_table_index].sh_offset);
        }
        for (int j = 0; j < num_of_symbols; j++) {
            char * section_name;
            if (symbol_table[j].st_shndx == SHN_UNDEF)
                section_name = "UNDEF";
            else if (symbol_table[j].st_shndx == SHN_ABS)
                section_name = "ABS";
            else if (symbol_table[j].st_shndx == SHN_COMMON)
                section_name = "COMMON";
            else if (symbol_table[j].st_shndx == SHN_HIRESERVE)
                section_name = "HIRESERVE";
            else if (symbol_table[j].st_shndx == SHN_LORESERVE)
                section_name = "LORESERVE";
            else if(symbol_table[j].st_shndx == SHN_LOPROC)
                section_name = "LOPROC";
            else if(symbol_table[j].st_shndx == SHN_HIPROC)
                section_name = "HIPROC";
            else
                section_name = string_table + section[symbol_table[j].st_shndx].sh_name;
            printf("[%d] \t %x \t %d \t %s \t %s \n", j, symbol_table[j].st_value, symbol_table[j].st_shndx,
                   section_name, string_table_symbols + symbol_table[j].st_name);
        }
    }
}

int find_string_table(keep_maps *keep_map, int file_index){
    Elf32_Ehdr *header = (Elf32_Ehdr *) keep_map->mmaps[file_index];
    Elf32_Shdr *section = (Elf32_Shdr *) (keep_map->mmaps[file_index] + header->e_shoff);
    Elf32_Shdr *string_table_section = (Elf32_Shdr *) (section + header->e_shstrndx);
    char *string_table = (char *) (keep_map->mmaps[file_index] + string_table_section->sh_offset);
    for(int j = 0; j<header->e_shnum; j++){
        if(strcmp(string_table + section[j].sh_name, ".strtab") == 0){
            return j;
        }
    }
    return -1;
}

int find_symbol_table(keep_maps *keep_map, int file_index){
    Elf32_Ehdr *header = (Elf32_Ehdr *) keep_map->mmaps[file_index];
    Elf32_Shdr *section = (Elf32_Shdr *) (keep_map->mmaps[file_index] + header->e_shoff);
    Elf32_Shdr *string_table_section = (Elf32_Shdr *) (section + header->e_shstrndx);
    char *string_table = (char *) (keep_map->mmaps[file_index] + string_table_section->sh_offset);
    for(int j = 0; j<header->e_shnum; j++){
        if(strcmp(string_table + section[j].sh_name, ".symtab") == 0){
            return j;
        }
    }
    return -1;
}

void check_merge(keep_maps *keep_map){
    if(keep_map->num_of_files != 2){
        printf("You need to load 2 files\n");
        return;
    }
    int num_of_symbols1 = find_num_of_symbolTables(keep_map, 0);
    int num_of_symbols2 = find_num_of_symbolTables(keep_map, 1);
    if(num_of_symbols1 != 1 ||  num_of_symbols2 !=1){
        printf("feature not supported\n");
        return;
    }
    int symbol_table_index_First = find_symbol_table(keep_map, 0);
    int symbol_string_table_index_First = find_string_table(keep_map, 0);
    Elf32_Ehdr *headerFirst = (Elf32_Ehdr *) keep_map->mmaps[0];
    Elf32_Shdr *sectionFirst = (Elf32_Shdr * )(keep_map->mmaps[0] + headerFirst->e_shoff);

    char *string_table_symbols =(char*) keep_map->mmaps[0] + sectionFirst[symbol_string_table_index_First].sh_offset;
    Elf32_Sym *symbol_table_First = (Elf32_Sym * )(keep_map->mmaps[0] + sectionFirst[symbol_table_index_First].sh_offset);
    int num_of_symbols_First = sectionFirst[symbol_table_index_First].sh_size / sectionFirst[symbol_table_index_First].sh_entsize;


    int symbol_table_index_Second = find_symbol_table(keep_map, 1);
    int symbol_string_table_index_Second = find_string_table(keep_map, 1);
    Elf32_Ehdr *headerSecond = (Elf32_Ehdr *) keep_map->mmaps[1];
    Elf32_Shdr *sectionSecond = (Elf32_Shdr * )(keep_map->mmaps[1] + headerSecond->e_shoff);

    char *string_table_symbols_Second =(char*) keep_map->mmaps[1] + sectionSecond[symbol_string_table_index_Second].sh_offset;
    Elf32_Sym *symbol_table_Second = (Elf32_Sym * )(keep_map->mmaps[1] + sectionSecond[symbol_table_index_Second].sh_offset);
    int num_of_symbols_Second = sectionSecond[symbol_table_index_Second].sh_size / sectionSecond[symbol_table_index_Second].sh_entsize;

    for(int i = 1; i<num_of_symbols_First; i++) {
        if(symbol_table_First[i].st_name== 0){
            continue;
        }
        char *symbol_name = string_table_symbols + symbol_table_First[i].st_name;
        int exists_both = 0;
        for (int j = 1; j < num_of_symbols_Second; j++) {
            if(symbol_table_Second[j].st_name == 0){
                continue;
            }
            if (strcmp(symbol_name, string_table_symbols_Second + symbol_table_Second[j].st_name) == 0) {
                exists_both = 1;
                if (symbol_table_First[i].st_shndx != SHN_UNDEF && symbol_table_Second[j].st_shndx != SHN_UNDEF) {
                    printf("Error: symbol %s multiply defined\n", symbol_name);
                } else if (symbol_table_First[i].st_shndx == SHN_UNDEF && symbol_table_Second[j].st_shndx == SHN_UNDEF) {
                    printf("Error: symbol %s undefined\n", symbol_name);
                } else {
                    if (keep_map->degug_mode == 1) {
                        if (symbol_table_First[i].st_shndx == SHN_UNDEF) {
                            printf("Debug: symbol %s is defined in file %s\n", symbol_name, keep_map->file_names[1]);
                        } else {
                            printf("Debug: symbol %s is defined in file %s\n", symbol_name, keep_map->file_names[0]);
                        }
                    }
                }
            }
        }
        if(!exists_both && symbol_table_First[i].st_shndx == SHN_UNDEF){
            printf("Error: symbol %s undefined\n", symbol_name);
        }
    }
    for (int i = 1; i < num_of_symbols_Second; i++) {
        if(symbol_table_Second[i].st_name == 0){
            continue;
        }
        char *symbol_name = string_table_symbols_Second + symbol_table_Second[i].st_name;
        int exists_both = 0;
        for (int j = 1; j < num_of_symbols_First; j++) {
            if(symbol_table_First[j].st_name == 0){
                continue;
            }
            if (strcmp(symbol_name, string_table_symbols + symbol_table_First[j].st_name) == 0) {
                exists_both = 1;
            }
        }
        if(!exists_both && symbol_table_Second[i].st_shndx == SHN_UNDEF) {
            printf("Error: symbol %s undefined\n", symbol_name);
        }
    }
}

int find_num_of_symbolTables(keep_maps *keep_map, int file_index){
    int count = 0;
    Elf32_Ehdr *header = (Elf32_Ehdr *) keep_map->mmaps[file_index];
    Elf32_Shdr *section = (Elf32_Shdr *) (keep_map->mmaps[file_index] + header->e_shoff);
    Elf32_Shdr *string_table_section = (Elf32_Shdr *) (section + header->e_shstrndx);
    char *string_table = (char *) (keep_map->mmaps[file_index] + string_table_section->sh_offset);
    for(int j = 0; j<header->e_shnum; j++){
        if(section[j].sh_type == SHT_SYMTAB){
            count += 1;
        }
    }
    return count;

}

void quit(keep_maps *keep_map){
    for (int i = 0; i < keep_map->num_of_files; i++){
        munmap(keep_map->mmaps[i], keep_map->sizes[i]);
    }
    free(keep_map);
    exit(0);
}

typedef struct fun_desc {
    char *name;
    void (*fun)(keep_maps *);
} fun_desc;

int main(int argc, char **argv) {
    keep_maps *keep_map = (keep_maps *) malloc(sizeof(keep_maps));
    keep_map->degug_mode = 1;
    keep_map->num_of_files = 0;
    fun_desc menu[] = {{"Toggle Debug Mode", debug_mode},
                       {"Examine ELF File", examine_ELF_file},
                       {"Print Section Names", print_section_names},
                          {"Print Symbols", print_symbols},
                       {"Quit", NULL}};

    int menu_size = sizeof(menu) / sizeof(fun_desc) - 1;
    int option;
    while (1) {
        printf("Choose action:\n");
        for (int i = 0; i < menu_size; i++) {
            printf("%d-%s\n", i, menu[i].name);
        }
        printf("Option: ");
        scanf("%d", &option);
        if (option >= 0 && option < menu_size) {
            fgetc(stdin);
            menu[option].fun(keep_map);
        } else {
            printf("Not within bounds\n");
            exit(0);
        }
    }
    free(keep_map);
    return 0;
}





