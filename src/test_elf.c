#include <stdio.h>
#include <unistd.h>
#include <elf.h>
#include <stdint.h>

int main(int argc, char **argv, char **envp) {
    printf("argc = %d\n", argc);
    for (int i = 0; i < argc; i++)
        printf("argv[%d] = %s\n", i, argv[i]);
    printf("cwd = %s\n",getcwd(NULL,0));
    // Find auxv by skipping past argv and envp
    while (*envp) envp++;
    envp++; // skip NULL

    Elf64_auxv_t *auxv = (Elf64_auxv_t *)envp;
    for (; auxv->a_type != AT_NULL; auxv++) {
        const char *name = "UNKNOWN";
        switch (auxv->a_type) {
            case AT_PHDR: name = "AT_PHDR"; break;
            case AT_PHNUM: name = "AT_PHNUM"; break;
            case AT_PHENT: name = "AT_PHENT"; break;
            case AT_PAGESZ: name = "AT_PAGESZ"; break;
            case AT_ENTRY: name = "AT_ENTRY"; break;
            case AT_RANDOM: name = "AT_RANDOM"; break;
            case AT_SYSINFO_EHDR: name = "AT_SYSINFO_EHDR"; break;
            case AT_SYSINFO: name = "AT_SYSINFO"; break;
            case AT_UID: name = "AT_UID"; break;
            case AT_EUID: name = "AT_EUID"; break;
            case AT_GID: name = "AT_GID"; break;
            case AT_EGID: name = "AT_EGID"; break;
            case AT_CLKTCK: name = "AT_CLKTCK"; break;
            case AT_HWCAP: name = "AT_HWCAP"; break;
            case AT_FLAGS: name = "AT_FLAGS"; break;
            case AT_BASE: name = "AT_BASE"; break;
            case AT_SECURE: name = "AT_SECURE"; break;
        }
        printf("auxv: %-15s type=%3lu val=0x%lx\n", name, (unsigned long)auxv->a_type, (unsigned long)auxv->a_un.a_val);
    }
    printf("auxv: AT_NULL\n");
    return 0;
}