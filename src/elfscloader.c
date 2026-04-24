#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

typedef void (*shellcode_fn)(char *output,size_t argc, char **argv, char **envp);

int main(int argc, char **argv, char **envp) {
    if (argc < 3) {
        fprintf(stderr, "usage: elfscloader <shellcode_file> <output> <elfname> [args...]\n");
        return 1;
    }

    const char *filepath = argv[1];

    // Read shellcode from file
    FILE *fp = fopen(filepath, "rb");
    if (!fp) {
        fprintf(stderr, "[x] fopen failed: %s\n", filepath);
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    size_t size = (size_t)ftell(fp);
    fseek(fp, 0, SEEK_SET);

    void *data = malloc(size);
    if (!data) {
        fprintf(stderr, "[x] malloc failed\n");
        fclose(fp);
        return 1;
    }

    size_t nread = fread(data, 1, size, fp);
    fclose(fp);
    if (nread != size) {
        fprintf(stderr, "[x] fread: expected %zu, got %zu\n", size, nread);
        free(data);
        return 1;
    }

    printf("[+] loaded shellcode: %s (%zu bytes)\n", filepath, size);

    // Allocate RWX memory via mmap
    long page_size = sysconf(_SC_PAGESIZE);
    size_t map_size = (size + page_size - 1) & ~(page_size - 1);

    void *sc_addr = mmap(NULL, map_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (sc_addr == MAP_FAILED) {
        fprintf(stderr, "[x] mmap failed\n");
        free(data);
        return 1;
    }

    // Copy shellcode into executable memory
    memcpy(sc_addr, data, size);
    free(data);

    printf("[+] shellcode at: %p\n", sc_addr);
    printf("[+] output: %s\n",argv[2]);
    printf("[+] elfname: %s\n",argv[3]);
    shellcode_fn sc_fn = (shellcode_fn)sc_addr;
    sc_fn(argv[2], (size_t)(argc - 3), argv + 3, envp);

    return 0;
}
