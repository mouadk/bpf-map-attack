#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdatomic.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <signal.h>

#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_pidfd_getfd
#define SYS_pidfd_getfd 438
#endif
#define BPF_MAP_TYPE_RINGBUF 27
#define MAX_FD_TRY 1024
#define PAGE_SIZE 4096

int pidfd_open(pid_t pid) {
    return syscall(SYS_pidfd_open, pid, 0);
}

int pidfd_getfd(int pidfd, int targetfd) {
    return syscall(SYS_pidfd_getfd, pidfd, targetfd, 0);
}
