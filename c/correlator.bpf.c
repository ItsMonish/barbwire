#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define AF_INET     2
#define AF_INET6    10

#define EVENT_OPEN      1
#define EVENT_EXEC      2
#define EVENT_CONNECT   3

struct event {
    // Common for everything
    __u8    type;
    pid_t   pid;
    pid_t   gid;
    __u64   timestamp;
    char    command[32];

    // For open
    char    fname[64];

    // For connnect
    __u16   con_family;
    __u16   con_port;
    __u8    ipv4_addr[4];
    __u8    ipv6_addr[16];

    // For exec
    pid_t   parent;
    pid_t   grant_parent;
    char    p_command[32];
    char    gp_command[32];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 2 << 16);       // 2*64 = 128 KB
} ring_buffer SEC(".maps");
