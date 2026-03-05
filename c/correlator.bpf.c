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
    pid_t   tgid;
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


SEC("tp/syscalls/sys_enter_openat")
int record_open(struct trace_event_raw_sys_enter *ctx) {
    struct event *e = bpf_ringbuf_reserve(&ring_buffer, sizeof(ring_buffer), 0);
    if (!e) return 0;

    __u64 ids = bpf_get_current_pid_tgid();
    e->pid = ids >> 32;
    e->tgid = (__u32)ids;
    e->type = EVENT_OPEN;
    e->timestamp = bpf_ktime_get_ns();

    bpf_get_current_comm(&e->command, sizeof(ring_buffer));

    const char *filename = (const char*)&ctx->args[1];
    bpf_probe_read_user_str(e->fname, sizeof(e->fname), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}


SEC("tp/syscalls/sys_enter_connect")
int record_connect(struct trace_event_raw_sys_enter *ctx) {
    struct event *e = bpf_ringbuf_reserve(&ring_buffer, sizeof(ring_buffer), 0);
    if (!e) return 0;

    __u64 ids = bpf_get_current_pid_tgid();
    e->pid = ids >> 32;
    e->tgid = (__u32)ids;
    e->type = EVENT_CONNECT;
    e->timestamp = bpf_ktime_get_ns();

    struct sockaddr *addr = (struct sockaddr*)ctx->args[1];
    struct sockaddr sa = {};
    bpf_probe_read_user(&sa, sizeof(sa), addr);

    e->con_family = sa.sa_family;

    if(sa.sa_family == AF_INET) {
        struct sockaddr_in ipv4 = {};
        bpf_probe_read_user(&ipv4, sizeof(ipv4), addr);

        e->con_port = ipv4.sin_port;
        __builtin_memcpy(e->ipv4_addr, &ipv4.sin_addr.s_addr, sizeof(e->ipv4_addr));
    } else if(sa.sa_family == AF_INET6) {
        struct sockaddr_in6 ipv6 = {};
        bpf_probe_read_user(&ipv6, sizeof(ipv6), addr);

        e->con_port = ipv6.sin6_port;
        __builtin_memcpy(e->ipv6_addr, &ipv6.sin6_addr, sizeof(e->ipv6_addr));
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
