// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <stdarg.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static volatile sig_atomic_t exiting = 0;

static void handle_sigint(int signo)
{
    (void)signo;
    exiting = 1;
}

/* 与内核态 struct flow_event 必须完全一致（字段/顺序/对齐） */
struct flow_event {
    __u64 ts_ns;
    __u32 src_ip;      /* network byte order */
    __u32 dst_ip;      /* network byte order */
    __u16 src_port;    /* network byte order */
    __u16 dst_port;    /* network byte order */
    __u8  proto;
    __u8  tcp_flags;
    __u16 _pad;
    __u32 pkt_len;
};

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args)
{
    /* 只把 libbpf 的日志打到 stderr，避免污染 stdout 的 JSON */
    if (level == LIBBPF_DEBUG) {
        /* 你不想看 debug 可以直接 return 0; */
        return vfprintf(stderr, format, args);
    }
    return vfprintf(stderr, format, args);
}

/* ringbuf 回调：每收到一个事件就会调用一次 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;

    if (data_sz < sizeof(struct flow_event)) {
        fprintf(stderr, "short event: data_sz=%zu expected=%zu\n",
                data_sz, sizeof(struct flow_event));
        return 0;
    }

    const struct flow_event *e = (const struct flow_event *)data;

    char ssrc[INET_ADDRSTRLEN] = {0};
    char sdst[INET_ADDRSTRLEN] = {0};
    struct in_addr a;

    a.s_addr = e->src_ip;  /* network order */
    inet_ntop(AF_INET, &a, ssrc, sizeof(ssrc));
    a.s_addr = e->dst_ip;
    inet_ntop(AF_INET, &a, sdst, sizeof(sdst));

    uint16_t sport = ntohs(e->src_port);
    uint16_t dport = ntohs(e->dst_port);

    /* stdout 只输出 JSON，便于管道给 Python */
    printf("{"
           "\"ts_ns\":%" PRIu64 ","
           "\"src_ip\":\"%s\","
           "\"dst_ip\":\"%s\","
           "\"sport\":%u,"
           "\"dport\":%u,"
           "\"proto\":%u,"
           "\"tcp_flags\":%u,"
           "\"pkt_len\":%u"
           "}\n",
           (uint64_t)e->ts_ns,
           ssrc, sdst,
           (unsigned)sport, (unsigned)dport,
           (unsigned)e->proto,
           (unsigned)e->tcp_flags,
           (unsigned)e->pkt_len);

    /* 确保管道实时刷新 */
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv)
{
    const char *ifname;
    int ifindex, err;

    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;
    struct ring_buffer *rb = NULL;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <ifname>\nExample: %s ens33\n", argv[0], argv[0]);
        return 1;
    }

    ifname = argv[1];
    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "if_nametoindex(%s) failed: %s\n", ifname, strerror(errno));
        return 1;
    }

    /* libbpf 设置：严格模式 + 日志输出到 stderr */
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    /* 1) 打开 BPF 对象 */
    obj = bpf_object__open_file("xdp_flow_kern.o", NULL);
    if (!obj) {
        fprintf(stderr, "bpf_object__open_file failed\n");
        return 1;
    }

    /* 2) 加载到内核 */
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "bpf_object__load failed: %d (%s)\n", err, strerror(-err));
        goto cleanup;
    }

    /* 3) 找到 xdp 程序 */
    prog = bpf_object__find_program_by_name(obj, "xdp_flow_collector");
    if (!prog) {
        fprintf(stderr, "find program 'xdp_flow_collector' failed\n");
        goto cleanup;
    }

    /* 4) 挂载 XDP */
    link = bpf_program__attach_xdp(prog, ifindex);
    if (!link) {
        fprintf(stderr, "attach xdp failed: if=%s (ifindex=%d)\n", ifname, ifindex);
        goto cleanup;
    }

    fprintf(stderr, "Attached XDP program to %s (ifindex=%d)\n", ifname, ifindex);

    /* 5) 找到 ringbuf map */
    int map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) {
        fprintf(stderr, "find map 'events' failed: %d\n", map_fd);
        goto cleanup;
    }

    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "ring_buffer__new failed\n");
        goto cleanup;
    }

    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);

    fprintf(stderr, "Polling events... (stdout is JSON) Ctrl+C to stop.\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 200 /* ms */);
        if (err == -EINTR)
            break;
        if (err < 0) {
            fprintf(stderr, "ring_buffer__poll error: %d\n", err);
            break;
        }
    }

cleanup:
    if (rb)
        ring_buffer__free(rb);
    if (link)
        bpf_link__destroy(link);
    if (obj)
        bpf_object__close(obj);

    fprintf(stderr, "Exiting.\n");
    return err < 0 ? 1 : 0;
}
