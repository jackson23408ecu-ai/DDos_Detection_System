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

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static volatile sig_atomic_t exiting = 0;

static void handle_sigint(int signo)
{
    (void)signo;
    exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args)
{
    /* 只打印 debug/info/warn/error 都行；这里全打印 */
    return vfprintf(stderr, format, args);
}

/* 与内核态 struct flow_event 必须完全一致（字段/顺序/对齐） */
struct flow_event {
    __u64 ts_ns;
    __u32 src_ip;     /* 网络序 */
    __u32 dst_ip;     /* 网络序 */
    __u16 src_port;   /* 网络序 */
    __u16 dst_port;   /* 网络序 */
    __u8  proto;
    __u8  tcp_flags;
    __u16 _pad;
    __u32 pkt_len;
};

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;

    if (data_sz < sizeof(struct flow_event)) {
        fprintf(stderr, "short event: data_sz=%zu expected=%zu\n",
                data_sz, sizeof(struct flow_event));
        return 0;
    }

    const struct flow_event *e = (const struct flow_event *)data;

    char ssrc[INET_ADDRSTRLEN], sdst[INET_ADDRSTRLEN];
    struct in_addr a;

    a.s_addr = e->src_ip; /* inet_ntop 直接处理网络序 */
    inet_ntop(AF_INET, &a, ssrc, sizeof(ssrc));
    a.s_addr = e->dst_ip;
    inet_ntop(AF_INET, &a, sdst, sizeof(sdst));

    uint16_t sport = ntohs(e->src_port);
    uint16_t dport = ntohs(e->dst_port);

    const char *p = (e->proto == IPPROTO_TCP) ? "TCP" :
                    (e->proto == IPPROTO_UDP) ? "UDP" :
                    (e->proto == IPPROTO_ICMP) ? "ICMP" : "OTHER";

    printf("event: %s:%u -> %s:%u proto=%s(%u) flags=0x%02x pkt_len=%u ts=%" PRIu64 "\n",
           ssrc, sport, sdst, dport,
           p, (unsigned)e->proto, (unsigned)e->tcp_flags,
           (unsigned)e->pkt_len, (uint64_t)e->ts_ns);

    return 0;
}

int main(int argc, char **argv)
{
    const char *ifname = NULL;
    int ifindex = 0;
    int err = 0;

    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;

    struct ring_buffer *rb = NULL;
    int map_fd = -1;

    int verbose = 0;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <ifname> [-v]\nExample: %s ens33 -v\n",
                argv[0], argv[0]);
        return 1;
    }

    ifname = argv[1];
    if (argc >= 3 && strcmp(argv[2], "-v") == 0)
        verbose = 1;

    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "if_nametoindex(%s) failed: %s\n", ifname, strerror(errno));
        return 1;
    }

    /* libbpf 设置 */
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    if (verbose)
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
        /* 常见：-EPERM/-EACCES 权限；-EINVAL verifier/BTF；-ENOENT 文件/段 */
        fprintf(stderr, "bpf_object__load failed: %d (%s)\n", err, strerror(-err));
        goto cleanup;
    }

    /* 3) 找到 xdp 程序（SEC("xdp") 对应的函数名） */
    prog = bpf_object__find_program_by_name(obj, "xdp_flow_collector");
    if (!prog) {
        fprintf(stderr, "find program 'xdp_flow_collector' failed\n");
        err = -ENOENT;
        goto cleanup;
    }

    /* 4) attach 到网卡 XDP
       注意：如果 ens33 已经挂了其它 XDP，这里会失败。
       你可以先执行：sudo ip link set dev ens33 xdp off  解除旧的
    */
    link = bpf_program__attach_xdp(prog, ifindex);
    if (!link) {
        err = -errno;
        fprintf(stderr, "attach xdp failed: %d (%s)\n", err, strerror(-err));
        fprintf(stderr, "Hint: if XDP already attached, run: sudo ip link set dev %s xdp off\n", ifname);
        goto cleanup;
    }

    printf("Attached XDP program to %s (ifindex=%d)\n", ifname, ifindex);

    /* 5) 找到 ringbuf map，并创建 reader */
    map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) {
        fprintf(stderr, "find map 'events' failed: %d\n", map_fd);
        err = map_fd;
        goto cleanup;
    }

    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        err = -errno;
        fprintf(stderr, "ring_buffer__new failed: %d (%s)\n", err, strerror(-err));
        goto cleanup;
    }

    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);

    printf("Polling events... Press Ctrl+C to stop.\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 200 /* ms */);
        if (err == -EINTR) {
            break;
        } else if (err < 0) {
            fprintf(stderr, "ring_buffer__poll error: %d (%s)\n", err, strerror(-err));
            break;
        }
        /* err==0: timeout 无事件 */
    }

cleanup:
    if (rb)
        ring_buffer__free(rb);
    if (link)
        bpf_link__destroy(link);
    if (obj)
        bpf_object__close(obj);

    printf("Exiting.\n");
    return err ? 1 : 0;
}
