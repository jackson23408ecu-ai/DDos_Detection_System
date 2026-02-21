// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif


/*
 * 事件结构：通过 ringbuf 传到用户态
 * 注意：src_ip/dst_ip、src_port/dst_port 都保持网络字节序，
 * 用户态打印/处理时再 ntohs/inet_ntop
 */
struct flow_event {
    __u64 ts_ns;        // 时间戳（ns）
    __u32 src_ip;       // 源 IP（网络序）
    __u32 dst_ip;       // 目的 IP（网络序）
    __u16 src_port;     // 源端口（网络序）
    __u16 dst_port;     // 目的端口（网络序）
    __u8  proto;        // IPPROTO_TCP / IPPROTO_UDP / IPPROTO_ICMP
    __u8  tcp_flags;    // TCP flags（CWR|ECE|URG|ACK|PSH|RST|SYN|FIN），非 TCP 为 0
    __u16 _pad;         // 对齐
    __u32 pkt_len;      // 包大小：XDP 可见帧长度 data_end - data
};

/* Ring Buffer：高吞吐事件上报，用户态 ring_buffer__poll 读取 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB，可按需调整
} events SEC(".maps");

/* 安全边界检查：确保 (ptr + size) 不越过 data_end */
static __always_inline int ptr_ok(const void *ptr, const void *data_end, __u64 size)
{
    return (const char *)ptr + size <= (const char *)data_end;
}

/*
 * 解析 Ethernet + IPv4，输出：
 * - iph：IPv4 头指针
 * - l4：L4 头起始指针（TCP/UDP）
 */
static __always_inline int parse_eth_ipv4(void *data, void *data_end,
                                          struct iphdr **iph_out,
                                          void **l4_out)
{
    struct ethhdr *eth = data;
    if (!ptr_ok(eth, data_end, sizeof(*eth)))
        return -1;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;

    struct iphdr *iph = (void *)(eth + 1);
    if (!ptr_ok(iph, data_end, sizeof(*iph)))
        return -1;

    /* IPv4 变长头：ihl 单位 4 bytes */
    __u32 ihl_bytes = (__u32)iph->ihl * 4;
    if (ihl_bytes < sizeof(*iph))
        return -1;

    if (!ptr_ok(iph, data_end, ihl_bytes))
        return -1;

    *iph_out = iph;
    *l4_out  = (void *)iph + ihl_bytes;
    return 0;
}

/*
 * XDP 主函数：只采集，不丢包（XDP_PASS）
 */
SEC("xdp")
int xdp_flow_collector(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct iphdr *iph = NULL;
    void *l4 = NULL;

    if (parse_eth_ipv4(data, data_end, &iph, &l4) < 0)
        return XDP_PASS;

    __u8 proto = iph->protocol;
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP && proto != IPPROTO_ICMP)
        return XDP_PASS;

    /* ringbuf 申请事件空间 */
    struct flow_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return XDP_PASS; // ringbuf 满了就丢事件，不影响转发

    /* 公共字段 */
    e->ts_ns   = bpf_ktime_get_ns();
    e->src_ip  = iph->saddr;
    e->dst_ip  = iph->daddr;
    e->proto   = proto;
    e->pkt_len = (__u32)((char *)data_end - (char *)data);

    e->src_port  = 0;
    e->dst_port  = 0;
    e->tcp_flags = 0;
    e->_pad      = 0;

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;

        /* 至少要能读到 tcp 基本头 */
        if (!ptr_ok(tcp, data_end, sizeof(*tcp))) {
            bpf_ringbuf_discard(e, 0);
            return XDP_PASS;
        }

        e->src_port = tcp->source;
        e->dst_port = tcp->dest;

        /*
         * TCP flags 在 TCP header 第 13 字节（offset 13）
         * 这里用字节偏移读取，最直接可靠
         */
        __u8 *p = (__u8 *)tcp;
        if (!ptr_ok(p, data_end, 14)) { // 至少保证 p[13] 可读
            bpf_ringbuf_discard(e, 0);
            return XDP_PASS;
        }
        e->tcp_flags = p[13];

    } else if (proto == IPPROTO_UDP) { // UDP
        struct udphdr *udp = l4;
        if (!ptr_ok(udp, data_end, sizeof(*udp))) {
            bpf_ringbuf_discard(e, 0);
            return XDP_PASS;
        }
        e->src_port = udp->source;
        e->dst_port = udp->dest;
        e->tcp_flags = 0;
    } else { // ICMP
        /* ICMP 无端口字段，保持 0，仅上报 proto=1 供上层统计 */
        if (!ptr_ok(l4, data_end, 1)) {
            bpf_ringbuf_discard(e, 0);
            return XDP_PASS;
        }
        e->src_port = 0;
        e->dst_port = 0;
        e->tcp_flags = 0;
    }

    /* 提交到 ringbuf */
    bpf_ringbuf_submit(e, 0);

    return XDP_PASS;
}
