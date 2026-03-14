#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
import time
import math
import argparse
from collections import Counter
from typing import Optional

UDP_AMP_PORTS = {
    53: "udp_dns",
    123: "udp_ntp",
    161: "udp_snmp",
    389: "udp_cldap",
    1900: "udp_ssdp",
    11211: "udp_memcached",
}

CHANNEL_ORDER = [
    "tcp_syn",
    "tcp_ack",
    "tcp_rst",
    "udp_generic",
    "udp_dns",
    "udp_ntp",
    "udp_ssdp",
    "udp_cldap",
    "udp_memcached",
    "udp_snmp",
    "icmp",
]

def safe_json_loads(line: str):
    line = line.strip()
    if not line:
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        # 兼容上游混入日志/非JSON
        return None

def shannon_entropy(counter: Counter) -> float:
    """Shannon entropy in bits."""
    total = sum(counter.values())
    if total <= 0:
        return 0.0
    ent = 0.0
    for c in counter.values():
        if c <= 0:
            continue
        p = c / total
        ent -= p * math.log2(p)
    return ent

def mean_var_from_counter(counter: Counter):
    """Return (mean, var) of values in counter interpreted as samples (value=key, count=occurrence)."""
    total = sum(counter.values())
    if total <= 0:
        return 0.0, 0.0
    mean = sum(v * c for v, c in counter.items()) / total
    var = sum(((v - mean) ** 2) * c for v, c in counter.items()) / total
    return mean, var

class FlowWindowAgg:
    def __init__(self, topk=5):
        self.topk = topk
        self.reset()

    def reset(self):
        self.pkt_cnt = 0
        self.byte_cnt = 0

        self.src_ip_cnt = Counter()
        self.dst_ip_cnt = Counter()
        self.pair_cnt = Counter()      # (src,dst)
        self.flow5_cnt = Counter()     # (src,dst,sport,dport,proto)

        self.proto_cnt = Counter()
        self.dst_port_cnt = Counter()
        self.src_port_cnt = Counter()

        self.pkt_len_cnt = Counter()

        # tcp flags
        self.tcp_cnt = 0
        self.syn = 0
        self.ack = 0
        self.fin = 0
        self.rst = 0
        self.psh = 0
        self.urg = 0

        # tcp syn-only(仅SYN无ACK)等
        self.syn_only = 0
        self.ack_only = 0
        self.syn_ack = 0
        self.rst_any = 0

    def update(self, e: dict):
        # 期望输入：{"ts_ns":..., "src_ip":"1.2.3.4", "dst_ip":"...", "sport":123, "dport":80, "proto":6, "tcp_flags":16, "pkt_len":66}
        src = e.get("src_ip")
        dst = e.get("dst_ip")
        if not src or not dst:
            return

        sport = int(e.get("sport", 0))
        dport = int(e.get("dport", 0))
        proto = int(e.get("proto", 0))
        flags = int(e.get("tcp_flags", 0))
        pkt_len = int(e.get("pkt_len", 0))

        self.pkt_cnt += 1
        self.byte_cnt += max(pkt_len, 0)

        self.src_ip_cnt[src] += 1
        self.dst_ip_cnt[dst] += 1
        self.pair_cnt[(src, dst)] += 1
        self.flow5_cnt[(src, dst, sport, dport, proto)] += 1

        self.proto_cnt[proto] += 1
        self.dst_port_cnt[dport] += 1
        self.src_port_cnt[sport] += 1

        if pkt_len > 0:
            self.pkt_len_cnt[pkt_len] += 1

        if proto == 6:  # TCP
            self.tcp_cnt += 1
            # TCP flags: URG 0x20 ACK 0x10 PSH 0x08 RST 0x04 SYN 0x02 FIN 0x01
            if flags & 0x02: self.syn += 1
            if flags & 0x10: self.ack += 1
            if flags & 0x01: self.fin += 1
            if flags & 0x04: self.rst += 1
            if flags & 0x08: self.psh += 1
            if flags & 0x20: self.urg += 1

            syn = bool(flags & 0x02)
            ack = bool(flags & 0x10)
            rst = bool(flags & 0x04)

            if syn and (not ack) and (not rst):
                self.syn_only += 1
            if ack and (not syn) and (not rst):
                self.ack_only += 1
            if syn and ack:
                self.syn_ack += 1
            if rst:
                self.rst_any += 1

    def summarize(self, win_start_ns: int, win_end_ns: int) -> dict:
        dur = max((win_end_ns - win_start_ns) / 1e9, 1e-9)
        pps = self.pkt_cnt / dur
        bps = self.byte_cnt / dur

        uniq_src = len(self.src_ip_cnt)
        uniq_dst = len(self.dst_ip_cnt)
        uniq_pair = len(self.pair_cnt)
        uniq_flow5 = len(self.flow5_cnt)

        # 熵：源IP、目的IP、目的端口（用于DDoS异常）
        src_ip_entropy = shannon_entropy(self.src_ip_cnt)
        dst_ip_entropy = shannon_entropy(self.dst_ip_cnt)
        dport_entropy = shannon_entropy(self.dst_port_cnt)

        # 包长统计（均值/方差）
        pktlen_mean, pktlen_var = mean_var_from_counter(self.pkt_len_cnt)

        tcp_cnt = self.tcp_cnt
        syn_ratio = (self.syn / tcp_cnt) if tcp_cnt else 0.0
        ack_ratio = (self.ack / tcp_cnt) if tcp_cnt else 0.0
        rst_ratio = (self.rst / tcp_cnt) if tcp_cnt else 0.0
        syn_only_ratio = (self.syn_only / tcp_cnt) if tcp_cnt else 0.0

        # TopK
        top_src = self.src_ip_cnt.most_common(self.topk)
        top_dst = self.dst_ip_cnt.most_common(self.topk)
        top_dport = self.dst_port_cnt.most_common(self.topk)

        # 典型DDoS强特征：每源IP平均包数、每目的平均包数
        avg_pkts_per_src = (self.pkt_cnt / uniq_src) if uniq_src else 0.0
        avg_pkts_per_dst = (self.pkt_cnt / uniq_dst) if uniq_dst else 0.0

        return {
            "window_start_ns": win_start_ns,
            "window_end_ns": win_end_ns,
            "window_sec": round(dur, 6),

            # 基本强度
            "pkt_cnt": self.pkt_cnt,
            "byte_cnt": self.byte_cnt,
            "pps": round(pps, 3),
            "bps": round(bps, 3),

            # 多样性/扩散程度
            "uniq_src": uniq_src,
            "uniq_dst": uniq_dst,
            "uniq_pair": uniq_pair,
            "uniq_flow5": uniq_flow5,
            "avg_pkts_per_src": round(avg_pkts_per_src, 6),
            "avg_pkts_per_dst": round(avg_pkts_per_dst, 6),

            # 熵（越高越“分散”，越低越“集中”）
            "src_ip_entropy": round(src_ip_entropy, 6),
            "dst_ip_entropy": round(dst_ip_entropy, 6),
            "dport_entropy": round(dport_entropy, 6),

            # 协议分布
            "proto_cnt": {str(k): v for k, v in self.proto_cnt.items()},   # 如 {"6":xxx, "17":xxx, "1":xxx}

            # 包长统计
            "pktlen_mean": round(pktlen_mean, 6),
            "pktlen_var": round(pktlen_var, 6),

            # TCP flags 统计（用于 SYN flood / ACK flood / RST 异常）
            "tcp_cnt": tcp_cnt,
            "tcp_syn": self.syn,
            "tcp_ack": self.ack,
            "tcp_rst": self.rst,
            "tcp_fin": self.fin,
            "tcp_psh": self.psh,
            "tcp_urg": self.urg,
            "syn_ratio": round(syn_ratio, 6),
            "ack_ratio": round(ack_ratio, 6),
            "rst_ratio": round(rst_ratio, 6),
            "syn_only_ratio": round(syn_only_ratio, 6),
            "syn_only": self.syn_only,
            "ack_only": self.ack_only,
            "syn_ack": self.syn_ack,
            "rst_any": self.rst_any,

            # TopK（便于调试/可视化/论文展示）
            "top_src_ip": top_src,      # [["1.2.3.4", 120], ...]
            "top_dst_ip": top_dst,
            "top_dport": top_dport,     # [[80, 500], [22, 100], ...]
        }


def classify_channel(e: dict) -> Optional[str]:
    proto = int(e.get("proto", 0) or 0)
    flags = int(e.get("tcp_flags", 0) or 0)
    dport = int(e.get("dport", 0) or 0)

    if proto == 6:
        syn = bool(flags & 0x02)
        ack = bool(flags & 0x10)
        rst = bool(flags & 0x04)
        if syn and (not ack) and (not rst):
            return "tcp_syn"
        if ack and (not syn) and (not rst):
            return "tcp_ack"
        if rst:
            return "tcp_rst"
        return None

    if proto == 17:
        return UDP_AMP_PORTS.get(dport, "udp_generic")

    if proto == 1:
        return "icmp"

    return None


def channel_meta(channel: str) -> dict:
    if channel.startswith("tcp_"):
        proto = 6
        family = "tcp"
    elif channel.startswith("udp_"):
        proto = 17
        family = "udp"
    elif channel == "icmp":
        proto = 1
        family = "icmp"
    else:
        proto = 0
        family = "other"

    return {
        "split_scope": "channel",
        "split_channel": channel,
        "split_family": family,
        "split_proto": proto,
    }


def global_meta() -> dict:
    return {
        "split_scope": "global",
        "split_channel": "global",
        "split_family": "all",
        "split_proto": 0,
    }


def sort_channels(channels):
    order = {name: idx for idx, name in enumerate(CHANNEL_ORDER)}
    return sorted(channels, key=lambda name: (order.get(name, len(order)), name))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--window", type=float, default=1.0, help="window size in seconds")
    ap.add_argument("--topk", type=int, default=20, help="top-k items to output")
    ap.add_argument("--out", type=str, default="", help="optional output jsonl file path")
    args = ap.parse_args()

    window_ns = int(args.window * 1e9)
    out_path = args.out.strip()

    global_agg = FlowWindowAgg(topk=args.topk)
    aggs = {}

    win_start = None
    win_end = None

    def emit(obj):
        s = json.dumps(obj, ensure_ascii=False)
        print(s, flush=True)
        if out_path:
            with open(out_path, "a", encoding="utf-8") as f:
                f.write(s + "\n")

    def emit_window(start_ns: int, end_ns: int):
        if global_agg.pkt_cnt > 0:
            obj = global_agg.summarize(start_ns, end_ns)
            obj.update(global_meta())
            emit(obj)
        for channel in sort_channels(aggs.keys()):
            agg = aggs.get(channel)
            if not agg or agg.pkt_cnt <= 0:
                continue
            obj = agg.summarize(start_ns, end_ns)
            obj.update(channel_meta(channel))
            emit(obj)

    for line in sys.stdin:
        e = safe_json_loads(line)
        if not e:
            continue

        ts_ns = e.get("ts_ns")
        if ts_ns is None:
            ts_ns = int(time.time() * 1e9)
        else:
            ts_ns = int(ts_ns)

        if win_start is None:
            win_start = ts_ns
            win_end = win_start + window_ns

        while ts_ns >= win_end:
            emit_window(win_start, win_end)
            global_agg = FlowWindowAgg(topk=args.topk)
            aggs = {}
            win_start = win_end
            win_end = win_start + window_ns

        global_agg.update(e)
        channel = classify_channel(e)
        if channel is None:
            continue
        agg = aggs.get(channel)
        if agg is None:
            agg = FlowWindowAgg(topk=args.topk)
            aggs[channel] = agg
        agg.update(e)

    # stdin结束，输出最后一个窗口（可选）
    if win_start is not None:
        emit_window(win_start, win_end)

if __name__ == "__main__":
    main()
