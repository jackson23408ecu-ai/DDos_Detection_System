# eBPF XDP Flow Collector

## 功能
- 基于 XDP 的高速流量采集
- 解析 IPv4 + TCP / UDP
- 提取字段：
  - 源 IP / 目的 IP
  - 源端口 / 目的端口
  - 协议
  - TCP flags
  - 包大小
  - 时间戳（ns）

## 技术栈
- eBPF + XDP (generic mode)
- libbpf (CO-RE)
- Ring Buffer 用户态通信

## 运行环境
- Linux kernel >= 5.15
- clang + llvm
- libbpf >= 1.0

## 编译
```bash
make
