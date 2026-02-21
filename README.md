# DDoS Detection System

基于 **eBPF/XDP + 规则引擎 + 深度学习时序模型 + Web 展示** 的在线 DDoS 检测系统。核心策略为 **Rule-first + DL-fallback**：
- 规则引擎优先识别常见明确攻击（如 UDP_FLOOD / TCP_SYN_FLOOD / ICMP_FLOOD）
- 对规则不明确的灰区/慢速/未知流量，交由 DL 时序模型判别
- 最终输出写入 `events.jsonl / alerts.jsonl`，并在 Web 页面展示

---

## 目录结构

```
.
├── ebpf/                # XDP/eBPF 流采集（xdp_flow_user / xdp_flow_kern.o）
├── feature/             # 特征提取（1s 窗口统计）
├── rule/                # 规则引擎 + 融合逻辑（rule_engine / fusion_engine）
├── dl/                  # 深度学习模块（数据集处理/训练/推理服务）
├── web/                 # Flask Web Dashboard
├── tools/               # 入库/查询/辅助工具
├── scripts/             # 一键运行脚本
├── models/              # 训练产物（dl_model.pt / dl_scaler.json）
├── logs/                # events.jsonl / alerts.jsonl / events.db
└── data/                # CICDDoS2019 parquet（默认位置）
```

---

## 环境要求

- Linux kernel >= 5.15（eBPF/XDP）
- clang/llvm + libbpf（编译 eBPF）
- Python 3.8+

Python 依赖：
```bash
pip install -r feature/requirements.txt
pip install -r dl/requirements.txt
pip install flask
```

---

## 快速启动（在线检测）

### 1) 编译 eBPF

```bash
cd ebpf
make
```

### 2) 启动 DL 推理服务（可选）

```bash
python3 dl/service/app.py --config dl/config.yaml
```

> 服务默认监听 `0.0.0.0:8001`

### 3) 启动在线 pipeline（规则 + 融合 + DL）

```bash
sudo bash scripts/run_pipeline.sh ens33 --ml
```

- `ens33` 为网卡名，按需替换（可用 `ip a` 查看）
- 若只用规则引擎，可去掉 `--ml`
- 默认仅写 `alerts.jsonl`（attack/suspect），不持久化 benign
- 如需同时写 `events.jsonl`（含 benign 全量窗口），可开启：`WRITE_EVENTS=1 sudo bash scripts/run_pipeline.sh ens33 --ml`

### 4) 启动 Web

```bash
python3 web/app.py
```

浏览器访问：
- http://127.0.0.1:5000

---

## 深度学习训练（离线）

详细说明见 `dl/README.md`，最小流程如下：

### 1) 数据集处理（Parquet → 窗口特征）

```bash
python3 dl/dataset/build_window_dataset.py --config dl/config.yaml
```

输出：
- `dl/data/X.npy`
- `dl/data/y.npy`
- `dl/data/meta.json`

### 1.1) 推荐：从在线流量导出训练集（避免域偏移）

先确保 pipeline 把全量窗口写到 `events`：

```bash
WRITE_EVENTS=1 sudo bash scripts/run_pipeline.sh ens33 --ml
python3 tools/ingest_sqlite.py
```

然后导出在线严格训练集（4 类）：

```bash
python3 tools/export_training_dataset.py \
  --db logs/events.db \
  --table events \
  --mode multiclass \
  --attack-types TCP_SYN_FLOOD,UDP_FLOOD,ICMP_FLOOD \
  --attack-sources rules \
  --benign-sources rules \
  --benign-max-score 0 \
  --output-dir dl/data
```

构建公开数据预训练集（扩展类型候选）：

```bash
python3 dl/dataset/build_public_multiclass_dataset.py \
  --config dl/config.yaml \
  --output-dir dl/data_public \
  --mode full
```

### 2) 训练时序模型（1D-CNN）

```bash
python3 dl/train/train_seq_model.py --config dl/config.yaml
```

输出：
- `models/dl_model.pt`
- `models/dl_scaler.json`
- `models/dl_metrics.json`

---

## 数据入库（SQLite）

将 `events.jsonl / alerts.jsonl` 入库到 `logs/events.db`：

```bash
python3 tools/ingest_sqlite.py --once
```

保留策略（events 仅保留近 7 天，alerts 长期保留）：

```bash
python3 tools/ingest_sqlite.py --events-retention-hours 168
```

可选：benign 下采样（减少 events 表规模）：

```bash
python3 tools/ingest_sqlite.py --benign-sample-rate 0.1
```

---

## 关键配置

- `rule/rules.json`：规则阈值与权重
- `rule/rules.json -> type_rules`：规则直返类型签名（`tcp_syn/udp/icmp + ack/rst + dns/ntp/ssdp/cldap/memcached/snmp`）
- `rule/rules.json -> decision.type_confirm_min`：规则类型确认阈值，命中后直接输出 `attack + 具体类型`
- `rule/rules.json -> decision.gate_*`：低风险门控（多条件 + 抽检 + 冷却期），用于降低 SSH 等正常流量被 DL 误判为 `suspect`
- `dl/config.yaml`：DL 数据/训练/服务参数
- `scripts/run_pipeline.sh`：运行入口（支持 `--ml` 和环境变量 `DL_URL`）

---

## 常见问题

- **DL 端口占用**：
  `ss -ltnp | rg ':8001'` 查进程，结束后重启服务。
- **未看到 DL 输出**：
  pipeline 缓存需要先累积 `T` 个窗口（默认 10）才会调用 DL。
- **events.jsonl / alerts.jsonl 为空**：
  确认 eBPF 程序已编译并在正确网卡上运行。

---

## 参考

- `ebpf/README.md`：eBPF/XDP 编译与运行细节
- `dl/README.md`：深度学习模块完整流程
