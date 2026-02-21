# 深度学习模块（1D-CNN 时序模型）

本目录为“规则优先 + DL 兜底”的时序模型实现，包含数据集处理、训练、推理服务与融合调用。

## 1. 数据集放置

默认读取路径：`data/archive/*.parquet`

如路径不同，请在 `dl/config.yaml` 修改：

- `dataset.input_glob`
- `dataset.window_sec`（默认 1s）

## 2. 数据集处理（窗口特征）

将 CICDDoS2019 的 flow 记录聚合为与在线一致的 1s 窗口特征，输出：
- `dl/data/X.npy`
- `dl/data/y.npy`
- `dl/data/meta.json`

命令：

```bash
python3 dl/dataset/build_window_dataset.py --config dl/config.yaml
```

对齐说明（重要）：
- 若 Parquet 不包含 Source/Destination IP 或 Port 列，则 `uniq_src/uniq_dst/uniq_pair/entropy` 会置为 0，`uniq_flow5` 以窗口内 flow 数量近似。
- 若缺少时间戳列，则使用行号序作为时间轴（窗口聚合依然按顺序进行）。

## 2.1 用在线真实流量重建训练集（推荐）

当 CICDDoS2019 特征分布与实验环境差异较大时，优先使用在线数据重训。

1) 采集并入库（务必包含 benign）：

```bash
WRITE_EVENTS=1 sudo bash scripts/run_pipeline.sh ens33 --ml
python3 tools/ingest_sqlite.py
```

2) 从 `events.db` 导出可训练样本到 `dl/data`：

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

说明：
- 严格集默认丢弃 `SUSPECT` / 未定型 `ATTACK`。
- benign 默认只取 `decision_source=rules` 且 `score<=0` 的窗口。
- `class_names` 会写入 `dl/data/meta.json`，训练时自动读取。

3) 从公开 Parquet 构建多分类预训练集（扩展候选类型）：

```bash
python3 dl/dataset/build_public_multiclass_dataset.py \
  --config dl/config.yaml \
  --output-dir dl/data_public \
  --mode full
```

## 3. 训练（1D-CNN 时序模型）

把 `[N,F]` 组装为 `[N-T+1,T,F]` 并训练，输出：
- `models/dl_model.pt`
- `models/dl_scaler.json`
- `models/dl_metrics.json`

训练流程：公开数据预训练 + 在线严格数据微调（由 `dl/config.yaml` 控制）

命令：

```bash
python3 dl/train/train_seq_model.py --config dl/config.yaml
```

## 4. 推理服务（FastAPI）

启动服务：

```bash
python3 dl/service/app.py --config dl/config.yaml
```

POST `/predict` 输入示例（需满足长度 T，默认 10）：

```json
{
  "seq": [
    {"pps": 1.2, "bps": 3200, "uniq_src": 2, "uniq_flow5": 2, "syn_ratio": 0.1, "syn_only_ratio": 0.0},
    {"pps": 1.3, "bps": 3100, "uniq_src": 2, "uniq_flow5": 2, "syn_ratio": 0.1, "syn_only_ratio": 0.0}
  ]
}
```

返回：

```json
{
  "p_attack": 0.82,
  "label": "attack",
  "attack_type": "UDP_FLOOD",
  "model_version": "20260217-200000",
  "type_probs": {
    "BENIGN": 0.18,
    "UDP_FLOOD": 0.42,
    "TCP_SYN_FLOOD": 0.29,
    "ICMP_FLOOD": 0.11
  },
  "extra_type": "UDP_FLOOD",
  "extra_confidence": 0.42
}
```

## 5. 与主系统集成（Rule-first + DL-fallback）

启动 DL 服务后，使用现有 pipeline：

```bash
DL_URL=http://127.0.0.1:8001/predict \
  bash scripts/run_pipeline.sh <IFACE> --ml
```

融合策略：
- 规则识别到明确攻击（UDP_FLOOD/TCP_SYN_FLOOD/ICMP_FLOOD）且置信度达阈值 → 直接输出
- 其他灰区/慢速/未知 → 调用 DL 推理
- DL 成功 → 写入 `decision_source/final_label/final_attack_type/dl_p_attack/dl_type_probs/dl_extra_type`
- DL 失败/超时 → 回退规则输出

## 6. events/alerts 入库与保留策略

- `events` 表保存全部流量（含 benign），会按保留期自动清理
- `alerts` 表只保存告警，长期保留

示例（保留 24 小时）：

```bash
python3 tools/ingest_sqlite.py --events-retention-hours 24
```

默认保留 7 天（168 小时）：

```bash
python3 tools/ingest_sqlite.py
```

可选：benign 下采样（降低 events 表体量）：

```bash
python3 tools/ingest_sqlite.py --benign-sample-rate 0.1
```

## 7. 常见错误排查

- `model not found`：先运行训练生成 `models/dl_model.pt` + `models/dl_scaler.json`
- `seq length must be T`：在线融合需要累计满 `T` 个窗口（默认 10）
- `no parquet files matched`：检查 `dl/config.yaml` 的 `dataset.input_glob`
- `feature size mismatch`：确认 `dl/data/X.npy` 由当前 `feature_spec.py` 生成
