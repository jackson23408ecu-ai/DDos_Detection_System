# 系统架构与实验设计

## 1. 系统架构

### 1.1 逻辑分层
- 数据采集层：XDP/eBPF 负责五元组采集与基础统计。
- 特征层：`feature_extractor.py` 输出固定时间窗口统计特征。
- 推理层：规则引擎与深度学习模块执行检测。
- 决策层：融合规则与模型输出并生成事件。
- 展示层：Flask API 与 Dashboard 提供查询和可视化。

### 1.2 融合模式
- Rule-only：仅使用规则阈值与权重打分。
- ML-only：仅使用模型输出作为最终标签。
- Hybrid：规则命中 `attack`/`suspect` 时直接保留告警；其余流量由模型补充判定。

### 1.3 事件字段规范
- `events.jsonl` 固定字段：
  - `ts`
  - `label`
  - `attack_type`
  - `score`
  - `confidence`
  - `reasons`
  - `features`
- 融合决策字段：
  - `decision_source`
  - `final_label`
  - `final_attack_type`
  - `dl_p_attack`
  - `dl_model_version`

### 1.4 稳定性与性能
- 规则决策与告警日志可分表/分文件存储，降低主表增长压力。
- 采集与特征提取之间引入缓冲，减小短时波动影响。
- 输出维持窗口级粒度，避免流级明细导致存储膨胀。

## 2. 实验设计

### 2.1 数据集与划分
- 数据集：CIC-DDoS2019、CIC-IDS2017、UNSW-NB15。
- 划分策略：按时间段或场景划分，避免训练集与测试集样本泄漏。
- 标签体系：`BENIGN` 与细分攻击类型（如 `UDP_FLOOD`、`TCP_SYN_FLOOD`、`ICMP_FLOOD`）。

### 2.2 基线模型
- Rule-only。
- ML-only（1D-CNN 时序模型，二分类或多分类）。
- Hybrid（规则 + 模型融合）。
- 无监督基线（Isolation Forest、One-Class SVM）。

### 2.3 评估指标
- 分类指标：Accuracy、Precision、Recall、F1、ROC-AUC、PR-AUC。
- 检测指标：告警延迟、误报率、漏报率。
- 系统指标：吞吐（pps）、CPU 占用、内存占用。

### 2.4 消融实验
- 去除熵特征（`src_ip_entropy`、`dport_entropy`）。
- 去除 TCP flags 相关特征。
- 调整窗口长度（0.5s / 1s / 2s / 5s）。
- 调整 Top-K 聚合参数（`top_src_ip` / `top_dport`）。

### 2.5 在线评估
- 在受控环境执行 UDP Flood 与 SYN Flood 压测并记录延迟。
- 对比规则与模型在峰值流量下的稳定性、误报率与漏报率。

## 3. 论文实验章节结构
1. 引言：DDoS 检测问题与 eBPF 方案背景。
2. 系统设计：采集、特征、推理与融合流程。
3. 特征工程：窗口统计特征与设计依据。
4. 检测方法：规则引擎、时序模型与融合策略。
5. 实验结果：基线对比、消融与在线评估。
6. 结论：主要结果与后续优化方向。
