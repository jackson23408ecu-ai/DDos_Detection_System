# 系统架构与实验设计建议

## 1. 架构优化建议

### 1.1 逻辑分层（保持现有结构，增强可解释与可扩展）
- 数据采集层：XDP/eBPF 负责 5 元组采集与基础统计
- 特征层：feature_extractor.py 输出固定窗口统计特征
- 推理层：Rule 引擎 + ML 模块（可选并行）
- 决策层：融合规则/模型输出，生成事件
- 展示层：Flask + Dashboard

### 1.2 推荐的融合策略（可论文表述）
- Rule-only：当前阈值 + 权重规则
- ML-only：模型输出作为最终标签
- Hybrid：若规则为 attack 或 suspect，则强制保留告警；否则由 ML 提升疑似等级

### 1.3 输出字段规范化
- events.jsonl 推荐固定字段：
  - ts / label / attack_type / score / confidence / reasons / features
  - 决策字段：decision_source / final_label / final_attack_type / dl_p_attack / dl_model_version

### 1.4 稳定性与性能优化
- rule_engine 的 decisions 与告警输出可分文件，避免主表过大
- XDP 采集到特征提取之间可加缓冲（减少波动）
- 输出字段维持“窗口级”粒度，避免流级数据膨胀

## 2. 实验设计建议

### 2.1 数据集与划分
- 公共数据集：CIC-DDoS2019、CIC-IDS2017、UNSW-NB15
- 划分策略：按日期/场景划分，避免同一攻击在训练和测试中泄漏
- 类别：正常流量 / 攻击类型（UDP Flood、SYN Flood、ICMP Flood…）

### 2.2 对比基线
- Rule-only（当前规则）
- ML-only（1D-CNN/时序模型，二分类）
- Hybrid（Rule + ML）
- 传统统计模型（如 Isolation Forest / One-Class SVM）作为无监督对比

### 2.3 指标
- 分类指标：Accuracy / Precision / Recall / F1 / ROC-AUC / PR-AUC
- 检测指标：告警延迟（ms / window）、误报率、漏报率
- 系统指标：吞吐（pps）、CPU / 内存开销

### 2.4 消融实验
- 去掉熵特征（src_ip_entropy / dport_entropy）
- 去掉 TCP flags 类特征
- 不同窗口大小（0.5s / 1s / 2s / 5s）
- 不同 topk（top_src_ip / top_dport）

### 2.5 在线评估
- 在真实环境中执行 UDP Flood / SYN Flood 压测，记录告警延迟
- 对比规则 vs 模型检测的稳定性（高峰期抖动 vs 误报）

## 3. 论文结构建议（快速落地）
1) 引言（DDoS 风险 + eBPF 可行性）
2) 系统架构（图 + 数据路径）
3) 特征设计（说明为什么选）
4) 检测模型（规则 + ML）
5) 实验与评估（指标 + 对比 + 消融）
6) 结论与展望（加入深度模型 / 边缘部署）
