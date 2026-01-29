# DDoS Detection System (eBPF + Feature + Rule Engine + Web)

## Modules
- `ebpf/`: XDP/eBPF flow collector (xdp_flow_user + xdp_flow_kern.o)
- `feature/`: feature extraction from flow events
- `rule/`: rule engine (rules.json) producing label/score/reasons
- `web/`: Flask dashboard (reads events.jsonl)

## Run pipeline (example)
```bash
cd /mnt/hgfs/ubuntushare/DDos_detection_system_1/ebpf
sudo stdbuf -oL -eL ./xdp_flow_user ens33 2>/dev/null \
| python3 -u ../feature/feature_extractor.py \
| python3 -u ../rule/rule_engine.py ../rule/rules.json --jsonl ../logs/events.jsonl
cd /mnt/hgfs/ubuntushare/DDos_detection_system_1
python3 web/app.py
# open http://127.0.0.1:5000
