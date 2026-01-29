#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IFACE="${1:-ens33}"
RULES="${ROOT_DIR}/rule/rules.json"
EVENTS="${ROOT_DIR}/logs/events.jsonl"
ALERTS="${ROOT_DIR}/logs/alerts.jsonl"

mkdir -p "${ROOT_DIR}/logs"

cd "${ROOT_DIR}/ebpf"
sudo stdbuf -oL -eL ./xdp_flow_user "${IFACE}" 2>/dev/null \
  | python3 -u "${ROOT_DIR}/feature/feature_extractor.py" \
  | python3 -u "${ROOT_DIR}/rule/rule_engine.py" "${RULES}" \
      --jsonl "${EVENTS}" \
      --alerts "${ALERTS}"
