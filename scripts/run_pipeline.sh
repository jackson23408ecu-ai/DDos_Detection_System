#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IFACE="${1:-ens33}"
USE_ML=0
if [[ "${2:-}" == "--ml" ]] || [[ "${ML:-0}" == "1" ]]; then
  USE_ML=1
fi
DL_URL="${DL_URL:-http://127.0.0.1:8001/predict}"
RULES="${ROOT_DIR}/rule/rules.json"
EVENTS="${ROOT_DIR}/logs/events.jsonl"
ALERTS="${ROOT_DIR}/logs/alerts.jsonl"

mkdir -p "${ROOT_DIR}/logs"

cd "${ROOT_DIR}/ebpf"
if [[ "${USE_ML}" -eq 1 ]]; then
  sudo stdbuf -oL -eL ./xdp_flow_user "${IFACE}" 2>/dev/null \
    | python3 -u "${ROOT_DIR}/feature/feature_extractor.py" \
    | python3 -u "${ROOT_DIR}/rule/fusion_engine.py" "${RULES}" --fuse --dl-url "${DL_URL}" \
        --jsonl "${EVENTS}" \
        --alerts "${ALERTS}"
else
  sudo stdbuf -oL -eL ./xdp_flow_user "${IFACE}" 2>/dev/null \
    | python3 -u "${ROOT_DIR}/feature/feature_extractor.py" \
    | python3 -u "${ROOT_DIR}/rule/fusion_engine.py" "${RULES}" \
        --jsonl "${EVENTS}" \
        --alerts "${ALERTS}"
fi
