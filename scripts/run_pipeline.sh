#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IFACE="ens33"
USE_ML=0
WRITE_EVENTS="${WRITE_EVENTS:-0}"
DL_ONLY=0

for arg in "$@"; do
  case "$arg" in
    --ml)
      USE_ML=1
      ;;
    --dl-only)
      USE_ML=1
      DL_ONLY=1
      ;;
    --write-events|--full)
      WRITE_EVENTS=1
      ;;
    --help|-h)
      echo "Usage: bash scripts/run_pipeline.sh [iface] [--ml] [--write-events] [--dl-only]"
      echo "Env: FEATURE_TOPK=50 (top source/port items kept per window)"
      exit 0
      ;;
    --*)
      echo "Unknown option: $arg" >&2
      exit 1
      ;;
    *)
      IFACE="$arg"
      ;;
  esac
done

if [[ "${ML:-0}" == "1" ]]; then
  USE_ML=1
fi

DL_URL="${DL_URL:-http://127.0.0.1:8001/predict}"
RULES="${ROOT_DIR}/rule/rules.json"
EVENTS="${ROOT_DIR}/logs/events.jsonl"
ALERTS="${ROOT_DIR}/logs/alerts.jsonl"
FEATURE_TOPK="${FEATURE_TOPK:-50}"
FUSION_EXTRA_ARGS=()
if [[ "${DL_ONLY}" == "1" ]]; then
  FUSION_EXTRA_ARGS+=(--dl-only)
fi

mkdir -p "${ROOT_DIR}/logs"

cd "${ROOT_DIR}/ebpf"
if [[ "${USE_ML}" -eq 1 ]]; then
  if [[ "${WRITE_EVENTS}" == "1" ]]; then
    sudo stdbuf -oL -eL ./xdp_flow_user "${IFACE}" 2>/dev/null \
      | python3 -u "${ROOT_DIR}/feature/feature_extractor.py" --topk "${FEATURE_TOPK}" \
      | python3 -u "${ROOT_DIR}/rule/fusion_engine.py" "${RULES}" --fuse --dl-url "${DL_URL}" "${FUSION_EXTRA_ARGS[@]}" \
          --jsonl "${EVENTS}" \
          --persist-benign \
          --alerts "${ALERTS}"
  else
    sudo stdbuf -oL -eL ./xdp_flow_user "${IFACE}" 2>/dev/null \
      | python3 -u "${ROOT_DIR}/feature/feature_extractor.py" --topk "${FEATURE_TOPK}" \
      | python3 -u "${ROOT_DIR}/rule/fusion_engine.py" "${RULES}" --fuse --alerts "${ALERTS}" --dl-url "${DL_URL}" "${FUSION_EXTRA_ARGS[@]}"
  fi
else
  if [[ "${WRITE_EVENTS}" == "1" ]]; then
    sudo stdbuf -oL -eL ./xdp_flow_user "${IFACE}" 2>/dev/null \
      | python3 -u "${ROOT_DIR}/feature/feature_extractor.py" --topk "${FEATURE_TOPK}" \
      | python3 -u "${ROOT_DIR}/rule/fusion_engine.py" "${RULES}" \
          --jsonl "${EVENTS}" \
          --persist-benign \
          --alerts "${ALERTS}"
  else
    sudo stdbuf -oL -eL ./xdp_flow_user "${IFACE}" 2>/dev/null \
      | python3 -u "${ROOT_DIR}/feature/feature_extractor.py" --topk "${FEATURE_TOPK}" \
      | python3 -u "${ROOT_DIR}/rule/fusion_engine.py" "${RULES}" --alerts "${ALERTS}"
  fi
fi
