#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="source events.jsonl")
    ap.add_argument("--output", required=True, help="output labeled benign jsonl")
    args = ap.parse_args()

    in_path = Path(args.input)
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    cnt = 0
    with open(in_path, "r", encoding="utf-8") as f, open(out_path, "w", encoding="utf-8") as out:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            features = obj.get("features", obj)
            out_obj = {
                "label": "benign",
                "attack_type": "BENIGN",
                "features": features,
            }
            out.write(json.dumps(out_obj, ensure_ascii=False) + "\n")
            cnt += 1

    print(f"[ok] wrote {out_path} ({cnt} rows)")


if __name__ == "__main__":
    main()
