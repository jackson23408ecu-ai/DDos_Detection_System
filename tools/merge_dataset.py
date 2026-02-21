#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--inputs", required=True, help="comma-separated input jsonl files")
    ap.add_argument("--output", required=True, help="output jsonl file")
    args = ap.parse_args()

    inputs = [s.strip() for s in args.inputs.split(",") if s.strip()]
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    total = 0
    with open(out_path, "w", encoding="utf-8") as out:
        for p in inputs:
            path = Path(p)
            if not path.exists():
                print(f"[skip] not found: {path}")
                continue
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    out.write(line)
                    total += 1

    print(f"[ok] wrote {out_path} ({total} rows)")


if __name__ == "__main__":
    main()
