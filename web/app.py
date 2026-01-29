#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, json, time
from pathlib import Path
from flask import Flask, jsonify, request, Response, send_from_directory

ROOT = Path(__file__).resolve().parents[1]  # 项目根目录
DEFAULT_ALERTS = ROOT / "logs" / "alerts.jsonl"
DEFAULT_EVENTS = ROOT / "logs" / "events.jsonl"

app = Flask(__name__, static_folder="static", static_url_path="/static")

def tail_jsonl(path: Path, max_lines: int = 200):
    if not path.exists():
        return []
    # 简单实现：读全文件最后 N 行（文件很大时可优化为倒读）
    with open(path, "rb") as f:
        data = f.read().splitlines()[-max_lines:]
    out = []
    for b in data:
        try:
            out.append(json.loads(b.decode("utf-8", errors="ignore")))
        except Exception:
            continue
    return out

@app.get("/")
def index():
    return send_from_directory("static", "index.html")

@app.get("/api/alerts")
def api_alerts():
    path = Path(request.args.get("path", str(DEFAULT_ALERTS)))
    limit = int(request.args.get("limit", "200"))
    return jsonify(tail_jsonl(path, limit))

@app.get("/api/events")
def api_events():
    path = Path(request.args.get("path", str(DEFAULT_EVENTS)))
    limit = int(request.args.get("limit", "200"))
    return jsonify(tail_jsonl(path, limit))

@app.get("/api/stream")
def api_stream():
    """
    SSE：浏览器实时接收新增告警
    用法：/api/stream?path=.../logs/alerts.jsonl
    """
    path = Path(request.args.get("path", str(DEFAULT_ALERTS)))
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.touch()

    def gen():
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            # 从文件末尾开始追
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if line:
                    line = line.strip()
                    if not line:
                        continue
                    yield f"data: {line}\n\n"
                else:
                    time.sleep(0.2)

    return Response(gen(), mimetype="text/event-stream")

if __name__ == "__main__":
    # 0.0.0.0 方便你在宿主机访问（如果网络允许）
    app.run(host="0.0.0.0", port=5000, debug=True)
