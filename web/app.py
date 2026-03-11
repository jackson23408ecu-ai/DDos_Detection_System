#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, json, time, sqlite3
from collections import defaultdict
from pathlib import Path
from flask import Flask, jsonify, request, Response, send_from_directory

ROOT = Path(__file__).resolve().parents[1]  # 项目根目录
DEFAULT_ALERTS = ROOT / "logs" / "alerts.jsonl"
DEFAULT_EVENTS = ROOT / "logs" / "events.jsonl"
DEFAULT_DB = ROOT / "logs" / "events.db"
RULES_JSON = ROOT / "rule" / "rules.json"

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


def get_db(path: Path):
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    return conn


def init_feedback_table(db_path: Path):
    conn = get_db(db_path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS feedback (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              event_id INTEGER,
              kind TEXT,
              note TEXT,
              ts REAL
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_feedback_ts ON feedback(ts);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_feedback_kind ON feedback(kind);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_feedback_event ON feedback(event_id);")
        conn.commit()
    finally:
        conn.close()


def _safe_json_loads(s, fallback):
    try:
        return json.loads(s) if s else fallback
    except Exception:
        return fallback


def _row_get(row, key, default=None):
    try:
        if key in row.keys():
            v = row[key]
            return default if v is None else v
    except Exception:
        return default
    return default


def _normalize_attack_type(label: str, attack_type: str) -> str:
    label = str(label or "").strip().lower()
    attack_type = str(attack_type or "").strip().upper()
    if label == "suspect":
        return "SUSPECT"
    if attack_type in ("", "ATTACK", "BENIGN"):
        return "UNKNOWN"
    return attack_type


def _parse_pair_list(raw):
    data = _safe_json_loads(raw, [])
    if not isinstance(data, list):
        return []
    out = []
    for item in data:
        if not isinstance(item, (list, tuple)) or len(item) < 2:
            continue
        k = str(item[0]).strip()
        if not k:
            continue
        try:
            v = float(item[1] or 0.0)
        except Exception:
            v = 0.0
        out.append((k, v))
    return out


def _merge_pairs(dst: dict, pairs):
    for k, v in pairs:
        dst[k] = float(dst.get(k, 0.0)) + float(v)


def _top_pairs(src: dict, topn: int):
    return [[k, round(v, 3)] for k, v in sorted(src.items(), key=lambda x: x[1], reverse=True)[:topn]]


def _build_event_filters(table: str, label: str, attack_type: str):
    where = []
    params = []
    if label:
        where.append("COALESCE(final_label, label) = ?")
        params.append(label)
    if attack_type:
        where.append("COALESCE(final_attack_type, attack_type) = ?")
        params.append(attack_type)
    if not where and table == "alerts":
        where.append("COALESCE(final_label, label) IN ('attack','suspect')")
    return where, params


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
    # default to alerts-only feed for better performance and cleaner view
    path = Path(request.args.get("path", str(DEFAULT_ALERTS)))
    limit = int(request.args.get("limit", "200"))
    return jsonify(tail_jsonl(path, limit))


@app.get("/api/events_db")
def api_events_db():
    path = Path(request.args.get("db", str(DEFAULT_DB)))
    table = str(request.args.get("table", "alerts")).strip().lower()
    if table not in ("events", "alerts"):
        table = "alerts"
    limit = int(request.args.get("limit", "200"))
    offset = int(request.args.get("offset", "0"))
    label = request.args.get("label", "").strip()
    attack_type = request.args.get("attack_type", "").strip()

    where, params = _build_event_filters(table, label, attack_type)

    sql = f"SELECT * FROM {table}"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY ts DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    conn = get_db(path)
    try:
        try:
            rows = conn.execute(sql, params).fetchall()
        except sqlite3.OperationalError:
            rows = []
    finally:
        conn.close()

    out = []
    for r in rows:
        out.append(
            {
                "id": r["id"],
                "ts": r["ts"],
                "label": r["label"],
                "attack_type": r["attack_type"],
                "final_label": _row_get(r, "final_label", r["label"]),
                "final_attack_type": _row_get(r, "final_attack_type", r["attack_type"]),
                "decision_source": _row_get(r, "decision_source", "rules"),
                "dl_p_attack": _row_get(r, "dl_p_attack"),
                "dl_model_version": _row_get(r, "dl_model_version"),
                "dl_error": _row_get(r, "dl_error"),
                "dl_type_probs": _safe_json_loads(_row_get(r, "dl_type_probs"), {}),
                "dl_extra_type": _row_get(r, "dl_extra_type"),
                "dl_extra_confidence": _row_get(r, "dl_extra_confidence"),
                "score": r["score"],
                "confidence": r["confidence"],
                "reasons": _safe_json_loads(r["reasons"], []),
                "features": _safe_json_loads(r["features"], {}),
            }
        )

    return jsonify(out)


@app.get("/api/events_segment")
def api_events_segment():
    path = Path(request.args.get("db", str(DEFAULT_DB)))
    table = str(request.args.get("table", "alerts")).strip().lower()
    if table not in ("events", "alerts"):
        table = "alerts"
    total_table = str(request.args.get("total_table", "events")).strip().lower()
    if total_table not in ("events", "alerts"):
        total_table = table
    minutes = int(request.args.get("minutes", "60"))
    bucket_sec = int(request.args.get("bucket_sec", "5"))
    limit = int(request.args.get("limit", "300"))
    topn = int(request.args.get("topn", "5"))
    label = request.args.get("label", "").strip()
    attack_type = request.args.get("attack_type", "").strip()
    since_ts = time.time() - (minutes * 60)

    where, params = _build_event_filters(table, label, attack_type)
    sql = (
        f"SELECT ts, label, attack_type, final_label, final_attack_type, decision_source, "
        f"pps, bps, uniq_src, uniq_flow5, top_src_ip, top_dport, features "
        f"FROM {table}"
    )
    if where:
        sql += " WHERE " + " AND ".join(where) + " AND ts >= ?"
    else:
        sql += " WHERE ts >= ?"
    params.append(since_ts)
    sql += " ORDER BY ts ASC"

    conn = get_db(path)
    try:
        try:
            rows = conn.execute(sql, params).fetchall()
        except sqlite3.OperationalError:
            rows = []
        try:
            total_rows = conn.execute(
                f"SELECT ts, features FROM {total_table} WHERE ts >= ? ORDER BY ts ASC",
                (since_ts,),
            ).fetchall()
        except sqlite3.OperationalError:
            total_rows = []
    finally:
        conn.close()

    total_pkt_by_bucket = defaultdict(float)
    for r in total_rows:
        ts = float(r["ts"] or 0.0)
        bucket = int(ts // bucket_sec) * bucket_sec
        features = _safe_json_loads(r["features"], {})
        pkt_cnt = float((features.get("pkt_cnt", 0.0) if isinstance(features, dict) else 0.0) or 0.0)
        total_pkt_by_bucket[bucket] += pkt_cnt

    buckets = {}
    for r in rows:
        ts = float(r["ts"] or 0.0)
        bucket = int(ts // bucket_sec) * bucket_sec
        item = buckets.setdefault(
            bucket,
            {
                "ts": bucket,
                "bucket_start": bucket,
                "bucket_end": bucket + bucket_sec,
                "window_count": 0,
                "alert_count": 0,
                "attack_count": 0,
                "suspect_count": 0,
                "total_pkt_sum": 0.0,
                "alert_pkt_sum": 0.0,
                "pps_sum": 0.0,
                "bps_sum": 0.0,
                "pps_peak": 0.0,
                "bps_peak": 0.0,
                "uniq_src_max": 0,
                "uniq_flow5_max": 0,
                "uniq_src_sum": 0,
                "type_cnt": defaultdict(int),
                "source_cnt": defaultdict(int),
                "top_src_map": {},
                "top_dport_map": {},
            },
        )

        item["window_count"] += 1
        final_label = str(r["final_label"] or r["label"] or "").strip().lower()
        final_attack_type = str(r["final_attack_type"] or r["attack_type"] or "UNKNOWN").strip()
        normalized_type = _normalize_attack_type(final_label, final_attack_type)
        decision_source = str(r["decision_source"] or "rules").strip().lower()
        features = _safe_json_loads(r["features"], {})
        pkt_cnt = float((features.get("pkt_cnt", 0.0) if isinstance(features, dict) else 0.0) or 0.0)
        item["source_cnt"][decision_source] += 1
        item["total_pkt_sum"] += pkt_cnt

        if final_label in ("attack", "suspect"):
            item["alert_count"] += 1
            item["alert_pkt_sum"] += pkt_cnt
        if final_label == "attack":
            item["attack_count"] += 1
        elif final_label == "suspect":
            item["suspect_count"] += 1
        item["type_cnt"][normalized_type] += 1

        pps = float(r["pps"] or 0.0)
        bps = float(r["bps"] or 0.0)
        item["pps_sum"] += pps
        item["bps_sum"] += bps
        item["pps_peak"] = max(item["pps_peak"], pps)
        item["bps_peak"] = max(item["bps_peak"], bps)
        uniq_src_now = int(r["uniq_src"] or 0)
        item["uniq_src_max"] = max(item["uniq_src_max"], uniq_src_now)
        item["uniq_src_sum"] += max(0, uniq_src_now)
        item["uniq_flow5_max"] = max(item["uniq_flow5_max"], int(r["uniq_flow5"] or 0))

        src_pairs = _parse_pair_list(r["top_src_ip"])
        dport_pairs = _parse_pair_list(r["top_dport"])
        if not src_pairs or not dport_pairs:
            if not src_pairs:
                src_pairs = _parse_pair_list(json.dumps(features.get("top_src_ip", []), ensure_ascii=False))
            if not dport_pairs:
                dport_pairs = _parse_pair_list(json.dumps(features.get("top_dport", []), ensure_ascii=False))
        _merge_pairs(item["top_src_map"], src_pairs)
        _merge_pairs(item["top_dport_map"], dport_pairs)

    out = []
    for bucket in sorted(buckets.keys(), reverse=True)[: max(1, limit)]:
        b = buckets[bucket]
        type_sorted = sorted(b["type_cnt"].items(), key=lambda x: x[1], reverse=True)
        source_sorted = sorted(b["source_cnt"].items(), key=lambda x: x[1], reverse=True)
        main_type = type_sorted[0][0] if type_sorted else "UNKNOWN"
        mixed = len([x for x in type_sorted if x[1] > 0]) > 1
        out.append(
            {
                "ts": b["ts"],
                "bucket_start": b["bucket_start"],
                "bucket_end": b["bucket_end"],
                "window_count": b["window_count"],
                "alert_count": b["alert_count"],
                "attack_count": b["attack_count"],
                "suspect_count": b["suspect_count"],
                "total_window_packets": int(round(total_pkt_by_bucket.get(bucket, b["total_pkt_sum"]))),
                "alert_window_packets": int(round(b["alert_pkt_sum"])),
                "main_attack_type": main_type,
                "attack_type_mixed": mixed,
                "attack_type_list": [x[0] for x in type_sorted],
                "attack_type_breakdown": [[k, int(v)] for k, v in type_sorted],
                "decision_source_breakdown": [[k, int(v)] for k, v in source_sorted],
                "avg_pps": round((b["pps_sum"] / b["window_count"]) if b["window_count"] else 0.0, 3),
                "peak_pps": round(b["pps_peak"], 3),
                "avg_bps": round((b["bps_sum"] / b["window_count"]) if b["window_count"] else 0.0, 3),
                "peak_bps": round(b["bps_peak"], 3),
                "uniq_src_max": int(b["uniq_src_max"]),
                "uniq_src_window_sum": int(b["uniq_src_sum"]),
                "uniq_src_bucket_est": int(max(b["uniq_src_max"], len(b["top_src_map"]))),
                "uniq_flow5_max": int(b["uniq_flow5_max"]),
                "top_src_ip_agg": _top_pairs(b["top_src_map"], max(1, topn)),
                "top_dport_agg": _top_pairs(b["top_dport_map"], max(1, topn)),
            }
        )
    return jsonify(out)


@app.get("/api/events_bucket_details")
def api_events_bucket_details():
    path = Path(request.args.get("db", str(DEFAULT_DB)))
    table = str(request.args.get("table", "alerts")).strip().lower()
    if table not in ("events", "alerts"):
        table = "alerts"
    try:
        bucket_start = float(request.args.get("bucket_start", "0") or 0.0)
    except (TypeError, ValueError):
        bucket_start = 0.0
    try:
        bucket_sec = max(1, int(request.args.get("bucket_sec", "5")))
    except (TypeError, ValueError):
        bucket_sec = 5
    try:
        limit = max(1, min(int(request.args.get("limit", "200")), 1000))
    except (TypeError, ValueError):
        limit = 200
    label = request.args.get("label", "").strip()
    attack_type = request.args.get("attack_type", "").strip()
    if bucket_start <= 0:
        return jsonify([])

    bucket_end = bucket_start + bucket_sec
    where, params = _build_event_filters(table, label, attack_type)
    sql = (
        f"SELECT id, ts, label, attack_type, final_label, final_attack_type, decision_source, "
        f"pps, bps, uniq_src, uniq_flow5, top_src_ip, top_dport, reasons, features "
        f"FROM {table}"
    )
    if where:
        sql += " WHERE " + " AND ".join(where) + " AND ts >= ? AND ts < ?"
    else:
        sql += " WHERE ts >= ? AND ts < ?"
    params.extend([bucket_start, bucket_end, limit])
    sql += " ORDER BY ts DESC LIMIT ?"

    fallback_sql = (
        f"SELECT id, ts, label, attack_type, "
        f"pps, bps, uniq_src, uniq_flow5, top_src_ip, top_dport, reasons, features "
        f"FROM {table}"
    )
    fallback_params = list(params)
    if where:
        fallback_sql += " WHERE " + " AND ".join(where) + " AND ts >= ? AND ts < ?"
    else:
        fallback_sql += " WHERE ts >= ? AND ts < ?"
    fallback_sql += " ORDER BY ts DESC LIMIT ?"

    conn = get_db(path)
    try:
        try:
            rows = conn.execute(sql, params).fetchall()
        except sqlite3.OperationalError:
            try:
                rows = conn.execute(fallback_sql, fallback_params).fetchall()
            except sqlite3.OperationalError:
                rows = []
    finally:
        conn.close()

    out = []
    for r in rows:
        features = _safe_json_loads(_row_get(r, "features"), {})
        reasons = _safe_json_loads(_row_get(r, "reasons"), [])
        src_pairs = _parse_pair_list(_row_get(r, "top_src_ip"))
        dport_pairs = _parse_pair_list(_row_get(r, "top_dport"))
        if not src_pairs and isinstance(features, dict):
            src_pairs = _parse_pair_list(json.dumps(features.get("top_src_ip", []), ensure_ascii=False))
        if not dport_pairs and isinstance(features, dict):
            dport_pairs = _parse_pair_list(json.dumps(features.get("top_dport", []), ensure_ascii=False))

        out.append(
            {
                "id": _row_get(r, "id"),
                "ts": _row_get(r, "ts"),
                "label": _row_get(r, "label", ""),
                "attack_type": _row_get(r, "attack_type", ""),
                "final_label": _row_get(r, "final_label", _row_get(r, "label", "")),
                "final_attack_type": _row_get(r, "final_attack_type", _row_get(r, "attack_type", "")),
                "decision_source": _row_get(r, "decision_source", "rules"),
                "pps": _row_get(r, "pps", 0.0),
                "bps": _row_get(r, "bps", 0.0),
                "uniq_src": _row_get(r, "uniq_src", 0),
                "uniq_flow5": _row_get(r, "uniq_flow5", 0),
                "top_src_ip": [[k, round(v, 3)] for k, v in src_pairs],
                "top_dport": [[k, round(v, 3)] for k, v in dport_pairs],
                "reasons": reasons if isinstance(reasons, list) else [],
            }
        )
    return jsonify(out)


@app.get("/api/series")
def api_series():
    path = Path(request.args.get("db", str(DEFAULT_DB)))
    table = str(request.args.get("table", "alerts")).strip().lower()
    if table not in ("events", "alerts"):
        table = "alerts"
    minutes = int(request.args.get("minutes", "60"))
    bucket_sec = int(request.args.get("bucket_sec", "5"))

    since_ts = time.time() - (minutes * 60)

    conn = get_db(path)
    try:
        try:
            rows = conn.execute(
                f"""
                SELECT
                  (CAST(ts / ? AS INTEGER) * ?) AS bucket,
                  AVG(pps) AS pps,
                  AVG(bps) AS bps,
                  AVG(score) AS score,
                  AVG(confidence) AS confidence,
                  SUM(CASE WHEN COALESCE(final_label, label) IN ('suspect','attack') THEN 1 ELSE 0 END) AS alert_count,
                  COUNT(*) AS total
                FROM {table}
                WHERE ts >= ?
                GROUP BY bucket
                ORDER BY bucket ASC
                """,
                (bucket_sec, bucket_sec, since_ts),
            ).fetchall()
        except sqlite3.OperationalError:
            rows = []
    finally:
        conn.close()

    out = []
    for r in rows:
        out.append(
            {
                "ts": r["bucket"],
                "pps": round(r["pps"] or 0, 6),
                "bps": round(r["bps"] or 0, 6),
                "score": round(r["score"] or 0, 6),
                "confidence": round(r["confidence"] or 0, 6),
                "alert_count": int(r["alert_count"] or 0),
                "total": int(r["total"] or 0),
            }
        )
    return jsonify({"meta": {"minutes": minutes, "bucket_sec": bucket_sec, "y": "avg_per_window"}, "series": out})


@app.get("/api/ddos_series")
def api_ddos_series():
    path = Path(request.args.get("db", str(DEFAULT_DB)))
    minutes = int(request.args.get("minutes", "60"))
    bucket_sec = int(request.args.get("bucket_sec", "5"))
    since_ts = time.time() - (minutes * 60)

    conn = get_db(path)
    try:
        try:
            rows = conn.execute(
                """
                SELECT
                  ts,
                  COALESCE(final_label, label) AS final_label,
                  COALESCE(final_attack_type, attack_type) AS final_attack_type
                FROM alerts
                WHERE ts >= ?
                ORDER BY ts ASC
                """,
                (since_ts,),
            ).fetchall()
        except sqlite3.OperationalError:
            rows = []
    finally:
        conn.close()

    known_types = []
    if RULES_JSON.exists():
        try:
            with open(RULES_JSON, "r", encoding="utf-8") as f:
                rules = json.load(f) or {}
            known_types = [str(x).strip().upper() for x in (rules.get("decision", {}) or {}).get("known_rule_attacks", []) if str(x).strip()]
        except Exception:
            known_types = []

    buckets = {}
    observed_types = set()

    for r in rows:
        ts = float(r["ts"] or 0.0)
        bucket = int(ts // bucket_sec) * bucket_sec
        label = str(r["final_label"] or "").strip().lower()
        attack_type = str(r["final_attack_type"] or "UNKNOWN").strip().upper()

        b = buckets.setdefault(
            bucket,
            {
                "ts": bucket,
                "total_ddos": 0,
                "attack_total": 0,
                "suspect": 0,
                "by_type": {},
            },
        )

        if label == "attack":
            b["total_ddos"] += 1
            b["attack_total"] += 1
            if attack_type in ("", "BENIGN", "SUSPECT", "ATTACK"):
                attack_type = "UNKNOWN"
            observed_types.add(attack_type)
            b["by_type"][attack_type] = int(b["by_type"].get(attack_type, 0)) + 1
        elif label == "suspect":
            b["total_ddos"] += 1
            b["suspect"] += 1

    types = list(dict.fromkeys(known_types + sorted(observed_types)))
    series = [buckets[k] for k in sorted(buckets.keys())]
    return jsonify({"meta": {"minutes": minutes, "bucket_sec": bucket_sec, "y": "alert_windows_per_bucket"}, "types": types, "series": series})


@app.get("/api/topk")
def api_topk():
    path = Path(request.args.get("db", str(DEFAULT_DB)))
    minutes = int(request.args.get("minutes", "60"))
    topn = int(request.args.get("topn", "8"))
    since_ts = time.time() - (minutes * 60)

    conn = get_db(path)
    try:
        try:
            rows = conn.execute(
                "SELECT top_src_ip, top_dport FROM alerts WHERE ts >= ? ORDER BY ts DESC",
                (since_ts,),
            ).fetchall()
        except sqlite3.OperationalError:
            rows = []
    finally:
        conn.close()

    src_map = {}
    dport_map = {}

    for r in rows:
        src_list = _safe_json_loads(r["top_src_ip"], [])
        dport_list = _safe_json_loads(r["top_dport"], [])
        if isinstance(src_list, list):
            for item in src_list:
                if not isinstance(item, (list, tuple)) or len(item) < 2:
                    continue
                k, v = item[0], item[1]
                src_map[k] = src_map.get(k, 0) + float(v or 0)
        if isinstance(dport_list, list):
            for item in dport_list:
                if not isinstance(item, (list, tuple)) or len(item) < 2:
                    continue
                k, v = str(item[0]), item[1]
                dport_map[k] = dport_map.get(k, 0) + float(v or 0)

    top_src = sorted(src_map.items(), key=lambda x: x[1], reverse=True)[:topn]
    top_dport = sorted(dport_map.items(), key=lambda x: x[1], reverse=True)[:topn]

    return jsonify(
        {
            "top_src_ip": [[k, v] for k, v in top_src],
            "top_dport": [[k, v] for k, v in top_dport],
        }
    )


@app.get("/api/topk_segment")
def api_topk_segment():
    path = Path(request.args.get("db", str(DEFAULT_DB)))
    minutes = int(request.args.get("minutes", "60"))
    bucket_sec = int(request.args.get("bucket_sec", "5"))
    topn = int(request.args.get("topn", "5"))
    label = request.args.get("label", "").strip()
    attack_type = request.args.get("attack_type", "").strip()
    since_ts = time.time() - (minutes * 60)

    where, params = _build_event_filters("alerts", label, attack_type)
    sql = "SELECT ts, top_src_ip FROM alerts"
    if where:
        sql += " WHERE " + " AND ".join(where) + " AND ts >= ?"
    else:
        sql += " WHERE ts >= ?"
    params.append(since_ts)
    sql += " ORDER BY ts ASC"

    conn = get_db(path)
    try:
        try:
            rows = conn.execute(sql, params).fetchall()
        except sqlite3.OperationalError:
            rows = []
    finally:
        conn.close()

    bucket_map = {}
    global_total = defaultdict(float)
    global_active = defaultdict(int)
    for r in rows:
        ts = float(r["ts"] or 0.0)
        bucket = int(ts // bucket_sec) * bucket_sec
        b = bucket_map.setdefault(bucket, {"ts": bucket, "top_src_map": {}})
        pairs = _parse_pair_list(r["top_src_ip"])
        if not pairs:
            continue
        active_ip = set()
        for ip, cnt in pairs:
            b["top_src_map"][ip] = float(b["top_src_map"].get(ip, 0.0)) + float(cnt)
            global_total[ip] += float(cnt)
            active_ip.add(ip)
        for ip in active_ip:
            global_active[ip] += 1

    ranked = sorted(global_total.keys(), key=lambda ip: (global_active[ip], global_total[ip]), reverse=True)
    selected = ranked[: max(1, topn)]

    series = []
    for bucket in sorted(bucket_map.keys()):
        b = bucket_map[bucket]
        selected_map = {}
        other_sum = 0.0
        for ip, cnt in b["top_src_map"].items():
            if ip in selected:
                selected_map[ip] = round(cnt, 3)
            else:
                other_sum += float(cnt)
        series.append(
            {
                "ts": b["ts"],
                "bucket_start": b["ts"],
                "bucket_end": b["ts"] + bucket_sec,
                "by_ip": selected_map,
                "other": round(other_sum, 3),
                "top_src_ip_agg": _top_pairs(b["top_src_map"], max(1, topn)),
            }
        )

    return jsonify(
        {
            "meta": {"minutes": minutes, "bucket_sec": bucket_sec},
            "ips": selected,
            "series": series,
        }
    )


@app.get("/api/db_status")
def api_db_status():
    path = Path(request.args.get("db", str(DEFAULT_DB)))
    conn = get_db(path)
    try:
        try:
            ev_cnt = conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]
            al_cnt = conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]
            ev_last = conn.execute("SELECT MAX(ts) AS ts FROM events").fetchone()["ts"]
            al_last = conn.execute("SELECT MAX(ts) AS ts FROM alerts").fetchone()["ts"]
        except sqlite3.OperationalError:
            ev_cnt = 0
            al_cnt = 0
            ev_last = 0
            al_last = 0
    finally:
        conn.close()
    return jsonify(
        {
            "events": int(ev_cnt or 0),
            "alerts": int(al_cnt or 0),
            "events_last_ts": ev_last or 0,
            "alerts_last_ts": al_last or 0,
        }
    )


@app.get("/api/rules")
def api_rules_get():
    if not RULES_JSON.exists():
        return jsonify({})
    with open(RULES_JSON, "r", encoding="utf-8") as f:
        return jsonify(json.load(f))


@app.post("/api/rules")
def api_rules_update():
    if not RULES_JSON.exists():
        return jsonify({"ok": False, "error": "rules.json not found"}), 404
    payload = request.get_json(force=True, silent=True) or {}
    with open(RULES_JSON, "r", encoding="utf-8") as f:
        rules = json.load(f)

    for key in ("thresholds", "decision", "type_rules"):
        if key in payload and isinstance(payload[key], dict):
            rules.setdefault(key, {})
            rules[key].update(payload[key])

    with open(RULES_JSON, "w", encoding="utf-8") as f:
        json.dump(rules, f, ensure_ascii=False, indent=2)

    return jsonify({"ok": True, "rules": rules})


@app.post("/api/feedback")
def api_feedback():
    payload = request.get_json(force=True, silent=True) or {}
    event_id = int(payload.get("event_id", 0) or 0)
    kind = str(payload.get("kind", "")).strip()
    note = str(payload.get("note", "")).strip()
    if event_id <= 0 or kind not in ("fp", "fn", "tp", "tn"):
        return jsonify({"ok": False, "error": "invalid payload"}), 400

    conn = get_db(DEFAULT_DB)
    try:
        conn.execute(
            "INSERT INTO feedback(event_id, kind, note, ts) VALUES(?,?,?,?)",
            (event_id, kind, note, time.time()),
        )
        conn.commit()
    finally:
        conn.close()
    return jsonify({"ok": True})


@app.get("/api/feedback_stats")
def api_feedback_stats():
    minutes = int(request.args.get("minutes", "60"))
    since_ts = time.time() - (minutes * 60)
    conn = get_db(DEFAULT_DB)
    try:
        rows = conn.execute(
            "SELECT kind, COUNT(*) AS c FROM feedback WHERE ts >= ? GROUP BY kind",
            (since_ts,),
        ).fetchall()
    finally:
        conn.close()
    out = {"fp": 0, "fn": 0, "tp": 0, "tn": 0}
    for r in rows:
        out[r["kind"]] = int(r["c"] or 0)
    return jsonify(out)


@app.get("/api/ml_series")
def api_ml_series():
    path = Path(request.args.get("db", str(DEFAULT_DB)))
    minutes = int(request.args.get("minutes", "60"))
    bucket_sec = int(request.args.get("bucket_sec", "5"))

    since_ts = time.time() - (minutes * 60)

    conn = get_db(path)
    try:
        try:
            rows = conn.execute(
                "SELECT ts, COALESCE(final_label, label) AS label, dl_p_attack, confidence FROM alerts WHERE ts >= ? ORDER BY ts ASC",
                (since_ts,),
            ).fetchall()
        except sqlite3.OperationalError:
            rows = []
    finally:
        conn.close()

    buckets = {}
    for r in rows:
        ts = float(r["ts"] or 0)
        bucket = int(ts // bucket_sec) * bucket_sec
        b = buckets.setdefault(bucket, {"dl_sum": 0.0, "dl_cnt": 0, "rule_sum": 0.0, "rule_cnt": 0, "alert": 0})
        dl_score = r["dl_p_attack"]
        if dl_score is not None:
            b["dl_sum"] += float(dl_score)
            b["dl_cnt"] += 1
        rule_conf = r["confidence"]
        if rule_conf is not None:
            b["rule_sum"] += float(rule_conf)
            b["rule_cnt"] += 1
        if (r["label"] or "") in ("suspect", "attack"):
            b["alert"] += 1

    out = []
    for bucket in sorted(buckets.keys()):
        b = buckets[bucket]
        dl_avg = round(b["dl_sum"] / b["dl_cnt"], 6) if b["dl_cnt"] > 0 else None
        rule_avg = round(b["rule_sum"] / b["rule_cnt"], 6) if b["rule_cnt"] > 0 else None
        out.append({"ts": bucket, "dl_p_attack": dl_avg, "rule_confidence": rule_avg, "alert_count": b["alert"]})
    return jsonify(out)


@app.get("/api/ml_agree")
def api_ml_agree():
    path = Path(request.args.get("db", str(DEFAULT_DB)))
    minutes = int(request.args.get("minutes", "60"))
    since_ts = time.time() - (minutes * 60)

    conn = get_db(path)
    try:
        try:
            rows = conn.execute(
                "SELECT decision_source FROM alerts WHERE ts >= ? ORDER BY ts DESC",
                (since_ts,),
            ).fetchall()
        except sqlite3.OperationalError:
            rows = []
    finally:
        conn.close()

    rules_cnt = 0
    dl_cnt = 0
    hybrid_cnt = 0

    for r in rows:
        src = (r["decision_source"] or "rules").lower()
        if src == "dl":
            dl_cnt += 1
        elif src == "hybrid":
            hybrid_cnt += 1
        else:
            rules_cnt += 1

    return jsonify({"rules": rules_cnt, "dl": dl_cnt, "hybrid": hybrid_cnt})


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


# ensure feedback table exists
init_feedback_table(DEFAULT_DB)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
