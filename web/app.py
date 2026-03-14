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


def _known_rule_attacks() -> set:
    default = {
        "UDP_FLOOD",
        "TCP_SYN_FLOOD",
        "ICMP_FLOOD",
        "TCP_ACK_FLOOD",
        "TCP_RST_FLOOD",
        "DNS_AMP_FLOOD",
        "NTP_AMP_FLOOD",
        "SSDP_AMP_FLOOD",
        "CLDAP_AMP_FLOOD",
        "MEMCACHED_AMP_FLOOD",
        "SNMP_AMP_FLOOD",
    }
    if not RULES_JSON.exists():
        return default
    try:
        with open(RULES_JSON, "r", encoding="utf-8") as f:
            rules = json.load(f) or {}
        known = (rules.get("decision", {}) or {}).get("known_rule_attacks", [])
        out = {str(x).strip().upper() for x in known if str(x).strip()}
        return out or default
    except Exception:
        return default


def _safe_int(x, default=0):
    try:
        return int(x)
    except Exception:
        return int(default)


def _safe_float_num(x, default=0.0):
    try:
        return float(x)
    except Exception:
        return float(default)


def _first_feature_pair(features: dict, key: str, fallback="UNKNOWN"):
    if not isinstance(features, dict):
        return str(fallback)
    items = features.get(key, []) or []
    if not isinstance(items, list) or not items:
        return str(fallback)
    item = items[0]
    if not isinstance(item, (list, tuple)) or len(item) < 1:
        return str(fallback)
    return str(item[0])


def _normalize_session_attack_type(label: str, attack_type: str) -> str:
    label = str(label or "").strip().lower()
    attack_type = str(attack_type or "").strip().upper()
    if label == "suspect":
        return "SUSPECT"
    if attack_type in ("", "ATTACK", "BENIGN"):
        return "UNKNOWN"
    return attack_type


def _row_target_signature(row, features: dict):
    dst_ip = _first_feature_pair(features, "top_dst_ip", "")
    if not dst_ip:
        dst_ip = "UNKNOWN_DST"
    dport = _first_feature_pair(features, "top_dport", "")
    if not dport:
        dport = "UNKNOWN_PORT"
    return str(dst_ip), str(dport)


def _row_source_pairs(row, features: dict):
    src_pairs = _parse_pair_list(_row_get(row, "top_src_ip"))
    if src_pairs:
        return src_pairs
    return _parse_pair_list(json.dumps((features or {}).get("top_src_ip", []), ensure_ascii=False))


def _row_dport_pairs(row, features: dict):
    dport_pairs = _parse_pair_list(_row_get(row, "top_dport"))
    if dport_pairs:
        return dport_pairs
    return _parse_pair_list(json.dumps((features or {}).get("top_dport", []), ensure_ascii=False))


def _selected_alert_rows(rows):
    known_attacks = _known_rule_attacks()
    channel_hits = set()
    normalized = []

    for row in rows:
        features = _safe_json_loads(_row_get(row, "features"), {})
        split_scope = str((features or {}).get("split_scope", "global") or "global").strip().lower()
        label = str(_row_get(row, "final_label", _row_get(row, "label", "")) or "").strip().lower()
        attack_type = _normalize_session_attack_type(label, _row_get(row, "final_attack_type", _row_get(row, "attack_type", "")))
        window_start = _safe_int((features or {}).get("window_start_ns", 0), 0)
        item = (row, features, split_scope, label, attack_type, window_start)
        normalized.append(item)
        if split_scope == "channel" and label == "attack" and attack_type in known_attacks and window_start > 0:
            channel_hits.add((window_start, attack_type))

    out = []
    for row, features, split_scope, label, attack_type, window_start in normalized:
        if (
            split_scope == "global"
            and label == "attack"
            and attack_type in known_attacks
            and window_start > 0
            and (window_start, attack_type) in channel_hits
        ):
            continue
        out.append((row, features, split_scope, label, attack_type))
    return out


def _build_session_summary(session: dict, topn: int = 8):
    window_count = max(1, int(session.get("window_count", 0) or 0))
    type_sorted = sorted((session.get("type_cnt") or {}).items(), key=lambda x: x[1], reverse=True)
    source_sorted = sorted((session.get("decision_source_cnt") or {}).items(), key=lambda x: x[1], reverse=True)
    main_type = type_sorted[0][0] if type_sorted else str(session.get("attack_type", "UNKNOWN"))
    source_rows = []
    for ip, meta in sorted(
        (session.get("source_map") or {}).items(),
        key=lambda x: (float(x[1].get("packet_est", 0.0)), float(x[1].get("window_hits", 0))),
        reverse=True,
    ):
        packet_est = float(meta.get("packet_est", 0.0) or 0.0)
        source_rows.append(
            {
                "src_ip": ip,
                "first_ts": float(meta.get("first_ts", 0.0) or 0.0),
                "last_ts": float(meta.get("last_ts", 0.0) or 0.0),
                "duration_sec": round(
                    max(0.0, float(meta.get("last_ts", 0.0) or 0.0) - float(meta.get("first_ts", 0.0) or 0.0)),
                    3,
                ),
                "window_hits": int(meta.get("window_hits", 0) or 0),
                "packet_est": int(round(packet_est)),
                "share_pct": round((packet_est / max(float(session.get("packet_est", 0.0) or 0.0), 1.0)) * 100.0, 2),
                "max_window_packets": int(round(float(meta.get("max_window_packets", 0.0) or 0.0))),
            }
        )

    return {
        "final_label": str(session.get("final_label", "suspect")),
        "attack_type": str(main_type),
        "main_attack_type": str(main_type),
        "start_ts": float(session.get("start_ts", 0.0) or 0.0),
        "end_ts": float(session.get("end_ts", 0.0) or 0.0),
        "duration_sec": round(
            max(0.0, float(session.get("end_ts", 0.0) or 0.0) - float(session.get("start_ts", 0.0) or 0.0)),
            3,
        ),
        "window_count": window_count,
        "attack_count": int(session.get("attack_count", 0) or 0),
        "suspect_count": int(session.get("suspect_count", 0) or 0),
        "avg_pps": round(float(session.get("pps_sum", 0.0) or 0.0) / window_count, 3),
        "peak_pps": round(float(session.get("pps_peak", 0.0) or 0.0), 3),
        "avg_bps": round(float(session.get("bps_sum", 0.0) or 0.0) / window_count, 3),
        "peak_bps": round(float(session.get("bps_peak", 0.0) or 0.0), 3),
        "uniq_src_max": int(session.get("uniq_src_max", 0) or 0),
        "uniq_flow5_max": int(session.get("uniq_flow5_max", 0) or 0),
        "source_ip_count": int(max(len(session.get("source_map") or {}), int(session.get("uniq_src_max", 0) or 0))),
        "packet_est": int(round(float(session.get("packet_est", 0.0) or 0.0))),
        "decision_source_breakdown": [[k, int(v)] for k, v in source_sorted],
        "attack_type_breakdown": [[k, int(v)] for k, v in type_sorted],
        "top_src_ip_agg": _top_pairs(session.get("top_src_map", {}) or {}, max(1, topn)),
        "top_dport_agg": _top_pairs(session.get("top_dport_map", {}) or {}, max(1, topn)),
        "source_details": source_rows,
    }


def _build_alert_sessions(rows, merge_gap_sec: float, topn: int = 8):
    merge_gap_sec = max(1.0, float(merge_gap_sec or 30.0))
    sessions = []
    last_session_by_key = {}

    for row, features, split_scope, label, attack_type in _selected_alert_rows(rows):
        ts = _safe_float_num(_row_get(row, "ts"), 0.0)
        if ts <= 0:
            continue
        if label not in ("attack", "suspect"):
            continue
        # Aggregate a continuous attack process by attack type only.
        # dport remains as a breakdown dimension instead of a split key.
        session_key = (attack_type,)

        session = last_session_by_key.get(session_key)
        if session is None or (ts - float(session.get("end_ts", 0.0) or 0.0)) > merge_gap_sec:
            session = {
                "key": session_key,
                "final_label": label,
                "attack_type": attack_type,
                "start_ts": ts,
                "end_ts": ts,
                "window_count": 0,
                "attack_count": 0,
                "suspect_count": 0,
                "pps_sum": 0.0,
                "bps_sum": 0.0,
                "pps_peak": 0.0,
                "bps_peak": 0.0,
                "packet_est": 0.0,
                "uniq_src_max": 0,
                "uniq_flow5_max": 0,
                "type_cnt": defaultdict(int),
                "decision_source_cnt": defaultdict(int),
                "top_src_map": {},
                "top_dport_map": {},
                "source_map": {},
            }
            sessions.append(session)
            last_session_by_key[session_key] = session

        session["end_ts"] = ts
        session["window_count"] += 1
        if label == "attack":
            session["attack_count"] += 1
            session["final_label"] = "attack"
        else:
            session["suspect_count"] += 1

        decision_source = str(_row_get(row, "decision_source", "rules") or "rules").strip().lower()
        session["decision_source_cnt"][decision_source] += 1
        session["type_cnt"][attack_type] += 1

        pps = _safe_float_num(_row_get(row, "pps", (features or {}).get("pps", 0.0)), 0.0)
        bps = _safe_float_num(_row_get(row, "bps", (features or {}).get("bps", 0.0)), 0.0)
        session["pps_sum"] += pps
        session["bps_sum"] += bps
        session["pps_peak"] = max(session["pps_peak"], pps)
        session["bps_peak"] = max(session["bps_peak"], bps)
        session["uniq_src_max"] = max(session["uniq_src_max"], _safe_int(_row_get(row, "uniq_src", (features or {}).get("uniq_src", 0)), 0))
        session["uniq_flow5_max"] = max(
            session["uniq_flow5_max"], _safe_int(_row_get(row, "uniq_flow5", (features or {}).get("uniq_flow5", 0)), 0)
        )

        src_pairs = _row_source_pairs(row, features)
        dport_pairs = _row_dport_pairs(row, features)

        _merge_pairs(session["top_src_map"], src_pairs)
        _merge_pairs(session["top_dport_map"], dport_pairs)

        src_window_total = 0.0
        seen_src = set()
        for ip, cnt in src_pairs:
            cnt = max(0.0, float(cnt or 0.0))
            src_window_total += cnt
            seen_src.add(ip)
            item = session["source_map"].setdefault(
                ip,
                {
                    "first_ts": ts,
                    "last_ts": ts,
                    "window_hits": 0,
                    "packet_est": 0.0,
                    "max_window_packets": 0.0,
                },
            )
            item["first_ts"] = min(float(item.get("first_ts", ts) or ts), ts)
            item["last_ts"] = max(float(item.get("last_ts", ts) or ts), ts)
            item["packet_est"] = float(item.get("packet_est", 0.0) or 0.0) + cnt
            item["max_window_packets"] = max(float(item.get("max_window_packets", 0.0) or 0.0), cnt)
        for ip in seen_src:
            session["source_map"][ip]["window_hits"] = int(session["source_map"][ip].get("window_hits", 0) or 0) + 1
        session["packet_est"] += src_window_total

    out = [_build_session_summary(session, topn=topn) for session in sessions]
    out.sort(key=lambda x: (float(x.get("end_ts", 0.0) or 0.0), float(x.get("start_ts", 0.0) or 0.0)), reverse=True)
    return out


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


@app.get("/api/alert_sessions")
def api_alert_sessions():
    path = Path(request.args.get("db", str(DEFAULT_DB)))
    table = str(request.args.get("table", "alerts")).strip().lower()
    if table not in ("events", "alerts"):
        table = "alerts"
    try:
        limit = max(1, min(int(request.args.get("limit", "200")), 1000))
    except (TypeError, ValueError):
        limit = 200
    try:
        minutes = max(1, int(request.args.get("minutes", "60")))
    except (TypeError, ValueError):
        minutes = 60
    try:
        merge_gap_sec = max(1, float(request.args.get("merge_gap_sec", "30")))
    except (TypeError, ValueError):
        merge_gap_sec = 30.0
    try:
        topn = max(1, min(int(request.args.get("topn", "8")), 50))
    except (TypeError, ValueError):
        topn = 8
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
    finally:
        conn.close()

    sessions = _build_alert_sessions(rows, merge_gap_sec=merge_gap_sec, topn=topn)
    return jsonify(sessions[:limit])


@app.get("/api/alert_session_sources")
def api_alert_session_sources():
    path = Path(request.args.get("db", str(DEFAULT_DB)))
    table = str(request.args.get("table", "alerts")).strip().lower()
    if table not in ("events", "alerts"):
        table = "alerts"
    attack_type = request.args.get("attack_type", "").strip().upper()
    dst_ip = request.args.get("dst_ip", "").strip()
    dst_port = request.args.get("dst_port", "").strip()
    label = request.args.get("label", "").strip().lower()
    try:
        start_ts = float(request.args.get("start_ts", "0") or 0.0)
    except (TypeError, ValueError):
        start_ts = 0.0
    try:
        end_ts = float(request.args.get("end_ts", "0") or 0.0)
    except (TypeError, ValueError):
        end_ts = 0.0
    try:
        topn = max(1, min(int(request.args.get("topn", "100")), 500))
    except (TypeError, ValueError):
        topn = 100
    if start_ts <= 0 or end_ts <= 0:
        return jsonify([])

    sql = (
        f"SELECT ts, label, attack_type, final_label, final_attack_type, decision_source, "
        f"pps, bps, uniq_src, uniq_flow5, top_src_ip, top_dport, features "
        f"FROM {table} WHERE ts >= ? AND ts <= ? ORDER BY ts ASC"
    )

    conn = get_db(path)
    try:
        try:
            rows = conn.execute(sql, (start_ts, end_ts)).fetchall()
        except sqlite3.OperationalError:
            rows = []
    finally:
        conn.close()

    matched = []
    for row, features, split_scope, row_label, row_type in _selected_alert_rows(rows):
        row_dst_ip, row_dst_port = _row_target_signature(row, features)
        if label and row_label != label:
            continue
        if attack_type and row_type != attack_type:
            continue
        if dst_ip and row_dst_ip != dst_ip:
            continue
        if dst_port and row_dst_port != dst_port:
            continue
        matched.append(row)

    sessions = _build_alert_sessions(matched, merge_gap_sec=max(1.0, end_ts - start_ts + 1.0), topn=max(8, topn))
    if not sessions:
        return jsonify([])
    source_rows = sessions[0].get("source_details", []) or []
    return jsonify(source_rows[:topn])


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
