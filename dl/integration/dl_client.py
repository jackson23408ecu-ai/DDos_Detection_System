#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from dataclasses import dataclass
from typing import Dict, List, Optional

import requests


@dataclass
class DLResult:
    p_attack: Optional[float] = None
    label: str = "unknown"
    attack_type: str = "UNKNOWN"
    model_version: str = "unknown"
    error: Optional[str] = None


class DLClient:
    def __init__(self, url: str, timeout: float = 0.6):
        self.url = url
        self.timeout = timeout

    def predict(self, seq: List[Dict]) -> DLResult:
        try:
            resp = requests.post(self.url, json={"seq": seq}, timeout=self.timeout)
        except Exception as e:
            return DLResult(error=f"request_failed: {e}")

        if resp.status_code != 200:
            return DLResult(error=f"http_{resp.status_code}: {resp.text[:200]}")

        try:
            data = resp.json()
        except Exception as e:
            return DLResult(error=f"bad_json: {e}")

        return DLResult(
            p_attack=float(data.get("p_attack", 0.0)),
            label=str(data.get("label", "unknown")),
            attack_type=str(data.get("attack_type", "UNKNOWN")),
            model_version=str(data.get("model_version", "unknown")),
        )
