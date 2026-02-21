#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import sys
from pathlib import Path
from typing import Dict, List

import numpy as np
import torch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dl.dataset.feature_spec import standardize, vectorize
from dl.train.model import CNN1D


class DLInference:
    def __init__(self, model_path: Path, scaler_path: Path):
        self.model_path = Path(model_path)
        self.scaler_path = Path(scaler_path)
        if not self.model_path.exists():
            raise FileNotFoundError(f"model not found: {self.model_path}")
        if not self.scaler_path.exists():
            raise FileNotFoundError(f"scaler not found: {self.scaler_path}")

        with open(self.scaler_path, "r", encoding="utf-8") as f:
            payload = json.load(f)

        self.mean = np.asarray(payload.get("mean", []), dtype=np.float32)
        self.std = np.asarray(payload.get("std", []), dtype=np.float32)
        self.mean_list = self.mean.tolist()
        self.std_list = self.std.tolist()
        self.seq_len = int(payload.get("seq_len", 10))
        self.model_version = str(payload.get("model_version", "unknown"))
        self.class_names = [str(x).upper() for x in payload.get("class_names", ["BENIGN", "ATTACK"])]
        self.benign_class = str(payload.get("benign_class", "BENIGN")).upper()
        self.attack_threshold = float(payload.get("attack_threshold", 0.6))
        core_cfg = payload.get("core_attack_classes", ["TCP_SYN_FLOOD", "UDP_FLOOD", "ICMP_FLOOD"]) or []
        self.core_attack_classes = [str(x).upper() for x in core_cfg if str(x).strip()]
        if not self.core_attack_classes:
            self.core_attack_classes = ["TCP_SYN_FLOOD", "UDP_FLOOD", "ICMP_FLOOD"]

        model_cfg = payload.get("model", {}) or {}
        hidden = int(model_cfg.get("hidden", 64))
        kernel = int(model_cfg.get("kernel", 3))
        dropout = float(model_cfg.get("dropout", 0.2))
        num_classes = int(model_cfg.get("num_classes", max(2, len(self.class_names))))
        if num_classes < len(self.class_names):
            num_classes = len(self.class_names)

        self.model = CNN1D(
            num_features=len(self.mean),
            hidden=hidden,
            kernel=kernel,
            dropout=dropout,
            num_classes=num_classes,
        )
        self.model.load_state_dict(torch.load(self.model_path, map_location="cpu"))
        self.model.eval()

    def _vectorize_seq(self, seq: List[Dict]) -> np.ndarray:
        if len(seq) != self.seq_len:
            raise ValueError(f"seq length must be {self.seq_len}")
        vecs = []
        for feat in seq:
            vec = vectorize(feat)
            vec = standardize(vec, self.mean_list, self.std_list)
            vecs.append(vec)
        return np.asarray(vecs, dtype=np.float32)

    def predict(self, seq: List[Dict]) -> Dict:
        x = self._vectorize_seq(seq)
        x = torch.from_numpy(x).unsqueeze(0)  # [1, T, F]
        with torch.no_grad():
            logits = self.model(x).squeeze(0)
            probs = torch.softmax(logits, dim=0).cpu().numpy()

        cls = self.class_names[: len(probs)]
        type_probs = {name: round(float(p), 6) for name, p in zip(cls, probs)}
        benign_prob = float(type_probs.get(self.benign_class, 0.0))
        core_probs = [(name, float(type_probs.get(name, 0.0))) for name in self.core_attack_classes]
        p_attack = float(sum(p for _, p in core_probs))
        if p_attack <= 1e-9:
            # Fallback for legacy models lacking explicit core classes.
            p_attack = max(0.0, min(1.0, 1.0 - benign_prob))
        else:
            p_attack = max(0.0, min(1.0, p_attack))

        top_idx = int(np.argmax(probs))
        top_type = cls[top_idx] if top_idx < len(cls) else "UNKNOWN"
        top_prob = float(probs[top_idx]) if top_idx < len(probs) else 0.0

        attack_candidates = [(name, float(p)) for name, p in zip(cls, probs) if name != self.benign_class]
        attack_candidates.sort(key=lambda x: x[1], reverse=True)
        extra_type = attack_candidates[0][0] if attack_candidates else "UNKNOWN"
        extra_conf = attack_candidates[0][1] if attack_candidates else 0.0
        top3 = sorted(type_probs.items(), key=lambda x: x[1], reverse=True)[:3]

        core_probs.sort(key=lambda x: x[1], reverse=True)
        top_core_type = core_probs[0][0] if core_probs else "UNKNOWN"
        top_core_prob = core_probs[0][1] if core_probs else 0.0

        label = "attack" if p_attack >= self.attack_threshold else "benign"
        attack_type = top_core_type if label == "attack" else "BENIGN"

        return {
            "p_attack": round(float(p_attack), 6),
            "label": label,
            "attack_type": attack_type,
            "model_version": self.model_version,
            "type_probs": type_probs,
            "extra_type": extra_type,
            "extra_confidence": round(float(extra_conf), 6),
            "top_types": [{"type": k, "prob": round(float(v), 6)} for k, v in top3],
            "detail": {
                "top_type": top_type,
                "top_type_prob": round(float(top_prob), 6),
                "top_core_type": top_core_type,
                "top_core_prob": round(float(top_core_prob), 6),
                "benign_prob": round(float(benign_prob), 6),
            },
        }
