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

from dl.dataset.feature_spec import vectorize, standardize
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
        model_cfg = payload.get("model", {}) or {}
        hidden = int(model_cfg.get("hidden", 64))
        kernel = int(model_cfg.get("kernel", 3))
        dropout = float(model_cfg.get("dropout", 0.2))

        self.model = CNN1D(
            num_features=len(self.mean),
            hidden=hidden,
            kernel=kernel,
            dropout=dropout,
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
            logits = self.model(x)
            p_attack = torch.sigmoid(logits).item()

        label = "attack" if p_attack >= 0.5 else "benign"
        return {
            "p_attack": round(float(p_attack), 6),
            "label": label,
            "attack_type": "UNKNOWN",
            "model_version": self.model_version,
        }
