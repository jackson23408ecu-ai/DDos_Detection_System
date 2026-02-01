#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import random
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple

import numpy as np
import torch
import torch.nn as nn
import yaml
from torch.utils.data import DataLoader, Dataset

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dl.dataset.feature_spec import FEATURE_ORDER
from dl.train.metrics import classification_metrics
from dl.train.model import CNN1D


@dataclass
class Standardizer:
    mean: np.ndarray
    std: np.ndarray

    def apply(self, X: np.ndarray) -> np.ndarray:
        return (X - self.mean) / self.std


def load_config(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def build_sequences(X: np.ndarray, y: np.ndarray, T: int, stride: int) -> Tuple[np.ndarray, np.ndarray]:
    n = X.shape[0]
    if n < T:
        return np.empty((0, T, X.shape[1]), dtype=np.float32), np.empty((0,), dtype=np.int64)

    seqs = []
    labels = []
    for i in range(0, n - T + 1, stride):
        seqs.append(X[i : i + T])
        labels.append(int(y[i + T - 1]))
    return np.asarray(seqs, dtype=np.float32), np.asarray(labels, dtype=np.int64)


class SequenceDataset(Dataset):
    def __init__(self, X_seq: np.ndarray, y_seq: np.ndarray):
        self.X = torch.from_numpy(X_seq)
        self.y = torch.from_numpy(y_seq)

    def __len__(self):
        return self.X.shape[0]

    def __getitem__(self, idx):
        return self.X[idx], self.y[idx]


def fit_standardizer(X: np.ndarray) -> Standardizer:
    mean = X.mean(axis=0)
    std = X.std(axis=0) + 1e-6
    return Standardizer(mean=mean, std=std)


def split_by_files(meta: dict, train_ratio: float) -> Tuple[List[Tuple[int, int]], List[Tuple[int, int]]]:
    files = meta.get("files", []) or []
    if not files:
        return [], []
    total = len(files)
    train_n = max(1, int(total * train_ratio))
    train_files = files[:train_n]
    test_files = files[train_n:]
    train_slices = [(int(f["start"]), int(f["end"])) for f in train_files]
    test_slices = [(int(f["start"]), int(f["end"])) for f in test_files]
    return train_slices, test_slices


def build_sequences_from_slices(X: np.ndarray, y: np.ndarray, slices: List[Tuple[int, int]], T: int, stride: int):
    X_list = []
    y_list = []
    for start, end in slices:
        if end - start < T:
            continue
        X_seq, y_seq = build_sequences(X[start:end], y[start:end], T, stride)
        if len(y_seq) == 0:
            continue
        X_list.append(X_seq)
        y_list.append(y_seq)
    if not X_list:
        return np.empty((0, T, X.shape[1]), dtype=np.float32), np.empty((0,), dtype=np.int64)
    return np.concatenate(X_list, axis=0), np.concatenate(y_list, axis=0)


def eval_metrics(model, loader, device, threshold=0.5):
    model.eval()
    probs = []
    ys = []
    with torch.no_grad():
        for Xb, yb in loader:
            Xb = Xb.to(device)
            logits = model(Xb)
            p = torch.sigmoid(logits).cpu().numpy()
            probs.append(p)
            ys.append(yb.numpy())
    if not probs:
        return {"accuracy": 0, "precision": 0, "recall": 0, "f1": 0, "auc": 0, "tp": 0, "tn": 0, "fp": 0, "fn": 0}

    ys = np.concatenate(ys)
    probs = np.concatenate(probs)
    return classification_metrics(ys, probs, threshold=threshold)


def train_one_epoch(model, loader, criterion, optimizer, device):
    model.train()
    total_loss = 0.0
    for Xb, yb in loader:
        Xb = Xb.to(device)
        yb = yb.to(device).float()
        optimizer.zero_grad()
        logits = model(Xb)
        loss = criterion(logits, yb)
        loss.backward()
        optimizer.step()
        total_loss += loss.item() * Xb.size(0)
    return total_loss / max(len(loader.dataset), 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="dl/config.yaml")
    args = ap.parse_args()

    cfg = load_config(Path(args.config))
    ds_cfg = cfg.get("dataset", {})
    tr_cfg = cfg.get("train", {})

    data_dir = Path(ds_cfg.get("output_dir", "dl/data"))
    if not data_dir.is_absolute():
        data_dir = ROOT / data_dir
    X_path = data_dir / "X.npy"
    y_path = data_dir / "y.npy"
    meta_path = data_dir / "meta.json"

    if not X_path.exists() or not y_path.exists():
        raise SystemExit("X.npy/y.npy not found. Run build_window_dataset.py first.")

    X = np.load(X_path)
    y = np.load(y_path)

    if X.shape[1] != len(FEATURE_ORDER):
        raise SystemExit("feature size mismatch with FEATURE_ORDER")

    meta = {}
    if meta_path.exists():
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

    seq_len = int(tr_cfg.get("seq_len", 10))
    stride = int(tr_cfg.get("stride", 1))
    batch = int(tr_cfg.get("batch_size", 256))
    epochs = int(tr_cfg.get("epochs", 10))
    lr = float(tr_cfg.get("lr", 1e-3))
    hidden = int(tr_cfg.get("hidden", 64))
    kernel = int(tr_cfg.get("kernel", 3))
    dropout = float(tr_cfg.get("dropout", 0.2))

    split_strategy = str(ds_cfg.get("split_strategy", "by_file"))
    train_ratio = float(ds_cfg.get("train_ratio", 0.8))

    random_seed = int(ds_cfg.get("random_seed", 42))
    random.seed(random_seed)
    np.random.seed(random_seed)
    torch.manual_seed(random_seed)

    train_slices, test_slices = split_by_files(meta, train_ratio)
    if split_strategy != "by_file" or not train_slices:
        # fallback: time-based split on raw order
        n = X.shape[0]
        cut = int(n * train_ratio)
        train_slices = [(0, cut)]
        test_slices = [(cut, n)]

    # fit scaler on train only
    train_idx = np.concatenate([np.arange(s, e) for s, e in train_slices]) if train_slices else np.arange(len(X))
    std = fit_standardizer(X[train_idx])
    X_std = std.apply(X)

    X_train_seq, y_train_seq = build_sequences_from_slices(X_std, y, train_slices, seq_len, stride)
    X_test_seq, y_test_seq = build_sequences_from_slices(X_std, y, test_slices, seq_len, stride)

    if X_train_seq.shape[0] == 0:
        raise SystemExit("train set too small for seq_len")

    train_ds = SequenceDataset(X_train_seq, y_train_seq)
    test_ds = SequenceDataset(X_test_seq, y_test_seq) if len(y_test_seq) else None

    train_loader = DataLoader(train_ds, batch_size=batch, shuffle=True, drop_last=True)
    test_loader = DataLoader(test_ds, batch_size=batch, shuffle=False) if test_ds else None

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = CNN1D(
        num_features=X.shape[1],
        hidden=hidden,
        kernel=kernel,
        dropout=dropout,
    ).to(device)

    # handle class imbalance for binary
    pos = y_train_seq.sum()
    neg = len(y_train_seq) - pos
    if pos > 0:
        pos_weight = torch.tensor([neg / max(pos, 1)], device=device)
        criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    else:
        criterion = nn.BCEWithLogitsLoss()

    optimizer = torch.optim.Adam(model.parameters(), lr=lr)

    history = []
    for epoch in range(1, epochs + 1):
        loss = train_one_epoch(model, train_loader, criterion, optimizer, device)
        train_metrics = eval_metrics(model, train_loader, device)
        test_metrics = eval_metrics(model, test_loader, device) if test_loader else {}
        history.append({"epoch": epoch, "loss": round(loss, 6), "train": train_metrics, "test": test_metrics})
        if test_loader:
            print(f"[epoch {epoch}] loss={loss:.4f} train_f1={train_metrics['f1']:.4f} test_f1={test_metrics['f1']:.4f}")
        else:
            print(f"[epoch {epoch}] loss={loss:.4f} train_f1={train_metrics['f1']:.4f}")

    model_out = Path(tr_cfg.get("model_out", "models/dl_model.pt"))
    scaler_out = Path(tr_cfg.get("scaler_out", "models/dl_scaler.json"))
    metrics_out = Path(tr_cfg.get("metrics_out", "models/dl_metrics.json"))
    if not model_out.is_absolute():
        model_out = ROOT / model_out
    if not scaler_out.is_absolute():
        scaler_out = ROOT / scaler_out
    if not metrics_out.is_absolute():
        metrics_out = ROOT / metrics_out

    model_out.parent.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), model_out)

    model_version = time.strftime("%Y%m%d-%H%M%S")
    scaler_payload = {
        "feature_order": FEATURE_ORDER,
        "mean": std.mean.tolist(),
        "std": std.std.tolist(),
        "seq_len": seq_len,
        "model": {
            "hidden": hidden,
            "kernel": kernel,
            "dropout": dropout,
        },
        "model_version": model_version,
    }
    with open(scaler_out, "w", encoding="utf-8") as f:
        json.dump(scaler_payload, f, ensure_ascii=False, indent=2)

    metrics_payload = {
        "train": history[-1]["train"] if history else {},
        "test": history[-1]["test"] if history else {},
        "history": history,
    }
    with open(metrics_out, "w", encoding="utf-8") as f:
        json.dump(metrics_payload, f, ensure_ascii=False, indent=2)

    print(f"[ok] saved model -> {model_out}")
    print(f"[ok] saved scaler -> {scaler_out}")
    print(f"[ok] saved metrics -> {metrics_out}")


if __name__ == "__main__":
    main()
