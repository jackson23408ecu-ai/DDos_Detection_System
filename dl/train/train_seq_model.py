#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import copy
import json
import random
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import torch
import torch.nn as nn
import yaml
from torch.utils.data import DataLoader, Dataset

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dl.dataset.feature_spec import FEATURE_ORDER
from dl.train.metrics import classification_metrics_multiclass
from dl.train.model import CNN1D


@dataclass
class Standardizer:
    mean: np.ndarray
    std: np.ndarray

    def apply(self, X: np.ndarray) -> np.ndarray:
        return (X - self.mean) / self.std


class SequenceDataset(Dataset):
    def __init__(self, X_seq: np.ndarray, y_seq: np.ndarray):
        self.X = torch.from_numpy(X_seq.astype(np.float32))
        self.y = torch.from_numpy(y_seq.astype(np.int64))

    def __len__(self):
        return self.X.shape[0]

    def __getitem__(self, idx):
        return self.X[idx], self.y[idx]


def load_config(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_dataset(data_dir: Path) -> Tuple[np.ndarray, np.ndarray, dict]:
    X_path = data_dir / "X.npy"
    y_path = data_dir / "y.npy"
    meta_path = data_dir / "meta.json"
    if not X_path.exists() or not y_path.exists():
        raise FileNotFoundError(f"X.npy/y.npy not found in {data_dir}")
    X = np.load(X_path)
    y = np.load(y_path)
    meta = {}
    if meta_path.exists():
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
    return X, y, meta


def infer_class_names(y: np.ndarray, meta: dict) -> List[str]:
    names = meta.get("class_names")
    if isinstance(names, list) and names:
        return [str(x) for x in names]
    uniq = sorted(int(x) for x in np.unique(y))
    if uniq == [0, 1]:
        return ["BENIGN", "ATTACK"]
    return [f"CLASS_{i}" for i in range(max(uniq) + 1)]


def remap_labels(y: np.ndarray, src_names: List[str], dst_names: List[str]) -> np.ndarray:
    idx = {n: i for i, n in enumerate(dst_names)}
    out = np.zeros_like(y, dtype=np.int64)
    for i, v in enumerate(y.astype(np.int64)):
        if v < 0 or v >= len(src_names):
            out[i] = 0
            continue
        out[i] = int(idx.get(src_names[v], 0))
    return out


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


def build_split(X: np.ndarray, y: np.ndarray, meta: dict, T: int, stride: int, train_ratio: float):
    train_slices, test_slices = split_by_files(meta, train_ratio)
    if not train_slices:
        n = X.shape[0]
        cut = int(n * train_ratio)
        train_slices = [(0, cut)]
        test_slices = [(cut, n)]
    X_train, y_train = build_sequences_from_slices(X, y, train_slices, T, stride)
    X_test, y_test = build_sequences_from_slices(X, y, test_slices, T, stride)
    return X_train, y_train, X_test, y_test, train_slices


def fit_standardizer(X: np.ndarray) -> Standardizer:
    mean = X.mean(axis=0)
    std = X.std(axis=0) + 1e-6
    return Standardizer(mean=mean, std=std)


def class_weights(y: np.ndarray, n_cls: int) -> np.ndarray:
    counts = np.bincount(y.astype(np.int64), minlength=n_cls).astype(np.float64)
    counts[counts <= 0] = 1.0
    inv = 1.0 / counts
    w = inv / inv.sum() * n_cls
    return w.astype(np.float32)


def eval_metrics(model, loader, device, class_names: List[str]):
    model.eval()
    ys = []
    preds = []
    with torch.no_grad():
        for Xb, yb in loader:
            Xb = Xb.to(device)
            logits = model(Xb)
            yp = torch.argmax(logits, dim=1).cpu().numpy()
            ys.append(yb.numpy())
            preds.append(yp)
    if not ys:
        return {
            "accuracy": 0.0,
            "macro_precision": 0.0,
            "macro_recall": 0.0,
            "macro_f1": 0.0,
            "per_class": {name: {"precision": 0.0, "recall": 0.0, "f1": 0.0, "support": 0} for name in class_names},
            "confusion_matrix": [[0 for _ in class_names] for _ in class_names],
        }
    y_true = np.concatenate(ys)
    y_pred = np.concatenate(preds)
    return classification_metrics_multiclass(y_true, y_pred, class_names)


def train_one_epoch(model, loader, criterion, optimizer, device):
    model.train()
    total = 0.0
    for Xb, yb in loader:
        Xb = Xb.to(device)
        yb = yb.to(device)
        optimizer.zero_grad()
        logits = model(Xb)
        loss = criterion(logits, yb)
        loss.backward()
        optimizer.step()
        total += loss.item() * Xb.size(0)
    return total / max(len(loader.dataset), 1)


def run_phase(
    phase_name: str,
    model,
    train_loader,
    val_loader,
    class_names: List[str],
    device,
    epochs: int,
    lr: float,
    weight: np.ndarray,
    history: List[dict],
):
    if epochs <= 0 or train_loader is None:
        return None

    criterion = nn.CrossEntropyLoss(weight=torch.tensor(weight, device=device))
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    best = {"score": -1.0, "state": None, "metrics": None}

    for epoch in range(1, epochs + 1):
        loss = train_one_epoch(model, train_loader, criterion, optimizer, device)
        tr = eval_metrics(model, train_loader, device, class_names)
        va = eval_metrics(model, val_loader, device, class_names) if val_loader is not None else tr
        history.append(
            {
                "phase": phase_name,
                "epoch": epoch,
                "loss": round(float(loss), 6),
                "train": tr,
                "val": va,
            }
        )
        score = float(va.get("macro_f1", 0.0))
        if score > best["score"]:
            best["score"] = score
            best["state"] = copy.deepcopy(model.state_dict())
            best["metrics"] = va
        print(
            f"[{phase_name} epoch {epoch}] "
            f"loss={loss:.4f} train_f1={tr['macro_f1']:.4f} val_f1={va['macro_f1']:.4f}"
        )
    return best


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="dl/config.yaml")
    args = ap.parse_args()

    cfg = load_config(Path(args.config))
    ds_cfg = cfg.get("dataset", {}) or {}
    tr_cfg = cfg.get("train", {}) or {}

    random_seed = int(ds_cfg.get("random_seed", 42))
    random.seed(random_seed)
    np.random.seed(random_seed)
    torch.manual_seed(random_seed)

    online_dir = Path(ds_cfg.get("output_dir", "dl/data"))
    if not online_dir.is_absolute():
        online_dir = ROOT / online_dir
    public_dir_cfg = tr_cfg.get("public_data_dir", "")
    public_dir = Path(public_dir_cfg) if public_dir_cfg else None
    if public_dir and not public_dir.is_absolute():
        public_dir = ROOT / public_dir

    seq_len = int(tr_cfg.get("seq_len", 10))
    stride = int(tr_cfg.get("stride", 1))
    batch = int(tr_cfg.get("batch_size", 256))
    train_ratio = float(ds_cfg.get("train_ratio", 0.8))
    hidden = int(tr_cfg.get("hidden", 64))
    kernel = int(tr_cfg.get("kernel", 3))
    dropout = float(tr_cfg.get("dropout", 0.2))
    use_public = bool(tr_cfg.get("use_public_pretrain", True))
    pretrain_epochs = int(tr_cfg.get("pretrain_epochs", 2))
    finetune_epochs = int(tr_cfg.get("finetune_epochs", tr_cfg.get("epochs", 8)))
    pretrain_lr = float(tr_cfg.get("pretrain_lr", tr_cfg.get("lr", 1e-3)))
    finetune_lr = float(tr_cfg.get("finetune_lr", tr_cfg.get("lr", 1e-3)))
    attack_threshold = float(tr_cfg.get("attack_threshold", 0.6))
    benign_class = str(tr_cfg.get("benign_class", "BENIGN")).upper()
    core_attack_classes = [str(x).upper() for x in (tr_cfg.get("core_attack_classes", ["TCP_SYN_FLOOD", "UDP_FLOOD", "ICMP_FLOOD"]) or [])]
    core_attack_classes = [x for x in core_attack_classes if x != benign_class]

    X_on, y_on, meta_on = load_dataset(online_dir)
    if X_on.shape[1] != len(FEATURE_ORDER):
        raise SystemExit("feature size mismatch with FEATURE_ORDER")
    names_on = infer_class_names(y_on, meta_on)

    names_pub = []
    X_pub = y_pub = meta_pub = None
    if use_public and public_dir and (public_dir / "X.npy").exists() and (public_dir / "y.npy").exists():
        X_pub, y_pub, meta_pub = load_dataset(public_dir)
        if X_pub.shape[1] != len(FEATURE_ORDER):
            raise SystemExit("public feature size mismatch with FEATURE_ORDER")
        names_pub = infer_class_names(y_pub, meta_pub)

    class_names = list(dict.fromkeys(names_on + names_pub))
    if benign_class not in class_names:
        class_names = [benign_class] + class_names
    n_cls = len(class_names)

    y_on = remap_labels(y_on, names_on, class_names)
    if y_pub is not None:
        y_pub = remap_labels(y_pub, names_pub, class_names)

    X_on_train, y_on_train, X_on_test, y_on_test, on_train_slices = build_split(
        X_on, y_on, meta_on, seq_len, stride, train_ratio
    )
    if len(y_on_train) == 0:
        raise SystemExit("online train set too small for seq_len")

    # Scaler fit only on online-train raw windows to reduce domain shift.
    on_train_idx = (
        np.concatenate([np.arange(s, e) for s, e in on_train_slices]) if on_train_slices else np.arange(len(X_on))
    )
    scaler = fit_standardizer(X_on[on_train_idx])
    X_on_std = scaler.apply(X_on)
    X_on_train, y_on_train, X_on_test, y_on_test, _ = build_split(
        X_on_std, y_on, meta_on, seq_len, stride, train_ratio
    )

    on_train_loader = DataLoader(SequenceDataset(X_on_train, y_on_train), batch_size=batch, shuffle=True, drop_last=True)
    on_test_loader = (
        DataLoader(SequenceDataset(X_on_test, y_on_test), batch_size=batch, shuffle=False)
        if len(y_on_test)
        else None
    )

    pub_train_loader = None
    pub_test_loader = None
    y_pub_train = np.empty((0,), dtype=np.int64)
    y_pub_test = np.empty((0,), dtype=np.int64)
    if y_pub is not None and X_pub is not None and len(y_pub):
        X_pub_std = scaler.apply(X_pub)
        X_pub_train, y_pub_train, X_pub_test, y_pub_test, _ = build_split(
            X_pub_std, y_pub, meta_pub, seq_len, stride, train_ratio
        )
        if len(y_pub_train):
            pub_train_loader = DataLoader(
                SequenceDataset(X_pub_train, y_pub_train), batch_size=batch, shuffle=True, drop_last=True
            )
        if len(y_pub_test):
            pub_test_loader = DataLoader(SequenceDataset(X_pub_test, y_pub_test), batch_size=batch, shuffle=False)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = CNN1D(
        num_features=X_on.shape[1],
        hidden=hidden,
        kernel=kernel,
        dropout=dropout,
        num_classes=n_cls,
    ).to(device)

    history = []

    best_phase = None
    if pub_train_loader is not None and pretrain_epochs > 0:
        w_pub = class_weights(y_pub_train, n_cls)
        best_phase = run_phase(
            phase_name="pretrain",
            model=model,
            train_loader=pub_train_loader,
            val_loader=pub_test_loader if pub_test_loader is not None else on_test_loader,
            class_names=class_names,
            device=device,
            epochs=pretrain_epochs,
            lr=pretrain_lr,
            weight=w_pub,
            history=history,
        )
        if best_phase and best_phase["state"] is not None:
            model.load_state_dict(best_phase["state"])

    w_on = class_weights(y_on_train, n_cls)
    best_finetune = run_phase(
        phase_name="finetune",
        model=model,
        train_loader=on_train_loader,
        val_loader=on_test_loader,
        class_names=class_names,
        device=device,
        epochs=finetune_epochs,
        lr=finetune_lr,
        weight=w_on,
        history=history,
    )
    if best_finetune and best_finetune["state"] is not None:
        model.load_state_dict(best_finetune["state"])

    train_metrics = eval_metrics(model, on_train_loader, device, class_names)
    test_metrics = eval_metrics(model, on_test_loader, device, class_names) if on_test_loader else {}

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
        "mean": scaler.mean.tolist(),
        "std": scaler.std.tolist(),
        "seq_len": seq_len,
        "class_names": class_names,
        "benign_class": benign_class,
        "attack_threshold": attack_threshold,
        "core_attack_classes": core_attack_classes,
        "model": {
            "hidden": hidden,
            "kernel": kernel,
            "dropout": dropout,
            "num_classes": n_cls,
        },
        "model_version": model_version,
    }
    with open(scaler_out, "w", encoding="utf-8") as f:
        json.dump(scaler_payload, f, ensure_ascii=False, indent=2)

    metrics_payload = {
        "train": train_metrics,
        "test": test_metrics,
        "history": history,
        "class_names": class_names,
    }
    with open(metrics_out, "w", encoding="utf-8") as f:
        json.dump(metrics_payload, f, ensure_ascii=False, indent=2)

    print(f"[ok] class_names={class_names}")
    print(f"[ok] online train={len(y_on_train)} test={len(y_on_test)}")
    if y_pub is not None:
        print(f"[ok] public train={len(y_pub_train)} test={len(y_pub_test)}")
    print(f"[ok] saved model -> {model_out}")
    print(f"[ok] saved scaler -> {scaler_out}")
    print(f"[ok] saved metrics -> {metrics_out}")


if __name__ == "__main__":
    main()
