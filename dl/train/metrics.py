#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, List

import numpy as np


def roc_auc_score(y_true: np.ndarray, y_score: np.ndarray) -> float:
    y_true = y_true.astype(np.int64)
    y_score = y_score.astype(np.float64)
    pos = y_true.sum()
    neg = len(y_true) - pos
    if pos == 0 or neg == 0:
        return 0.0
    order = np.argsort(-y_score)
    y_true = y_true[order]
    cum_pos = np.cumsum(y_true)
    cum_neg = np.cumsum(1 - y_true)
    tpr = cum_pos / pos
    fpr = cum_neg / neg
    tpr = np.concatenate([[0.0], tpr, [1.0]])
    fpr = np.concatenate([[0.0], fpr, [1.0]])
    return float(np.trapz(tpr, fpr))


def classification_metrics_binary(y_true: np.ndarray, y_score: np.ndarray, threshold: float = 0.5) -> Dict[str, float]:
    y_true = y_true.astype(np.int64)
    y_score = y_score.astype(np.float64)
    preds = (y_score >= threshold).astype(np.int64)

    tp = int(((preds == 1) & (y_true == 1)).sum())
    tn = int(((preds == 0) & (y_true == 0)).sum())
    fp = int(((preds == 1) & (y_true == 0)).sum())
    fn = int(((preds == 0) & (y_true == 1)).sum())

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    acc = (tp + tn) / max(tp + tn + fp + fn, 1)

    auc = roc_auc_score(y_true, y_score)

    return {
        "accuracy": round(acc, 6),
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        "auc": round(auc, 6),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
    }


def _safe_div(a: float, b: float) -> float:
    return float(a / b) if b else 0.0


def classification_metrics_multiclass(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    class_names: List[str],
) -> Dict[str, object]:
    y_true = y_true.astype(np.int64)
    y_pred = y_pred.astype(np.int64)
    n_cls = len(class_names)
    cm = np.zeros((n_cls, n_cls), dtype=np.int64)
    for yt, yp in zip(y_true, y_pred):
        if 0 <= yt < n_cls and 0 <= yp < n_cls:
            cm[yt, yp] += 1

    total = int(cm.sum())
    accuracy = _safe_div(float(np.trace(cm)), float(total))

    per_class = {}
    p_sum = 0.0
    r_sum = 0.0
    f1_sum = 0.0
    valid_cls = 0
    for i, name in enumerate(class_names):
        tp = int(cm[i, i])
        fp = int(cm[:, i].sum() - tp)
        fn = int(cm[i, :].sum() - tp)
        support = int(cm[i, :].sum())
        precision = _safe_div(tp, tp + fp)
        recall = _safe_div(tp, tp + fn)
        f1 = _safe_div(2 * precision * recall, precision + recall) if (precision + recall) else 0.0
        per_class[name] = {
            "precision": round(precision, 6),
            "recall": round(recall, 6),
            "f1": round(f1, 6),
            "support": support,
        }
        if support > 0:
            p_sum += precision
            r_sum += recall
            f1_sum += f1
            valid_cls += 1

    macro_p = _safe_div(p_sum, valid_cls)
    macro_r = _safe_div(r_sum, valid_cls)
    macro_f1 = _safe_div(f1_sum, valid_cls)

    return {
        "accuracy": round(accuracy, 6),
        "macro_precision": round(macro_p, 6),
        "macro_recall": round(macro_r, 6),
        "macro_f1": round(macro_f1, 6),
        "per_class": per_class,
        "confusion_matrix": cm.tolist(),
    }
