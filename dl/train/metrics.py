#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict

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


def classification_metrics(y_true: np.ndarray, y_score: np.ndarray, threshold: float = 0.5) -> Dict[str, float]:
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
