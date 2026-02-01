#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import torch
import torch.nn as nn


class CNN1D(nn.Module):
    """
    Input: x [B, T, F]
    Internally: transpose to [B, F, T] and apply 1D conv over time.
    Output: logits [B]
    """

    def __init__(self, num_features: int, hidden: int = 64, kernel: int = 3, dropout: float = 0.2):
        super().__init__()
        pad = kernel // 2
        self.net = nn.Sequential(
            nn.Conv1d(num_features, hidden, kernel_size=kernel, padding=pad),
            nn.ReLU(),
            nn.BatchNorm1d(hidden),
            nn.Conv1d(hidden, hidden, kernel_size=kernel, padding=pad),
            nn.ReLU(),
            nn.BatchNorm1d(hidden),
            nn.Conv1d(hidden, hidden * 2, kernel_size=kernel, padding=pad),
            nn.ReLU(),
            nn.BatchNorm1d(hidden * 2),
            nn.AdaptiveAvgPool1d(1),
        )
        self.head = nn.Sequential(
            nn.Flatten(),
            nn.Dropout(dropout),
            nn.Linear(hidden * 2, 1),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = x.transpose(1, 2)  # [B, F, T]
        x = self.net(x)
        x = self.head(x)
        return x.squeeze(1)
