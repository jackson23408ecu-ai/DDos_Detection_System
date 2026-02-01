#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from dataclasses import dataclass, field
from collections import deque
from typing import Dict, List, Optional, Set, Tuple

from dl.integration.dl_client import DLClient, DLResult


@dataclass
class FusionSettings:
    seq_len: int = 10
    dl_attack_score: float = 0.7
    dl_suspect_score: float = 0.5
    rule_confidence_min: float = 0.6
    known_rule_attacks: Set[str] = field(default_factory=lambda: {"UDP_FLOOD", "TCP_SYN_FLOOD", "ICMP_FLOOD"})


@dataclass
class FusionResult:
    final_label: str
    final_attack_type: str
    decision_source: str
    dl_p_attack: Optional[float] = None
    dl_model_version: Optional[str] = None
    dl_error: Optional[str] = None


class FusionEngine:
    def __init__(self, client: Optional[DLClient], settings: FusionSettings):
        self.client = client
        self.settings = settings
        self.buffer = deque(maxlen=settings.seq_len)

    def _rule_is_strong(self, label: str, attack_type: str, confidence: float) -> bool:
        if label != "attack":
            return False
        if attack_type not in self.settings.known_rule_attacks:
            return False
        return confidence >= self.settings.rule_confidence_min

    def update(self, features: Dict, rule_out: Tuple[str, str, float, float, List[str]]) -> FusionResult:
        label, attack_type, score, confidence, reasons = rule_out

        # always update buffer for sequence assembly
        self.buffer.append(features)

        if self._rule_is_strong(label, attack_type, confidence):
            return FusionResult(
                final_label=label,
                final_attack_type=attack_type,
                decision_source="rules",
            )

        if self.client is None:
            return FusionResult(
                final_label=label,
                final_attack_type=attack_type,
                decision_source="rules",
                dl_error="dl_disabled",
            )

        if len(self.buffer) < self.settings.seq_len:
            return FusionResult(
                final_label=label,
                final_attack_type=attack_type,
                decision_source="rules",
                dl_error="seq_too_short",
            )

        result: DLResult = self.client.predict(list(self.buffer))
        if result.error:
            return FusionResult(
                final_label=label,
                final_attack_type=attack_type,
                decision_source="rules",
                dl_error=result.error,
            )

        p = float(result.p_attack or 0.0)
        if p >= self.settings.dl_attack_score:
            final_label = "attack"
            final_attack_type = result.attack_type or "UNKNOWN"
        elif p >= self.settings.dl_suspect_score:
            final_label = "suspect"
            final_attack_type = "SUSPECT"
        else:
            final_label = "benign"
            final_attack_type = "BENIGN"

        decision_source = "dl" if label == "benign" else "hybrid"

        return FusionResult(
            final_label=final_label,
            final_attack_type=final_attack_type,
            decision_source=decision_source,
            dl_p_attack=p,
            dl_model_version=result.model_version,
        )
