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
    type_confirm_min: float = 0.45
    known_rule_attacks: Set[str] = field(
        default_factory=lambda: {
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
    )
    gate_min_rule_score: float = 0.0
    gate_low_pps: float = 120.0
    gate_low_uniq_src: int = 3
    gate_low_uniq_flow5: int = 30
    gate_low_syn_ratio: float = 0.2
    gate_low_syn_only_ratio: float = 0.05
    gate_streak: int = 3
    gate_sample_every: int = 10
    gate_cooldown_windows: int = 8


@dataclass
class FusionResult:
    final_label: str
    final_attack_type: str
    decision_source: str
    dl_p_attack: Optional[float] = None
    dl_model_version: Optional[str] = None
    dl_error: Optional[str] = None
    dl_type_probs: Optional[Dict[str, float]] = None
    dl_extra_type: Optional[str] = None
    dl_extra_confidence: Optional[float] = None


class FusionEngine:
    def __init__(self, client: Optional[DLClient], settings: FusionSettings):
        self.client = client
        self.settings = settings
        self.buffer = deque(maxlen=settings.seq_len)
        self.low_risk_streak = 0
        self.gated_counter = 0
        self.cooldown_left = 0

    @staticmethod
    def _norm_type(attack_type: str) -> str:
        return str(attack_type or "").strip().upper()

    def _is_known_type(self, attack_type: str) -> bool:
        return self._norm_type(attack_type) in self.settings.known_rule_attacks

    @staticmethod
    def _safe_num(x, default=0.0) -> float:
        try:
            return float(x)
        except Exception:
            return float(default)

    def _enter_cooldown(self) -> None:
        self.cooldown_left = max(self.cooldown_left, int(self.settings.gate_cooldown_windows))

    def _tick_window(self) -> None:
        if self.cooldown_left > 0:
            self.cooldown_left -= 1

    def _is_low_risk_window(self, features: Dict, label: str, score: float) -> bool:
        if label != "benign":
            return False
        if score > self.settings.gate_min_rule_score:
            return False

        pps = self._safe_num(features.get("pps"))
        uniq_src = int(features.get("uniq_src", 0) or 0)
        uniq_flow5 = int(features.get("uniq_flow5", 0) or 0)
        syn_ratio = self._safe_num(features.get("syn_ratio"))
        syn_only_ratio = self._safe_num(features.get("syn_only_ratio"))
        ack_ratio = self._safe_num(features.get("ack_ratio"))
        rst_ratio = self._safe_num(features.get("rst_ratio"))

        base_low = (
            pps < self.settings.gate_low_pps
            and uniq_src <= self.settings.gate_low_uniq_src
            and uniq_flow5 <= self.settings.gate_low_uniq_flow5
            and syn_ratio < self.settings.gate_low_syn_ratio
            and syn_only_ratio < self.settings.gate_low_syn_only_ratio
        )
        if base_low:
            return True

        # SSH-like steady ACK streams are common benign patterns in this lab setup.
        top_dport = features.get("top_dport", []) or []
        ssh_hits = 0.0
        top_total = 0.0
        if isinstance(top_dport, list):
            for item in top_dport[:5]:
                if not isinstance(item, (list, tuple)) or len(item) < 2:
                    continue
                try:
                    dport = int(item[0])
                    cnt = float(item[1] or 0.0)
                except Exception:
                    continue
                top_total += max(cnt, 0.0)
                if dport == 22:
                    ssh_hits += max(cnt, 0.0)
        ssh_dom = ssh_hits >= max(20.0, 0.7 * max(top_total, 1.0))

        ssh_like = (
            uniq_src <= 2
            and uniq_flow5 <= 20
            and pps < 1200.0
            and syn_ratio < 0.08
            and syn_only_ratio < 0.03
            and ack_ratio > 0.7
            and rst_ratio < 0.15
            and ssh_dom
        )
        return ssh_like

    def _should_gate_dl(self, features: Dict, label: str, score: float) -> bool:
        if self.cooldown_left > 0:
            return False

        if self._is_low_risk_window(features, label, score):
            self.low_risk_streak += 1
        else:
            self.low_risk_streak = 0
            return False

        if self.low_risk_streak < int(self.settings.gate_streak):
            return False

        # Safety sampling: every N-th gated low-risk window still goes to DL.
        self.gated_counter += 1
        sample_every = max(1, int(self.settings.gate_sample_every))
        return (self.gated_counter % sample_every) != 0

    def _to_suspect(
        self,
        source: str,
        p_attack: Optional[float] = None,
        model_version: Optional[str] = None,
        dl_error: Optional[str] = None,
        dl_type_probs: Optional[Dict[str, float]] = None,
        dl_extra_type: Optional[str] = None,
        dl_extra_confidence: Optional[float] = None,
    ) -> FusionResult:
        return FusionResult(
            final_label="suspect",
            final_attack_type="SUSPECT",
            decision_source=source,
            dl_p_attack=p_attack,
            dl_model_version=model_version,
            dl_error=dl_error,
            dl_type_probs=dl_type_probs,
            dl_extra_type=dl_extra_type,
            dl_extra_confidence=dl_extra_confidence,
        )

    def _rule_is_strong(self, label: str, attack_type: str, confidence: float) -> bool:
        if label != "attack":
            return False
        if not self._is_known_type(attack_type):
            return False
        return confidence >= self.settings.type_confirm_min

    def update(self, features: Dict, rule_out: Tuple[str, str, float, float, List[str]]) -> FusionResult:
        label, attack_type, score, confidence, reasons = rule_out
        self._tick_window()

        # always update buffer for sequence assembly
        self.buffer.append(features)

        if self._rule_is_strong(label, attack_type, confidence):
            self._enter_cooldown()
            return FusionResult(
                final_label=label,
                final_attack_type=self._norm_type(attack_type),
                decision_source="rules",
            )

        if self.client is None:
            if label in ("attack", "suspect"):
                if label == "attack":
                    self._enter_cooldown()
                return self._to_suspect(source="rules", dl_error="dl_disabled")
            return FusionResult(final_label="benign", final_attack_type="BENIGN", decision_source="rules", dl_error="dl_disabled")

        if len(self.buffer) < self.settings.seq_len:
            if label in ("attack", "suspect"):
                if label == "attack":
                    self._enter_cooldown()
                return self._to_suspect(source="rules", dl_error="seq_too_short")
            return FusionResult(final_label="benign", final_attack_type="BENIGN", decision_source="rules", dl_error="seq_too_short")

        if self._should_gate_dl(features, label, score):
            return FusionResult(
                final_label="benign",
                final_attack_type="BENIGN",
                decision_source="rules",
                dl_error="dl_gated_low_risk",
            )

        result: DLResult = self.client.predict(list(self.buffer))
        if result.error:
            if label in ("attack", "suspect"):
                if label == "attack":
                    self._enter_cooldown()
                return self._to_suspect(source="hybrid", dl_error=result.error)
            return FusionResult(final_label="benign", final_attack_type="BENIGN", decision_source="hybrid", dl_error=result.error)

        p = float(result.p_attack or 0.0)
        rule_type = self._norm_type(attack_type)
        dl_type = self._norm_type(result.attack_type)
        dl_extra_type = self._norm_type(result.extra_type or "")
        dl_extra_conf = float(result.extra_confidence or 0.0)
        confirmed_type = ""
        if label == "attack" and self._is_known_type(rule_type):
            confirmed_type = rule_type
        elif self._is_known_type(dl_type):
            confirmed_type = dl_type

        if p >= self.settings.dl_attack_score:
            if confirmed_type:
                final_label = "attack"
                final_attack_type = confirmed_type
            else:
                final_label = "suspect"
                final_attack_type = "SUSPECT"
        elif p >= self.settings.dl_suspect_score:
            final_label = "suspect"
            final_attack_type = "SUSPECT"
        else:
            final_label = "benign"
            final_attack_type = "BENIGN"

        decision_source = "dl" if label == "benign" else "hybrid"

        if final_label == "attack":
            self._enter_cooldown()

        return FusionResult(
            final_label=final_label,
            final_attack_type=final_attack_type,
            decision_source=decision_source,
            dl_p_attack=p,
            dl_model_version=result.model_version,
            dl_type_probs=result.type_probs,
            dl_extra_type=dl_extra_type if dl_extra_type else None,
            dl_extra_confidence=round(dl_extra_conf, 6) if dl_extra_type else None,
        )
