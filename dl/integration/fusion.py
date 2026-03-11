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
    dl_type_confirm_min: float = 0.6
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
    enable_low_risk_gate: bool = False
    dl_error_as_suspect: bool = True
    dl_warmup_pad: bool = True


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
        if self._is_low_risk_window(features, label, score):
            self.low_risk_streak += 1
        else:
            self.low_risk_streak = 0
            if self.cooldown_left > 0:
                return False
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

    def _build_seq_for_infer(self) -> Optional[List[Dict]]:
        if len(self.buffer) >= self.settings.seq_len:
            return list(self.buffer)[-self.settings.seq_len :]
        if not self.settings.dl_warmup_pad:
            return None
        if not self.buffer:
            return None
        pad_n = self.settings.seq_len - len(self.buffer)
        first = self.buffer[0]
        return [first] * pad_n + list(self.buffer)

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

        # Empty/silent windows should not trigger DL alerts.
        pps_now = self._safe_num(features.get("pps"))
        pkt_now = self._safe_num(features.get("pkt_cnt"))
        if label == "benign" and (pps_now <= 0.0 or pkt_now <= 0.0):
            return FusionResult(
                final_label="benign",
                final_attack_type="BENIGN",
                decision_source="rules",
                dl_error="dl_gated_empty_window",
            )

        if self._rule_is_strong(label, attack_type, confidence):
            self._enter_cooldown()
            return FusionResult(
                final_label=label,
                final_attack_type=self._norm_type(attack_type),
                decision_source="rules",
            )

        # Optional low-risk gate. Keep disabled by default so DL can backstop slow/rare attacks.
        if self.settings.enable_low_risk_gate and label == "benign" and float(score or 0.0) <= 0.0:
            pps = self._safe_num(features.get("pps"))
            uniq_src = int(features.get("uniq_src", 0) or 0)
            uniq_flow5 = int(features.get("uniq_flow5", 0) or 0)
            syn_ratio = self._safe_num(features.get("syn_ratio"))
            syn_only_ratio = self._safe_num(features.get("syn_only_ratio"))
            tcp_cnt = self._safe_num(features.get("tcp_cnt"))
            proto_cnt = features.get("proto_cnt", {}) or {}
            udp_cnt = self._safe_num(proto_cnt.get("17", proto_cnt.get(17, 0)))
            icmp_cnt = self._safe_num(proto_cnt.get("1", proto_cnt.get(1, 0)))
            total = max(1.0, tcp_cnt + udp_cnt + icmp_cnt)
            tcp_ratio = tcp_cnt / total
            udp_ratio = udp_cnt / total
            icmp_ratio = icmp_cnt / total

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
            ssh_dom = ssh_hits >= max(15.0, 0.65 * max(top_total, 1.0))

            if (
                pps < 260.0
                and uniq_src <= 3
                and uniq_flow5 <= 24
                and syn_ratio < 0.12
                and syn_only_ratio < 0.04
                and udp_ratio < 0.35
                and icmp_ratio < 0.25
                and tcp_ratio > 0.60
                and ssh_dom
            ):
                return FusionResult(
                    final_label="benign",
                    final_attack_type="BENIGN",
                    decision_source="rules",
                    dl_error="dl_hard_gated_low_risk",
                )

        if self.client is None:
            if label in ("attack", "suspect"):
                if label == "attack":
                    self._enter_cooldown()
                return self._to_suspect(source="rules", dl_error="dl_disabled")
            return FusionResult(final_label="benign", final_attack_type="BENIGN", decision_source="rules", dl_error="dl_disabled")

        seq = self._build_seq_for_infer()
        if seq is None:
            if label in ("attack", "suspect"):
                if label == "attack":
                    self._enter_cooldown()
                return self._to_suspect(source="rules", dl_error="seq_too_short")
            return FusionResult(final_label="benign", final_attack_type="BENIGN", decision_source="rules", dl_error="seq_too_short")

        if self.settings.enable_low_risk_gate and self._should_gate_dl(features, label, score):
            return FusionResult(
                final_label="benign",
                final_attack_type="BENIGN",
                decision_source="rules",
                dl_error="dl_gated_low_risk",
            )

        result: DLResult = self.client.predict(seq)
        if result.error:
            if label in ("attack", "suspect"):
                if label == "attack":
                    self._enter_cooldown()
                return self._to_suspect(source="hybrid", dl_error=result.error)
            if self.settings.dl_error_as_suspect and (pps_now > 0.0 and pkt_now > 0.0):
                return self._to_suspect(source="hybrid", dl_error=result.error)
            return FusionResult(final_label="benign", final_attack_type="BENIGN", decision_source="hybrid", dl_error=result.error)

        p = float(result.p_attack or 0.0)
        rule_type = self._norm_type(attack_type)
        dl_type = self._norm_type(result.attack_type)
        dl_extra_type = self._norm_type(result.extra_type or "")
        dl_extra_conf = float(result.extra_confidence or 0.0)
        dl_type_prob = 0.0
        if isinstance(result.type_probs, dict):
            dl_type_prob = self._safe_num(result.type_probs.get(dl_type, 0.0))
        p_fused = p
        dl_label = str(result.label or "").strip().lower()
        confirmed_type = ""
        if label == "attack" and self._is_known_type(rule_type):
            confirmed_type = rule_type
        elif self._is_known_type(dl_type) and dl_type_prob >= self.settings.dl_type_confirm_min:
            confirmed_type = dl_type

        # Prefer the DL model's own binary decision to avoid suppressing
        # model-positive windows in dl-only validation mode.
        if dl_label == "attack":
            final_label = "attack"
            if confirmed_type:
                final_attack_type = confirmed_type
            elif dl_type and dl_type != "BENIGN":
                final_attack_type = dl_type
            else:
                final_attack_type = "UNKNOWN_ATTACK"
        elif p_fused >= self.settings.dl_attack_score:
            final_label = "attack"
            if confirmed_type:
                final_attack_type = confirmed_type
            elif dl_type and dl_type != "BENIGN":
                final_attack_type = dl_type
            else:
                final_attack_type = "UNKNOWN_ATTACK"
        elif p_fused >= self.settings.dl_suspect_score:
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
            dl_p_attack=p_fused,
            dl_model_version=result.model_version,
            dl_type_probs=result.type_probs,
            dl_extra_type=dl_extra_type if dl_extra_type else None,
            dl_extra_confidence=round(dl_extra_conf, 6) if dl_extra_type else None,
        )
