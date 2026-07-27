"""
====================================================
LIVE ASTERISK FIREWALL

detector.py

Stateful attack detection engine.
Thresholds are fully configurable in config.py
====================================================
"""

from collections import defaultdict
from datetime    import datetime

from config import (
    INVITE_THRESHOLD,
    AUTH_FAIL_THRESHOLD,
    REGISTER_THRESHOLD,
    OPTIONS_THRESHOLD,
    TOLL_FRAUD_THRESHOLD,
    ACL_BLOCK_THRESHOLD,
)


class Detector:

    def __init__(self):
        # Per-IP counters for stateful tracking
        self.attack_db = defaultdict(lambda: defaultdict(int))

    def detect(self, event):
        """
        Analyse a parsed event and return an attack dict
        if an attack threshold has been crossed, else None.

        Attack dict keys:
            ip        — source IP
            attack    — attack type string
            severity  — LOW / MEDIUM / HIGH / CRITICAL
            event     — the original parsed event
        """

        ip         = event.get("source_ip", "UNKNOWN")
        event_type = event.get("event",     "OTHER")
        method     = event.get("method",    "UNKNOWN")

        # Skip internal / unknown IPs
        if not ip or ip in ("UNKNOWN", "127.0.0.1", "0.0.0.0"):
            return None

        attack   = None
        severity = None

        # --------------------------------------------------
        # BRUTE FORCE — failed authentication
        # --------------------------------------------------
        if event_type == "FAILED_AUTH":
            self.attack_db[ip]["auth_fail"] += 1
            if self.attack_db[ip]["auth_fail"] >= AUTH_FAIL_THRESHOLD:
                attack   = "BRUTE_FORCE"
                severity = "HIGH"

        # --------------------------------------------------
        # ACL VIOLATION
        # --------------------------------------------------
        elif event_type == "ACL_BLOCKED":
            self.attack_db[ip]["acl"] += 1
            if self.attack_db[ip]["acl"] >= ACL_BLOCK_THRESHOLD:
                attack   = "ACL_VIOLATION"
                severity = "HIGH"

        # --------------------------------------------------
        # UNKNOWN ENDPOINT — scanning unknown SIP accounts
        # --------------------------------------------------
        elif event_type == "UNKNOWN_ENDPOINT":
            self.attack_db[ip]["unknown"] += 1
            if self.attack_db[ip]["unknown"] >= AUTH_FAIL_THRESHOLD:
                attack   = "SIP_SCANNING"
                severity = "MEDIUM"

        # --------------------------------------------------
        # TOLL FRAUD — suspicious outbound calls
        # --------------------------------------------------
        elif event_type == "TOLL_FRAUD":
            self.attack_db[ip]["toll_fraud"] += 1
            if self.attack_db[ip]["toll_fraud"] >= TOLL_FRAUD_THRESHOLD:
                attack   = "TOLL_FRAUD"
                severity = "CRITICAL"

        # --------------------------------------------------
        # INVITE FLOOD — too many INVITEs from same IP
        # --------------------------------------------------
        elif method == "INVITE" or event_type == "INVITE":
            self.attack_db[ip]["invite"] += 1
            if self.attack_db[ip]["invite"] >= INVITE_THRESHOLD:
                attack   = "INVITE_FLOOD"
                severity = "HIGH"

        # --------------------------------------------------
        # REGISTER FLOOD — too many REGISTERs from same IP
        # --------------------------------------------------
        elif method == "REGISTER" or event_type == "REGISTER":
            self.attack_db[ip]["register"] += 1
            if self.attack_db[ip]["register"] >= REGISTER_THRESHOLD:
                attack   = "REGISTER_FLOOD"
                severity = "MEDIUM"

        # --------------------------------------------------
        # OPTIONS FLOOD — too many OPTIONS from same IP
        # --------------------------------------------------
        elif method == "OPTIONS" or event_type == "OPTIONS":
            self.attack_db[ip]["options"] += 1
            if self.attack_db[ip]["options"] >= OPTIONS_THRESHOLD:
                attack   = "OPTIONS_FLOOD"
                severity = "LOW"

        if attack:
            # Reset counter after detection
            self.attack_db[ip] = defaultdict(int)

            return {
                "ip":       ip,
                "attack":   attack,
                "severity": severity,
                "event":    event,
                "time":     datetime.now().isoformat(),
            }

        return None
