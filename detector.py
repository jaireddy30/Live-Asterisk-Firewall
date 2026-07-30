"""
====================================================
LIVE ASTERISK FIREWALL

detector.py

Stateful attack detection engine with LightGBM ML Integration.
Thresholds are fully configurable in config.py
====================================================
"""

import os
from collections import defaultdict
from datetime import datetime

try:
    import joblib
    import pandas as pd
except ImportError:
    joblib = None
    pd = None

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
        self.ip_user_sets = defaultdict(set)
        
        # Load LightGBM Machine Learning Model if available
        self.ml_model = None
        model_paths = ["lightgbm_log_model.pkl", "Live-Asterisk-Firewall-main/lightgbm_log_model.pkl"]
        for mp in model_paths:
            if os.path.exists(mp) and joblib:
                try:
                    self.ml_model = joblib.load(mp)
                    print(f"[INFO] LightGBM ML Model successfully loaded from '{mp}'!")
                    break
                except Exception as e:
                    print(f"[WARNING] Could not load LightGBM model from '{mp}': {e}")

    def predict_ml_threat(self, ip):
        """
        Uses LightGBM model to evaluate threat probability for an IP address.
        Returns attack probability float (0.0 to 1.0)
        """
        if not self.ml_model or not pd:
            return 0.0
            
        stats = self.attack_db[ip]
        total_events = sum(stats.values())
        failed_auth = stats["auth_fail"]
        success_auth = stats["auth_success"]
        unique_users = len(self.ip_user_sets[ip])
        fail_ratio = failed_auth / total_events if total_events > 0 else 0.0

        features = pd.DataFrame([{
            "total_events": total_events,
            "failed_auth": failed_auth,
            "success_auth": success_auth,
            "unique_users": unique_users,
            "fail_ratio": fail_ratio
        }])

        try:
            probability = self.ml_model.predict_proba(features)[0][1]
            return probability
        except Exception:
            return 0.0

    def detect(self, event):
        """
        Analyse a parsed event and return an attack dict
        if an attack threshold or ML threat probability threshold has been crossed.
        """

        ip         = event.get("source_ip", "UNKNOWN")
        event_type = event.get("event",     "OTHER")
        method     = event.get("method",    "UNKNOWN")
        username   = event.get("account_id","unknown")

        # Skip internal / unknown IPs
        if not ip or ip in ("UNKNOWN", "127.0.0.1", "0.0.0.0"):
            return None

        # Track targeted usernames
        if username and username != "unknown":
            self.ip_user_sets[ip].add(username)

        attack   = None
        severity = None

        # --------------------------------------------------
        # 1. BRUTE FORCE — failed authentication
        # --------------------------------------------------
        if event_type == "FAILED_AUTH":
            self.attack_db[ip]["auth_fail"] += 1
            if self.attack_db[ip]["auth_fail"] >= AUTH_FAIL_THRESHOLD:
                attack   = "BRUTE_FORCE"
                severity = "HIGH"

        # --------------------------------------------------
        # 2. ACL VIOLATION
        # --------------------------------------------------
        elif event_type == "ACL_BLOCKED":
            self.attack_db[ip]["acl"] += 1
            if self.attack_db[ip]["acl"] >= ACL_BLOCK_THRESHOLD:
                attack   = "ACL_VIOLATION"
                severity = "HIGH"

        # --------------------------------------------------
        # 3. UNKNOWN ENDPOINT — scanning unknown SIP accounts
        # --------------------------------------------------
        elif event_type == "UNKNOWN_ENDPOINT":
            self.attack_db[ip]["unknown"] += 1
            if self.attack_db[ip]["unknown"] >= AUTH_FAIL_THRESHOLD:
                attack   = "SIP_SCANNING"
                severity = "MEDIUM"

        # --------------------------------------------------
        # 4. TOLL FRAUD — suspicious outbound calls
        # --------------------------------------------------
        elif event_type == "TOLL_FRAUD":
            self.attack_db[ip]["toll_fraud"] += 1
            if self.attack_db[ip]["toll_fraud"] >= TOLL_FRAUD_THRESHOLD:
                attack   = "TOLL_FRAUD"
                severity = "CRITICAL"

        # --------------------------------------------------
        # 5. INVITE FLOOD
        # --------------------------------------------------
        elif method == "INVITE" or event_type == "INVITE":
            self.attack_db[ip]["invite"] += 1
            if self.attack_db[ip]["invite"] >= INVITE_THRESHOLD:
                attack   = "INVITE_FLOOD"
                severity = "HIGH"

        # --------------------------------------------------
        # 6. REGISTER FLOOD
        # --------------------------------------------------
        elif method == "REGISTER" or event_type == "REGISTER":
            self.attack_db[ip]["register"] += 1
            if self.attack_db[ip]["register"] >= REGISTER_THRESHOLD:
                attack   = "REGISTER_FLOOD"
                severity = "MEDIUM"

        # --------------------------------------------------
        # 7. OPTIONS FLOOD
        # --------------------------------------------------
        elif method == "OPTIONS" or event_type == "OPTIONS":
            self.attack_db[ip]["options"] += 1
            if self.attack_db[ip]["options"] >= OPTIONS_THRESHOLD:
                attack   = "OPTIONS_FLOOD"
                severity = "LOW"
        else:
            self.attack_db[ip]["normal"] += 1

        # --------------------------------------------------
        # 8. LIGHTGBM MACHINE LEARNING ANOMALY DETECTION
        # --------------------------------------------------
        if not attack and self.ml_model:
            ml_prob = self.predict_ml_threat(ip)
            if ml_prob >= 0.85:  # Trigger ML attack flag if LightGBM probability >= 85%
                attack   = "LIGHTGBM_ML_ANOMALY"
                severity = "HIGH"

        if attack:
            # Reset counters after detection
            self.attack_db[ip] = defaultdict(int)
            self.ip_user_sets[ip] = set()

            return {
                "ip":       ip,
                "attack":   attack,
                "severity": severity,
                "event":    event,
                "time":     datetime.now().isoformat(),
            }

        return None
