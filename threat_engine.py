"""
====================================================
LIVE ASTERISK FIREWALL

threat_engine.py

Stateful, multi-layer behavioral threat assessment
engine for SIP call analysis.

Detection Layers:
  1. Static rules        — sanity checks on call fields
  2. Country risk tiers  — 4-level risk from E.164 prefix
  3. Premium-rate regex  — regex matching premium-rate patterns
  4. Time-of-day         — after-hours risk elevation
  5. Velocity detection  — calls-per-minute sliding window
  6. Multi-destination   — same caller hitting many extensions
  7. Sequential dialing  — numeric scan pattern detection
  8. Relay fraud         — inbound + outbound to premium number
  +  Reputation memory   — persistent per-caller score with decay

Author: Jai
====================================================
"""

import re
import time

from collections import defaultdict, deque
from datetime    import datetime


# ============================================================
# Country Risk Tiers (from E.164 phone prefix)
# Tier 0 = trusted / domestic
# Tier 1 = low risk international
# Tier 2 = elevated risk
# Tier 3 = high-risk / frequently abused
# ============================================================

COUNTRY_RISK = {
    # Tier 0
    "91":  (0, "India"),
    "1":   (0, "USA / Canada"),
    "44":  (0, "United Kingdom"),
    "61":  (0, "Australia"),
    "49":  (0, "Germany"),
    "33":  (0, "France"),
    "39":  (0, "Italy"),
    "34":  (0, "Spain"),
    "81":  (0, "Japan"),
    "82":  (0, "South Korea"),
    "65":  (0, "Singapore"),
    "64":  (0, "New Zealand"),
    "41":  (0, "Switzerland"),
    "31":  (0, "Netherlands"),
    "46":  (0, "Sweden"),
    "47":  (0, "Norway"),
    "45":  (0, "Denmark"),
    "32":  (0, "Belgium"),
    "43":  (0, "Austria"),
    "48":  (0, "Poland"),
    "55":  (0, "Brazil"),
    "52":  (0, "Mexico"),
    "86":  (0, "China"),
    "60":  (0, "Malaysia"),
    "66":  (0, "Thailand"),
    "62":  (0, "Indonesia"),
    "63":  (0, "Philippines"),
    "84":  (0, "Vietnam"),
    "94":  (0, "Sri Lanka"),
    "880": (0, "Bangladesh"),
    "92":  (0, "Pakistan"),
    "90":  (0, "Turkey"),
    "972": (0, "Israel"),
    "27":  (0, "South Africa"),
    "20":  (0, "Egypt"),
    "234": (0, "Nigeria"),
    "380": (0, "Ukraine"),
    "7":   (0, "Russia"),
    # Tier 1
    "54":  (1, "Argentina"),
    "56":  (1, "Chile"),
    "57":  (1, "Colombia"),
    "51":  (1, "Peru"),
    "30":  (1, "Greece"),
    "36":  (1, "Hungary"),
    "40":  (1, "Romania"),
    "420": (1, "Czech Republic"),
    "421": (1, "Slovakia"),
    "385": (1, "Croatia"),
    "386": (1, "Slovenia"),
    "381": (1, "Serbia"),
    "994": (1, "Azerbaijan"),
    "995": (1, "Georgia"),
    "996": (1, "Kyrgyzstan"),
    "998": (1, "Uzbekistan"),
    "993": (1, "Turkmenistan"),
    "992": (1, "Tajikistan"),
    "977": (1, "Nepal"),
    "98":  (1, "Iran"),
    "212": (1, "Morocco"),
    "213": (1, "Algeria"),
    "216": (1, "Tunisia"),
    "254": (1, "Kenya"),
    "255": (1, "Tanzania"),
    "256": (1, "Uganda"),
    "263": (1, "Zimbabwe"),
    "264": (1, "Namibia"),
    "962": (1, "Jordan"),
    "961": (1, "Lebanon"),
    "965": (1, "Kuwait"),
    "966": (1, "Saudi Arabia"),
    "971": (1, "UAE"),
    "973": (1, "Bahrain"),
    "974": (1, "Qatar"),
    "968": (1, "Oman"),
    "886": (1, "Taiwan"),
    "960": (1, "Maldives"),
    # Tier 2
    "243": (2, "DR Congo"),
    "225": (2, "Ivory Coast"),
    "221": (2, "Senegal"),
    "237": (2, "Cameroon"),
    "233": (2, "Ghana"),
    "250": (2, "Rwanda"),
    "53":  (2, "Cuba"),
    "58":  (2, "Venezuela"),
    "95":  (2, "Myanmar"),
    "93":  (2, "Afghanistan"),
    "850": (2, "North Korea"),
    "383": (2, "Kosovo"),
    # Tier 3
    "963": (3, "Syria"),
    "964": (3, "Iraq"),
    "967": (3, "Yemen"),
    "218": (3, "Libya"),
    "249": (3, "Sudan"),
    "252": (3, "Somalia"),
    "682": (3, "Cook Islands — premium arbitrage"),
    "676": (3, "Tonga — premium arbitrage"),
    "688": (3, "Tuvalu — premium arbitrage"),
    "690": (3, "Tokelau — premium arbitrage"),
    "677": (3, "Solomon Islands — premium arbitrage"),
    "674": (3, "Nauru — premium arbitrage"),
    "678": (3, "Vanuatu — premium arbitrage"),
    "357": (3, "Cyprus — premium-rate abuse"),
    "372": (3, "Estonia — premium-rate abuse"),
    "373": (3, "Moldova — premium-rate abuse"),
    "375": (3, "Belarus — IPRN abuse"),
    "900": (3, "US Premium-rate 900"),
    "976": (3, "US Premium-rate 976"),
}

# Regex-based premium-rate patterns
PREMIUM_RATE_PATTERNS = [
    re.compile(r"^1900"),
    re.compile(r"^1976"),
    re.compile(r"^44(843|844|845|870|871|872|873|874|875|876|877|878|879|909|118)"),
    re.compile(r"^353(818|1890)"),
    re.compile(r"^3590900"),
    re.compile(r"^37(230|270|260|261)"),
]

# ============================================================
# Thresholds
# ============================================================

VELOCITY_WINDOW_SECONDS  = 60
VELOCITY_WARN_THRESHOLD  = 5
VELOCITY_HIGH_THRESHOLD  = 10
VELOCITY_CRIT_THRESHOLD  = 20

MULTIDST_WARN_THRESHOLD  = 4
MULTIDST_HIGH_THRESHOLD  = 8

SEQ_SCAN_WINDOW_SECONDS  = 120
SEQ_SCAN_MIN_SAMPLES     = 3

REPUTATION_MAX_SCORE     = 80
REPUTATION_DECAY_SECONDS = 3600

AFTER_HOURS_START = 22
AFTER_HOURS_END   = 6

COUNTRY_TIER_SCORE = {0: 0, 1: 3, 2: 8, 3: 22}


# ============================================================
# ThreatEngine
# ============================================================

class ThreatEngine:
    """
    Stateful behavioral threat assessment engine.
    Maintains per-caller history across calls.

    Usage:
        engine = ThreatEngine()
        result = engine.assess(caller_id, exten, context,
                               direction, src_ip, event, uniqueid)
        # result: {level, score, reason, flags, breakdown}
    """

    def __init__(self):
        self._caller_velocity     = defaultdict(deque)
        self._caller_destinations = defaultdict(set)
        self._caller_seq          = defaultdict(deque)
        self._reputation          = {}
        self._active_inbound      = {}
        self._concurrent_outbound = {}

    # ──────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────

    def assess(self, caller_id, exten, context, direction,
               src_ip, event="INVITE", uniqueid=""):

        now     = time.time()
        caller  = self._normalise(caller_id)
        exten_n = self._normalise(exten)
        score   = 0
        flags   = []
        breakdown = {}

        # Layer 1 — Static rules
        s, f = self._layer_static(caller_id, exten, direction)
        score += s; flags += f; breakdown["static"] = s

        # Layer 2 — Country risk
        s, f = self._layer_country_risk(caller_id, exten, direction)
        score += s; flags += f; breakdown["country"] = s

        # Layer 3 — Premium-rate
        s, f = self._layer_premium_rate(caller_id, exten, direction)
        score += s; flags += f; breakdown["premium_rate"] = s

        # Layer 4 — Time of day
        s, f = self._layer_time_of_day()
        score += s; flags += f; breakdown["time_of_day"] = s

        # Layer 5 — Velocity
        s, f = self._layer_velocity(caller, now)
        score += s; flags += f; breakdown["velocity"] = s

        # Layer 6 — Multi-destination
        if event == "INVITE" and direction == "OUTGOING" and exten_n:
            self._caller_destinations[caller].add(exten_n)
        s, f = self._layer_multi_destination(caller)
        score += s; flags += f; breakdown["multi_dst"] = s

        # Layer 7 — Sequential scan
        if event == "INVITE" and exten_n and exten_n.isdigit():
            self._caller_seq[caller].append((now, int(exten_n)))
            self._prune_seq(caller, now)
        s, f = self._layer_sequential_scan(caller)
        score += s; flags += f; breakdown["seq_scan"] = s

        # Layer 8 — Relay fraud
        if event == "INVITE":
            if direction == "INCOMING":
                self._active_inbound[caller] = exten_n
            elif direction == "OUTGOING" and self._active_inbound:
                self._concurrent_outbound[caller] = exten_n
        s, f = self._layer_relay_fraud(caller, exten_n, direction)
        score += s; flags += f; breakdown["relay_fraud"] = s

        # Reputation memory
        rep_bonus = self._get_reputation_bonus(caller, now)
        score += rep_bonus
        breakdown["reputation"] = rep_bonus
        if rep_bonus > 0:
            flags.append(f"Repeat offender — reputation score +{rep_bonus}")

        if event == "INVITE":
            self._update_reputation(caller, score, now)

        level, reason = self._resolve_level(score, flags)

        return {
            "level":     level,
            "score":     score,
            "reason":    reason,
            "flags":     flags,
            "breakdown": breakdown,
        }

    # ──────────────────────────────────────────────────────
    # Detection Layers
    # ──────────────────────────────────────────────────────

    @staticmethod
    def _layer_static(caller_id, exten, direction):
        score = 0
        flags = []
        caller_clean = str(caller_id or "").lstrip("+").strip()
        exten_clean  = str(exten     or "").lstrip("+").strip()

        if not caller_id or caller_id in ("<unknown>", "unknown", "", "anonymous"):
            score += 8
            flags.append("Anonymous / hidden caller ID")

        if exten in ("s", "i") and direction == "INCOMING":
            score += 10
            flags.append(f"SIP scan marker extension '{exten}' on inbound")

        if caller_clean and not caller_clean.replace("-", "").replace("_", "").isdigit():
            if caller_clean.lower() not in ("unknown", "anonymous", ""):
                score += 10
                flags.append("Non-numeric caller ID — likely SIP endpoint token")

        if len(caller_clean) > 15:
            score += 5
            flags.append(f"Oversized caller ID ({len(caller_clean)} chars) — possible spoofing")

        if len(exten_clean) > 15:
            score += 5
            flags.append(f"Oversized extension ({len(exten_clean)} chars)")

        if caller_clean and caller_clean.replace("0", "") == "":
            score += 8
            flags.append("Caller ID is all zeros — likely spoofed")

        return score, flags

    @staticmethod
    def _layer_country_risk(caller_id, exten, direction):
        score = 0
        flags = []

        raw = str(exten if direction == "OUTGOING" else (caller_id or "")).lstrip("+").strip()
        if not raw or not raw.isdigit():
            return 0, []

        if raw.startswith("00"):
            raw = raw[2:]
        elif raw.startswith("0"):
            raw = raw[1:]

        tier, country = None, None
        for length in (3, 2, 1):
            prefix = raw[:length]
            if prefix in COUNTRY_RISK:
                tier, country = COUNTRY_RISK[prefix]
                break

        if tier is None:
            score += 2
            flags.append("Unknown country prefix — unrecognised E.164 number")
            return score, flags

        contrib = COUNTRY_TIER_SCORE[tier]
        score  += contrib

        if tier == 3:
            flags.append(f"High-risk destination country: {country} (Tier 3)")
        elif tier == 2:
            flags.append(f"Elevated-risk country: {country} (Tier 2)")
        elif tier == 1 and contrib > 0:
            flags.append(f"International call: {country}")

        return score, flags

    @staticmethod
    def _layer_premium_rate(caller_id, exten, direction):
        score = 0
        flags = []

        numbers = []
        if direction == "OUTGOING" and exten:
            numbers.append(("destination", str(exten).lstrip("+").strip()))
        if caller_id:
            numbers.append(("caller", str(caller_id).lstrip("+").strip()))

        for label, number in numbers:
            if not number:
                continue
            if number.startswith("00"):
                number = number[2:]
            for pattern in PREMIUM_RATE_PATTERNS:
                if pattern.match(number):
                    score += 30
                    flags.append(
                        f"Premium-rate number matched on {label}: "
                        f"+{number[:6]}... (pattern: {pattern.pattern})"
                    )
                    break

        return score, flags

    @staticmethod
    def _layer_time_of_day():
        score = 0
        flags = []
        hour = datetime.now().hour
        if AFTER_HOURS_START <= hour or hour < AFTER_HOURS_END:
            score += 5
            flags.append(
                f"After-hours call ({hour:02d}:xx) — "
                f"elevated risk window ({AFTER_HOURS_START}:00-{AFTER_HOURS_END:02d}:00)"
            )
        return score, flags

    def _layer_velocity(self, caller, now):
        score = 0
        flags = []
        dq = self._caller_velocity[caller]
        dq.append(now)
        cutoff = now - VELOCITY_WINDOW_SECONDS
        while dq and dq[0] < cutoff:
            dq.popleft()
        count = len(dq)
        if count >= VELOCITY_CRIT_THRESHOLD:
            score += 35
            flags.append(f"CRITICAL velocity: {count} calls in {VELOCITY_WINDOW_SECONDS}s")
        elif count >= VELOCITY_HIGH_THRESHOLD:
            score += 20
            flags.append(f"HIGH velocity: {count} calls in {VELOCITY_WINDOW_SECONDS}s")
        elif count >= VELOCITY_WARN_THRESHOLD:
            score += 8
            flags.append(f"Elevated call rate: {count} calls in {VELOCITY_WINDOW_SECONDS}s")
        return score, flags

    def _layer_multi_destination(self, caller):
        score = 0
        flags = []
        distinct = len(self._caller_destinations.get(caller, set()))
        if distinct >= MULTIDST_HIGH_THRESHOLD:
            score += 25
            flags.append(f"Extension scanning: {distinct} distinct destinations dialled")
        elif distinct >= MULTIDST_WARN_THRESHOLD:
            score += 10
            flags.append(f"Multiple destinations: {distinct} distinct extensions dialled")
        return score, flags

    def _layer_sequential_scan(self, caller):
        score = 0
        flags = []
        seq = self._caller_seq.get(caller)
        if not seq or len(seq) < SEQ_SCAN_MIN_SAMPLES:
            return 0, []
        extens = [e for _, e in seq]
        diffs  = [extens[i+1] - extens[i] for i in range(len(extens)-1)]
        if not diffs:
            return 0, []
        if len(set(diffs)) == 1 and diffs[0] in (1, -1, 10, -10, 100, -100):
            score += 20
            flags.append(
                f"Sequential dialing scan detected: "
                f"{extens[:3]}... (step={diffs[0]}) over {len(extens)} calls"
            )
        elif len(diffs) >= 3 and diffs.count(diffs[0]) >= len(diffs) * 0.75:
            score += 10
            flags.append(f"Probable sequential scan: {extens[:3]}... (step={diffs[0]})")
        return score, flags

    def _layer_relay_fraud(self, caller, exten, direction):
        score = 0
        flags = []
        if direction != "OUTGOING":
            return 0, []
        if not self._active_inbound:
            return 0, []
        exten_clean = str(exten or "").lstrip("+").strip()
        for pattern in PREMIUM_RATE_PATTERNS:
            if exten_clean and pattern.match(exten_clean):
                score += 40
                flags.append(
                    "RELAY FRAUD PATTERN: Outbound call to premium-rate number "
                    "while inbound call is active — possible call-bridge fraud"
                )
                break
        else:
            score += 5
            flags.append("Concurrent inbound/outbound call — monitoring for relay fraud")
        return score, flags

    # ──────────────────────────────────────────────────────
    # Reputation
    # ──────────────────────────────────────────────────────

    def _get_reputation_bonus(self, caller, now):
        rec = self._reputation.get(caller)
        if not rec:
            return 0
        elapsed    = now - rec["last_seen"]
        half_lives = elapsed / REPUTATION_DECAY_SECONDS
        decayed    = rec["score"] * (0.5 ** half_lives)
        if decayed < 1:
            del self._reputation[caller]
            return 0
        return int(decayed * 0.3)

    def _update_reputation(self, caller, score, now):
        if score <= 0:
            return
        rec = self._reputation.get(caller, {"score": 0, "last_seen": now})
        rec["score"]     = min(rec["score"] + score, REPUTATION_MAX_SCORE)
        rec["last_seen"] = now
        self._reputation[caller] = rec

    # ──────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────

    @staticmethod
    def _resolve_level(score, flags):
        if score >= 50:
            return "CRITICAL", "Critical threat — immediate action recommended"
        elif score >= 35:
            return "HIGH",     "High-risk call pattern — potential fraud or attack"
        elif score >= 20:
            return "MEDIUM",   "Moderate risk indicators detected"
        elif score >= 8:
            return "LOW",      "Minor anomaly noted — monitoring elevated"
        else:
            return "None",     "Call appears normal — no threat indicators"

    @staticmethod
    def _normalise(value):
        return str(value or "").lstrip("+").strip().lower() or "unknown"

    def _prune_seq(self, caller, now):
        dq     = self._caller_seq[caller]
        cutoff = now - SEQ_SCAN_WINDOW_SECONDS
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def clear_inbound(self, uniqueid):
        """Call when an inbound channel hangs up."""
        self._active_inbound.pop(uniqueid, None)
