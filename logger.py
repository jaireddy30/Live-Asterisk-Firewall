"""
===========================================================
Live Asterisk Firewall

log_parser.py

Purpose:
    Parse live Asterisk log lines into structured events.

Author:
    Jai
===========================================================
"""

import re
from datetime import datetime


PRIVATE_IP_PATTERNS = [
    r"^10\.",
    r"^172\.(1[6-9]|2\d|3[0-1])\.",
    r"^192\.168\.",
    r"^127\.",
]

# Modules that only ever produce normal, expected call-flow noise.
# If a line isn't a security/attack event and belongs to one of
# these modules, it should be classified as an informational
# system log, not "OTHER" / unknown.
INTERNAL_MODULES = {
    "channel.c",
    "pbx.c",
    "app_dial.c",
    "bridge_channel.c",
    "core_local.c",
}


def is_private_ip(ip):
    for pattern in PRIVATE_IP_PATTERNS:
        if re.match(pattern, ip):
            return True
    return False


class LogParser:

    def __init__(self):
        pass

    # --------------------------------------------------
    # Extract Timestamp
    # --------------------------------------------------

    def extract_timestamp(self, line):

        match = re.search(r"\[([^\]]+)\]", line)

        if not match:
            return datetime.now().isoformat()

        timestamp = match.group(1).strip()

        formats = [
            "%Y-%m-%d %H:%M:%S.%f",
            "%b %d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%b %d %Y %H:%M:%S",
            "%d/%b/%Y:%H:%M:%S"
        ]

        for fmt in formats:
            try:
                parsed = datetime.strptime(timestamp, fmt)
                if fmt == "%b %d %H:%M:%S":
                    parsed = parsed.replace(year=datetime.now().year)
                return parsed.isoformat()
            except ValueError:
                continue

        return timestamp

    # --------------------------------------------------
    # Extract Source IP
    # --------------------------------------------------

    def extract_ip(self, line):

        high_confidence_patterns = [
            r'RemoteAddress="IPV4/UDP/(\d+\.\d+\.\d+\.\d+)',
            r'LocalAddress="IPV4/UDP/(\d+\.\d+\.\d+\.\d+)',
            r"from\s+'?(\d+\.\d+\.\d+\.\d+)",
            r"received\s+from\s+(\d+\.\d+\.\d+\.\d+)",
        ]

        for pattern in high_confidence_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                return match.group(1)

        all_ips = re.findall(r"\d+\.\d+\.\d+\.\d+", line)

        if not all_ips:
            return "UNKNOWN"

        for ip in all_ips:
            if not is_private_ip(ip):
                return ip

        return all_ips[0]

    # --------------------------------------------------
    # Extract Account / Extension ID
    # --------------------------------------------------

    def extract_account_id(self, line):

        match = re.search(r'AccountID="([^"]+)"', line)
        if match:
            return match.group(1)

        # Also try to pick up an extension number from call-flow
        # lines like "PJSIP/2001-00000011" or "[2001@internal:1]"
        ext_match = re.search(r"PJSIP/(\d{3,6})-", line)
        if ext_match:
            return ext_match.group(1)

        ext_match = re.search(r"\[(\d{3,6})@internal", line)
        if ext_match:
            return ext_match.group(1)

        return "UNKNOWN"

    # --------------------------------------------------
    # Extract Toll-Fraud Destination Number
    # --------------------------------------------------

    def extract_toll_destination(self, line):

        dial_match = re.search(
            r"DIAL\([^)]*(?:\+|00)(\d{9,15})",
            line.upper()
        )
        if dial_match:
            return dial_match.group(1)

        local_match = re.search(
            r"Local/(\d{9,15})__",
            line
        )
        if local_match:
            return local_match.group(1)

        if "TOLL" in line.upper():
            bare_number = re.search(r"(\d{9,15})", line)
            if bare_number:
                return bare_number.group(1)

        return None

    # --------------------------------------------------
    # Detect Module
    # --------------------------------------------------

    def detect_module(self, line):

        upper = line.upper()

        if "FUNC_ODBC.C" in upper:
            return "func_odbc.c"
        elif "CORE_LOCAL.C" in upper:
            return "core_local.c"
        elif "BRIDGE_CHANNEL.C" in upper:
            return "bridge_channel.c"
        elif "APP_DIAL.C" in upper:
            return "app_dial.c"
        elif "PBX.C" in upper:
            return "pbx.c"
        elif "CHANNEL.C" in upper:
            return "channel.c"
        elif "RES_PJSIP" in upper:
            return "res_pjsip"
        elif "RES_SECURITY_LOG.C" in upper:
            return "res_security_log.c"
        elif "CHAN_SIP" in upper:
            return "chan_sip"
        elif "RTP" in upper:
            return "rtp"

        return "UNKNOWN"

    # --------------------------------------------------
    # Detect SIP Method
    # --------------------------------------------------

    def detect_method(self, line):

        upper = line.upper()

        methods = [
            "REGISTER",
            "INVITE",
            "OPTIONS",
            "ACK",
            "BYE",
            "CANCEL",
            "MESSAGE",
            "SUBSCRIBE",
            "NOTIFY",
            "REFER",
            "UPDATE",
            "INFO"
        ]

        for method in methods:
            if re.search(r"\b" + method + r"\b", upper):
                return method

        return "UNKNOWN"

    # --------------------------------------------------
    # Classify Event
    #
    # Order matters: security/attack signals are checked first.
    # Only if none of those match do we fall back to asking
    # "which internal module produced this line" - that catches
    # normal call-flow noise (pbx.c, app_dial.c, bridge_channel.c,
    # channel.c, core_local.c) instead of dumping it into OTHER.
    # --------------------------------------------------

    def classify_event(self, line):

        upper = line.upper()

        # ---------- Asterisk Security Events ----------

        if 'SECURITYEVENT="CHALLENGESENT"' in upper:
            return "AUTH_CHALLENGE"

        elif 'SECURITYEVENT="SUCCESSFULAUTH"' in upper:
            return "AUTH_SUCCESS"

        elif 'SECURITYEVENT="INVALIDPASSWORD"' in upper:
            return "FAILED_AUTH"

        elif 'SECURITYEVENT="INVALIDACCOUNTID"' in upper:
            return "UNKNOWN_ENDPOINT"

        elif 'SECURITYEVENT="FAILEDACL"' in upper:
            return "ACL_BLOCKED"

        elif 'SECURITYEVENT="REQUESTNOTALLOWED"' in upper:
            return "REQUEST_BLOCKED"

        # ---------- Generic Security Events ----------

        elif "FAILED AUTHENTICATION" in upper:
            return "FAILED_AUTH"

        elif "WRONG PASSWORD" in upper:
            return "FAILED_AUTH"

        elif "AUTH FAILED" in upper:
            return "FAILED_AUTH"

        elif "SUCCESSFULLY REGISTERED" in upper:
            return "REGISTER_SUCCESS"

        elif self.extract_toll_destination(line) is not None:
            return "TOLL_FRAUD"

        elif "NO MATCHING ENDPOINT" in upper:
            return "UNKNOWN_ENDPOINT"

        # ---------- SIP Methods (only if not already claimed above) ----------

        elif "REGISTER" in upper:
            return "REGISTER"

        elif "INVITE" in upper:
            return "INVITE"

        elif "OPTIONS" in upper:
            return "OPTIONS"

        # ---------- Fall back to module-based classification ----------

        module = self.detect_module(line)

        if module in INTERNAL_MODULES:
            return "SYSTEM_LOG"
        elif module == "func_odbc.c":
            return "DATABASE_LOG"
        elif module == "res_pjsip":
            return "PJSIP_LOG"
        elif module == "chan_sip":
            return "CHAN_SIP_LOG"
        elif module == "rtp":
            return "RTP_LOG"

        return "OTHER"

    # --------------------------------------------------
    # Main Parser
    # --------------------------------------------------

    def parse(self, line):

        return {
            "timestamp":   self.extract_timestamp(line),
            "source_ip":   self.extract_ip(line),
            "account_id":  self.extract_account_id(line),
            "destination": self.extract_toll_destination(line),
            "module":      self.detect_module(line),
            "method":      self.detect_method(line),
            "event":       self.classify_event(line),
            "raw_log":     line.strip()
        }


# ------------------------------------------------------
# Testing
# ------------------------------------------------------

if __name__ == "__main__":

    parser = LogParser()

    samples = [
        '[Jul 22 10:10:15] NOTICE Failed Authentication from "185.22.11.5" using REGISTER',
        '[Jul 25 06:59:04] VERBOSE[22417][C-00000009] pbx.c: Executing [2001@internal:1] Dial("PJSIP/2002-00000010", "PJSIP/2001") in new stack',
        '[Jul 25 06:59:09] VERBOSE[22417][C-00000009] app_dial.c: Called PJSIP/2001',
        '[Jul 25 06:59:13] VERBOSE[22423][C-00000009] bridge_channel.c: Channel PJSIP/2001-00000011 joined \'simple_bridge\'',
        '[Jul 25 06:59:30] VERBOSE[22423][C-00000009] app_dial.c: PJSIP/2001-00000011 left \'native_rtp\'',
        '[2026-07-24 15:40:38.311] WARNING[1643562] core_local.c: Someone used Local/919566704154__7e36d5ab somewhere without a @context. This is bad.',
    ]

    for sample in samples:
        print("\n==============================")
        print("Parsed Event")
        print("==============================")
        result = parser.parse(sample)
        for key, value in result.items():
            print(f"{key:15}: {value}")
