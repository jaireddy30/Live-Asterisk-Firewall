"""
===========================================================
Live Asterisk Firewall

parser.py

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
    #
    # Strategy:
    #   1. Try high-confidence, structured patterns first
    #      (SecurityEvent RemoteAddress, "from", "received from").
    #   2. If nothing structured matches, fall back to scanning
    #      every IP-looking token and prefer a PUBLIC one over a
    #      private/local one (avoids grabbing your own LAN IP out
    #      of a Via: or Contact: header).
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
    #
    # Present on Asterisk SecurityEvent lines, e.g.
    # AccountID="2002". Not present on every line - callers
    # should treat "UNKNOWN" as "not available in this line".
    # --------------------------------------------------

    def extract_account_id(self, line):

        match = re.search(r'AccountID="([^"]+)"', line)

        if match:
            return match.group(1)

        return "UNKNOWN"

    # --------------------------------------------------
    # Extract Toll-Fraud Destination Number
    #
    # Two real patterns seen in production Asterisk logs:
    #
    #   1. Dial(SIP/trunk/00441234567890) or ...+971...
    #   2. Local/919566704154__<call-id>...
    #      (seen in core_local.c "without a @context" warnings)
    #
    # Returns the destination number as a string, or None.
    # --------------------------------------------------

    def extract_toll_destination(self, line):

        # Pattern 1: Dial() with international prefix
        dial_match = re.search(
            r"DIAL\([^)]*(?:\+|00)(\d{9,15})",
            line.upper()
        )

        if dial_match:
            return dial_match.group(1)

        # Pattern 2: Local/<number>__<call-id>
        local_match = re.search(
            r"Local/(\d{9,15})__",
            line
        )

        if local_match:
            return local_match.group(1)

        # Pattern 3: bare "TOLL" keyword mention with a nearby number
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

        elif "PBX.C" in upper:
            return "pbx.c"

        elif "APP_DIAL.C" in upper:
            return "app_dial.c"

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

        # ---------- Generic Events ----------

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

        elif "REGISTER" in upper:
            return "REGISTER"

        elif "INVITE" in upper:
            return "INVITE"

        elif "OPTIONS" in upper:
            return "OPTIONS"

        elif "NO MATCHING ENDPOINT" in upper:
            return "UNKNOWN_ENDPOINT"

        # ---------- System Events ----------

        elif "CHANNEL.C" in upper:
            return "SYSTEM_LOG"

        elif "FUNC_ODBC.C" in upper:
            return "DATABASE_LOG"

        elif "RES_PJSIP" in upper:
            return "PJSIP_LOG"

        elif "CHAN_SIP" in upper:
            return "CHAN_SIP_LOG"

        elif "RTP" in upper:
            return "RTP_LOG"

        return "OTHER"

    # --------------------------------------------------
    # Main Parser
    # --------------------------------------------------

    def parse(self, line):

        return {

            "timestamp": self.extract_timestamp(line),

            "source_ip": self.extract_ip(line),

            "account_id": self.extract_account_id(line),

            "destination": self.extract_toll_destination(line),

            "module": self.detect_module(line),

            "method": self.detect_method(line),

            "event": self.classify_event(line),

            "raw_log": line.strip()

        }


# ------------------------------------------------------
# Testing
# ------------------------------------------------------

if __name__ == "__main__":

    parser = LogParser()

    samples = [

        '[Jul 22 10:10:15] NOTICE Failed Authentication from "185.22.11.5" using REGISTER',

        '[Jul 22 10:10:20] NOTICE Received SIP INVITE from 192.168.1.20',

        '[Jul 22 10:10:30] SECURITY SecurityEvent="ChallengeSent" RemoteAddress="IPV4/UDP/192.168.1.192/57948"',

        '[Jul 24 09:53:41] SECURITY[1386] res_security_log.c: SecurityEvent="SuccessfulAuth",AccountID="2002",LocalAddress="IPV4/UDP/192.168.1.76/5060",RemoteAddress="IPV4/UDP/192.168.1.192/60941"',

        '[2026-07-24 15:40:38.311] WARNING[1643562] core_local.c: Someone used Local/919566704154__7e36d5ab-7958-43ac-b89e-b3889244b808__8d18d75e-0dac-4e97 somewhere without a @context. This is bad.',

        '[Jul 22 10:10:34] NOTICE Dial(SIP/trunk-out/00441234567890) from ext 1001',

    ]

    for sample in samples:

        print("\n==============================")
        print("Parsed Event")
        print("==============================")

        result = parser.parse(sample)

        for key, value in result.items():
            print(f"{key:15}: {value}")
