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
    #   2. If one of those matches, use it directly - these are
    #      almost always the real attacker/peer IP.
    #   3. If nothing structured matches, fall back to scanning
    #      every IP-looking token in the line and prefer the
    #      first PUBLIC IP over a private/local one. This avoids
    #      accidentally picking your own LAN extension's IP out
    #      of a Via: or Contact: header instead of the real
    #      remote address.
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

        # Fallback: scan every IP-looking token, prefer a public one
        all_ips = re.findall(r"\d+\.\d+\.\d+\.\d+", line)

        if not all_ips:
            return "UNKNOWN"

        for ip in all_ips:
            if not is_private_ip(ip):
                return ip

        # Nothing public found - return the first match anyway
        return all_ips[0]

    # --------------------------------------------------
    # Detect Module
    # --------------------------------------------------

    def detect_module(self, line):

        upper = line.upper()

        if "FUNC_ODBC.C" in upper:
            return "func_odbc.c"

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
    # Detect possible toll-fraud indicators in a log line
    #
    # NOTE: True toll-fraud detection needs CDR data (call
    # duration, destination, cost) - a single log line rarely
    # contains enough info. This checks for common signs that
    # DO sometimes appear in Asterisk dial logs: outbound calls
    # to international prefixes or explicit "toll" mentions.
    # Treat this as a weak signal, not a reliable detector.
    # --------------------------------------------------

    def looks_like_toll_fraud(self, line):

        upper = line.upper()

        if "TOLL" in upper:
            return True

        # Common international dial prefixes seen in Dial() lines,
        # e.g. Dial(SIP/trunk/00441234567890) or .../+971...
        international_patterns = [
            r"DIAL\([^)]*(\+|00)(44|971|1|234|91)\d{6,}",
        ]

        for pattern in international_patterns:
            if re.search(pattern, upper):
                return True

        return False

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

        elif self.looks_like_toll_fraud(line):
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

        '[Jul 22 10:10:25] WARNING res_pjsip: Request "OPTIONS" from 192.168.1.30 failed',

        '[Jul 22 10:10:30] SECURITY SecurityEvent="ChallengeSent" RemoteAddress="IPV4/UDP/192.168.1.192/57948"',

        '[Jul 22 10:10:31] SECURITY SecurityEvent="SuccessfulAuth" RemoteAddress="IPV4/UDP/192.168.1.192/57948"',

        '[Jul 22 10:10:32] SECURITY SecurityEvent="InvalidPassword" RemoteAddress="IPV4/UDP/185.22.11.5/5060"',

        '[Jul 22 10:10:33] SECURITY SecurityEvent="InvalidAccountID" RemoteAddress="IPV4/UDP/185.22.11.5/5060"',

        '[Jul 22 10:10:34] NOTICE Dial(SIP/trunk-out/00441234567890) from ext 1001',

        '[Jul 22 10:10:35] NOTICE INVITE via Via: SIP/2.0/UDP 192.168.1.5;received=203.0.113.9'

    ]

    for sample in samples:

        print("\n==============================")
        print("Parsed Event")
        print("==============================")

        result = parser.parse(sample)

        for key, value in result.items():
            print(f"{key:15}: {value}")
