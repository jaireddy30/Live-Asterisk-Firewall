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
    # --------------------------------------------------

    def extract_ip(self, line):

        patterns = [

            r"(\d{1,3}(?:\.\d{1,3}){3})",

            r"from\s+'?(\d{1,3}(?:\.\d{1,3}){3})",

            r"received\s+from\s+(\d{1,3}(?:\.\d{1,3}){3})",

            r"Contact:.*?@(\d{1,3}(?:\.\d{1,3}){3})",

            r"Via:.*?(\d{1,3}(?:\.\d{1,3}){3})"

        ]

        for pattern in patterns:

            match = re.search(pattern, line, re.IGNORECASE)

            if match:
                return match.group(1)

        return "UNKNOWN"

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

            if method in upper:
                return method

        return "UNKNOWN"

    # --------------------------------------------------
    # Classify Event
    # --------------------------------------------------

    def classify_event(self, line):

        upper = line.upper()

        # ---------- Security Events ----------

        if "FAILED AUTHENTICATION" in upper:
            return "FAILED_AUTH"

        elif "WRONG PASSWORD" in upper:
            return "FAILED_AUTH"

        elif "AUTH FAILED" in upper:
            return "FAILED_AUTH"

        elif "SUCCESSFULLY REGISTERED" in upper:
            return "REGISTER_SUCCESS"

        elif "REGISTER" in upper:
            return "REGISTER"

        elif "INVITE" in upper:
            return "INVITE"

        elif "OPTIONS" in upper:
            return "OPTIONS"

        elif "NO MATCHING ENDPOINT" in upper:
            return "UNKNOWN_ENDPOINT"

        elif "TOLL" in upper:
            return "TOLL_FRAUD"

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

        event = {

            "timestamp": self.extract_timestamp(line),

            "source_ip": self.extract_ip(line),

            "module": self.detect_module(line),

            "method": self.detect_method(line),

            "event": self.classify_event(line),

            "raw_log": line.strip()

        }

        return event


# ------------------------------------------------------
# Testing
# ------------------------------------------------------

if __name__ == "__main__":

    parser = LogParser()

    samples = [

        "[Jul 22 10:10:15] NOTICE Failed Authentication from '185.22.11.5' using REGISTER",

        "[Jul 22 10:10:20] NOTICE Received SIP INVITE from 192.168.1.20",

        "[Jul 22 10:10:25] WARNING[1234] res_pjsip/pjsip_distributor.c: Request 'OPTIONS' from '192.168.1.30' failed",

        "[Jul 22 10:10:30] WARNING[1234] channel.c: Exceptionally long voice queue length"

    ]

    for sample in samples:

        print("\n==============================")
        print("Parsed Event")
        print("==============================")

        result = parser.parse(sample)

        for key, value in result.items():
            print(f"{key:15}: {value}")
