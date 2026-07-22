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

        match = re.search(r"\[(.*?)\]", line)

        if match:
            return match.group(1)

        return str(datetime.now())

    # --------------------------------------------------
    # Extract Source IP
    # --------------------------------------------------

    def extract_ip(self, line):

        match = re.search(
            r"(\d{1,3}(?:\.\d{1,3}){3})",
            line
        )

        if match:
            return match.group(1)

        return "UNKNOWN"

    # --------------------------------------------------
    # Detect SIP Method
    # --------------------------------------------------

    def detect_method(self, line):

        methods = [

            "REGISTER",
            "INVITE",
            "OPTIONS",
            "ACK",
            "BYE",
            "CANCEL"

        ]

        upper = line.upper()

        for method in methods:

            if method in upper:
                return method

        return "UNKNOWN"

    # --------------------------------------------------
    # Event Classification
    # --------------------------------------------------

    def classify_event(self, line):

        upper = line.upper()

        if "FAILED AUTHENTICATION" in upper:
            return "FAILED_AUTH"

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

        elif "SUCCESSFULLY REGISTERED" in upper:
            return "REGISTER_SUCCESS"

        return "OTHER"

    # --------------------------------------------------
    # Main Parser
    # --------------------------------------------------

    def parse(self, line):

        event = {

            "timestamp":
                self.extract_timestamp(line),

            "source_ip":
                self.extract_ip(line),

            "method":
                self.detect_method(line),

            "event":
                self.classify_event(line),

            "raw_log":
                line.strip()

        }

        return event


# ------------------------------------------------------
# Testing
# ------------------------------------------------------

if __name__ == "__main__":

    parser = LogParser()

    sample = "[Jul 22 10:10:15] NOTICE Failed Authentication from '185.22.11.5' using REGISTER"

    result = parser.parse(sample)

    print("\n========== Parsed Event ==========\n")

    for key, value in result.items():

        print(f"{key:12}: {value}")