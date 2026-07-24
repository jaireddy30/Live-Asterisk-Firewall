"""
===========================================================
Live Asterisk Firewall

detector.py

Purpose
-------
Detect SIP attacks from parsed events.

Author:
    Jai
===========================================================
"""

from config import *


class Detector:

    def __init__(self):

        self.attack_db = {}

    # ---------------------------------------------------
    # Initialize IP
    # ---------------------------------------------------

    def initialize_ip(self, ip):

        if ip not in self.attack_db:

            self.attack_db[ip] = {

                "failed_auth": 0,
                "register": 0,
                "invite": 0,
                "options": 0,
                "unknown_endpoint": 0,
                "toll_fraud": 0,

                "auth_challenge": 0,
                "auth_success": 0,
                "acl_blocked": 0,
                "request_blocked": 0

            }

    # ---------------------------------------------------
    # Main Detection Function
    # ---------------------------------------------------

    def detect(self, event):

        ip = event["source_ip"]

        self.initialize_ip(ip)

        attack = None
        severity = "LOW"

        # -----------------------------------------------
        # Auth Challenge (informational, not an attack by itself)
        # -----------------------------------------------

        if event["event"] == "AUTH_CHALLENGE":

            self.attack_db[ip]["auth_challenge"] += 1

        # -----------------------------------------------
        # Successful Auth
        #
        # If this IP successfully authenticates, it is
        # unlikely to be the source of a brute-force attempt
        # right now. Reset the failed_auth counter so a
        # legitimate user who mistyped a password a few times
        # isn't blocked right after they log in correctly.
        # -----------------------------------------------

        elif event["event"] == "AUTH_SUCCESS":

            self.attack_db[ip]["auth_success"] += 1
            self.attack_db[ip]["failed_auth"] = 0

        # -----------------------------------------------
        # Failed Authentication
        # -----------------------------------------------

        elif event["event"] == "FAILED_AUTH":

            self.attack_db[ip]["failed_auth"] += 1

            if self.attack_db[ip]["failed_auth"] >= FAILED_AUTH_THRESHOLD:

                attack = "BRUTE_FORCE"
                severity = "HIGH"

        # -----------------------------------------------
        # ACL Blocked (Asterisk already rejected this at ACL level)
        # -----------------------------------------------

        elif event["event"] == "ACL_BLOCKED":

            self.attack_db[ip]["acl_blocked"] += 1

            attack = "ACL_VIOLATION"
            severity = "MEDIUM"

        # -----------------------------------------------
        # Request Not Allowed
        # -----------------------------------------------

        elif event["event"] == "REQUEST_BLOCKED":

            self.attack_db[ip]["request_blocked"] += 1

            attack = "REQUEST_BLOCKED"
            severity = "MEDIUM"

        # -----------------------------------------------
        # Toll Fraud
        # -----------------------------------------------

        elif event["event"] == "TOLL_FRAUD":

            self.attack_db[ip]["toll_fraud"] += 1

            attack = "TOLL_FRAUD"
            severity = "CRITICAL"

        # -----------------------------------------------
        # Unknown Endpoint
        # -----------------------------------------------

        elif event["event"] == "UNKNOWN_ENDPOINT":

            self.attack_db[ip]["unknown_endpoint"] += 1

            attack = "UNKNOWN_ENDPOINT_SCAN"
            severity = "MEDIUM"

        # -----------------------------------------------
        # REGISTER Flood
        # -----------------------------------------------

        elif event["method"] == "REGISTER":

            self.attack_db[ip]["register"] += 1

            if self.attack_db[ip]["register"] >= REGISTER_THRESHOLD:

                attack = "REGISTER_FLOOD"
                severity = "HIGH"

        # -----------------------------------------------
        # INVITE Flood
        # -----------------------------------------------

        elif event["method"] == "INVITE":

            self.attack_db[ip]["invite"] += 1

            if self.attack_db[ip]["invite"] >= INVITE_THRESHOLD:

                attack = "INVITE_FLOOD"
                severity = "HIGH"

        # -----------------------------------------------
        # OPTIONS Flood
        # -----------------------------------------------

        elif event["method"] == "OPTIONS":

            self.attack_db[ip]["options"] += 1

            if self.attack_db[ip]["options"] >= OPTIONS_THRESHOLD:

                attack = "SIP_ENUMERATION"
                severity = "MEDIUM"

        # -----------------------------------------------
        # Attack Found
        # -----------------------------------------------

        if attack:

            result = {

                "source_ip": ip,

                "attack": attack,

                "severity": severity,

                "details": self.attack_db[ip]

            }

            print("\n====================================")

            print("ATTACK DETECTED")

            print("====================================")

            print("IP        :", ip)

            print("Attack    :", attack)

            print("Severity  :", severity)

            print("Counters  :", self.attack_db[ip])

            return result

        return None


# ---------------------------------------------------
# Testing
# ---------------------------------------------------

if __name__ == "__main__":

    detector = Detector()

    sample = {

        "source_ip": "185.22.11.5",

        "event": "FAILED_AUTH",

        "method": "REGISTER"

    }

    for _ in range(12):

        attack = detector.detect(sample)

        if attack:

            print("\nFinal Result")

            print(attack)

    # Verify AUTH_SUCCESS resets the failed_auth counter
    success_sample = {

        "source_ip": "185.22.11.5",

        "event": "AUTH_SUCCESS",

        "method": "REGISTER"

    }

    detector.detect(success_sample)

    print("\nAfter AUTH_SUCCESS, failed_auth counter:")
    print(detector.attack_db["185.22.11.5"]["failed_auth"])
