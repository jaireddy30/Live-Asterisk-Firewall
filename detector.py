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

# Fallback threshold in case it's not defined in config.py yet.
try:
    TOLL_FRAUD_THRESHOLD
except NameError:
    TOLL_FRAUD_THRESHOLD = 2


class Detector:

    def __init__(self):

        self.attack_db = {}

        # Separate tracking for toll fraud, keyed by DESTINATION
        # NUMBER instead of source IP. Real toll-fraud log lines
        # (e.g. "Local/919566704154__...") carry no source IP at
        # all - the fraud is in what number your own PBX is
        # calling out to, not who connected in.
        self.toll_db = {}

    # ---------------------------------------------------
    # Initialize IP
    # ---------------------------------------------------

    def initialize_ip(self, ip):

        if ip not in self.attack_db:
            self.attack_db[ip] = {
                "failed_auth":    0,
                "register":       0,
                "invite":         0,
                "options":        0,
                "unknown_endpoint": 0,
                "auth_challenge": 0,
                "auth_success":   0,
                "acl_blocked":    0,
                "request_blocked": 0
            }

    # ---------------------------------------------------
    # Initialize Destination (for toll fraud tracking)
    # ---------------------------------------------------

    def initialize_destination(self, destination):

        if destination not in self.toll_db:
            self.toll_db[destination] = {
                "count":             0,
                "account_ids_seen":  set()
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
        # Reset failed_auth so a legitimate user who mistyped
        # a password a couple times isn't blocked right after
        # they log in correctly.
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
        # ACL Blocked
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
        #
        # Tracked by DESTINATION NUMBER, not source IP, since
        # the source IP is usually "UNKNOWN" for this event type
        # (it's your own PBX placing an outbound call).
        # -----------------------------------------------

        elif event["event"] == "TOLL_FRAUD":

            destination = event.get("destination") or "UNKNOWN_DESTINATION"

            self.initialize_destination(destination)

            self.toll_db[destination]["count"] += 1

            account_id = event.get("account_id", "UNKNOWN")
            if account_id != "UNKNOWN":
                self.toll_db[destination]["account_ids_seen"].add(account_id)

            if self.toll_db[destination]["count"] >= TOLL_FRAUD_THRESHOLD:
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

            if attack == "TOLL_FRAUD":

                destination = event.get("destination") or "UNKNOWN_DESTINATION"

                result = {
                    "source_ip":   ip,
                    "attack":      attack,
                    "severity":    severity,
                    "destination": destination,
                    "details":     self.toll_db[destination]
                }

                print("\n====================================")
                print("ATTACK DETECTED")
                print("====================================")
                print("Attack       :", attack)
                print("Severity     :", severity)
                print("Destination  :", destination)
                print("Call Count   :", self.toll_db[destination]["count"])
                print("Account IDs  :", self.toll_db[destination]["account_ids_seen"] or "Not available in log - check CDR")

                return result

            result = {
                "source_ip": ip,
                "attack":    attack,
                "severity":  severity,
                "details":   self.attack_db[ip]
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
        "event":     "FAILED_AUTH",
        "method":    "REGISTER"
    }

    for _ in range(12):
        attack = detector.detect(sample)
        if attack:
            print("\nFinal Result")
            print(attack)

    success_sample = {
        "source_ip": "185.22.11.5",
        "event":     "AUTH_SUCCESS",
        "method":    "REGISTER"
    }

    detector.detect(success_sample)

    print("\nAfter AUTH_SUCCESS, failed_auth counter:")
    print(detector.attack_db["185.22.11.5"]["failed_auth"])

    toll_sample = {
        "source_ip":   "UNKNOWN",
        "event":       "TOLL_FRAUD",
        "method":      "UNKNOWN",
        "destination": "919566704154",
        "account_id":  "UNKNOWN"
    }

    print("\n--- Simulating repeated toll fraud calls ---")

    for _ in range(2):
        result = detector.detect(toll_sample)
        if result:
            print("\nFinal Toll Fraud Result:")
            print(result)
