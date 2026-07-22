"""
===========================================================
Live Asterisk Firewall

firewall.py

Purpose
--------
Receives detected attacks from detector.py
and decides what action to take.

Author:
    Jai
===========================================================
"""

from logger import FirewallLogger
from iptables_controller import IPTablesController


class Firewall:

    def __init__(self):

        self.logger = FirewallLogger()

        self.iptables = IPTablesController()

    # -------------------------------------------------
    # Main Decision Engine
    # -------------------------------------------------

    def process_attack(self, attack):

        if attack is None:

            return

        ip = attack["source_ip"]

        attack_type = attack["attack"]

        severity = attack["severity"]

        print("\n===================================")
        print("FIREWALL DECISION ENGINE")
        print("===================================")

        print("IP :", ip)

        print("Attack :", attack_type)

        print("Severity :", severity)

        # ---------------------------------------------
        # Critical
        # ---------------------------------------------

        if severity == "CRITICAL":

            action = "BLOCK"

            self.iptables.block_ip(ip)

        # ---------------------------------------------

        elif severity == "HIGH":

            action = "BLOCK"

            self.iptables.block_ip(ip)

        # ---------------------------------------------

        elif severity == "MEDIUM":

            action = "MONITOR"

        # ---------------------------------------------

        else:

            action = "ALLOW"

        print("Firewall Action :", action)

        self.logger.log(

            ip=ip,

            attack=attack_type,

            severity=severity,

            action=action

        )


# -------------------------------------------------------
# Testing
# -------------------------------------------------------

if __name__ == "__main__":

    fw = Firewall()

    sample = {

        "source_ip": "185.22.11.5",

        "attack": "BRUTE_FORCE",

        "severity": "HIGH"

    }

    fw.process_attack(sample)