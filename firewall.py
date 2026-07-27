"""
===========================================================
Live Asterisk Firewall

firewall.py

Purpose:
    Receives detected attacks from detector.py
    and decides what action to take.

Author:
    Jai
===========================================================
"""

from colorama import Fore, init

from logger              import FirewallLogger
from iptables_controller import IPTablesController

init(autoreset=True)


class Firewall:

    def __init__(self):
        self.logger   = FirewallLogger()
        self.iptables = IPTablesController()

    # -------------------------------------------------
    # Main Decision Engine
    # -------------------------------------------------

    def process_attack(self, attack):

        if attack is None:
            return

        # ── key is "ip" from detector.py ──
        ip          = attack["ip"]
        attack_type = attack["attack"]
        severity    = attack["severity"]

        print(Fore.RED + "\n====================================")
        print(Fore.RED + "ATTACK DETECTED")
        print(Fore.RED + "====================================")
        print(Fore.RED + f"IP        : {ip}")
        print(Fore.RED + f"Attack    : {attack_type}")
        print(Fore.RED + f"Severity  : {severity}")

        print(Fore.YELLOW + "\n===================================")
        print(Fore.YELLOW + "FIREWALL DECISION ENGINE")
        print(Fore.YELLOW + "===================================")
        print(Fore.YELLOW + f"IP       : {ip}")
        print(Fore.YELLOW + f"Attack   : {attack_type}")
        print(Fore.YELLOW + f"Severity : {severity}")

        # ---------------------------------------------
        # Decision based on severity
        # ---------------------------------------------

        if severity == "CRITICAL":
            action = "BLOCK"
            print(Fore.RED + f"Blocking : {ip}")
            self.iptables.block_ip(ip)

        elif severity == "HIGH":
            action = "BLOCK"
            print(Fore.RED + f"Blocking : {ip}")
            self.iptables.block_ip(ip)

        elif severity == "MEDIUM":
            action = "MONITOR"
            print(Fore.YELLOW + f"Action   : Monitoring {ip} (no block yet)")

        else:
            action = "ALLOW"
            print(Fore.GREEN + f"Action   : Allowed — low severity")

        print(Fore.YELLOW + f"Firewall Action : {action}")
        print(Fore.YELLOW + "===================================")

        self.logger.log(
            ip       = ip,
            attack   = attack_type,
            severity = severity,
            action   = action
        )


# -------------------------------------------------------
# Testing
# -------------------------------------------------------

if __name__ == "__main__":

    fw = Firewall()

    sample = {
        "ip":       "185.22.11.5",   # ← fixed key
        "attack":   "BRUTE_FORCE",
        "severity": "HIGH"
    }

    fw.process_attack(sample)
