"""
===========================================================
Live Asterisk Firewall

iptables_controller.py

Purpose
--------
Blocks attacker IPs using Linux iptables.

Windows:
    Simulates blocking.

Ubuntu:
    Executes real iptables commands.

Author:
    Jai
===========================================================
"""

import platform
import subprocess
import os
import pandas as pd


BLOCK_FILE = "data/blocked_ips.csv"

os.makedirs("data", exist_ok=True)


class IPTablesController:

    def __init__(self):

        if not os.path.exists(BLOCK_FILE):

            df = pd.DataFrame(columns=[

                "ip",
                "status"

            ])

            df.to_csv(

                BLOCK_FILE,

                index=False

            )

    # --------------------------------------------
    # Save Blocked IP
    # --------------------------------------------

    def save_blocked_ip(self, ip):

        df = pd.read_csv(BLOCK_FILE)

        if ip not in df["ip"].values:

            df.loc[len(df)] = [

                ip,

                "BLOCKED"

            ]

            df.to_csv(

                BLOCK_FILE,

                index=False

            )

    # --------------------------------------------
    # Block IP
    # --------------------------------------------

    def block_ip(self, ip):

        system = platform.system()

        print()

        print("Blocking :", ip)

        # ----------------------------------------
        # Linux
        # ----------------------------------------

        if system == "Linux":

            command = [

                "sudo",

                "iptables",

                "-A",

                "INPUT",

                "-s",

                ip,

                "-j",

                "DROP"

            ]

            try:

                subprocess.run(

                    command,

                    check=True

                )

                print("iptables rule added.")

            except Exception as e:

                print("iptables failed")

                print(e)

        # ----------------------------------------
        # Windows
        # ----------------------------------------

        else:

            print(

                "Windows detected."

            )

            print(

                "Simulating firewall block."

            )

        self.save_blocked_ip(ip)

    # --------------------------------------------
    # Remove Block
    # --------------------------------------------

    def unblock_ip(self, ip):

        system = platform.system()

        print()

        print("Removing :", ip)

        if system == "Linux":

            command = [

                "sudo",

                "iptables",

                "-D",

                "INPUT",

                "-s",

                ip,

                "-j",

                "DROP"

            ]

            try:

                subprocess.run(

                    command,

                    check=True

                )

                print(

                    "Rule removed."

                )

            except Exception as e:

                print(e)

        else:

            print(

                "Windows simulation."

            )

    # --------------------------------------------
    # Show Current Rules
    # --------------------------------------------

    def show_rules(self):

        system = platform.system()

        if system == "Linux":

            subprocess.run(

                [

                    "sudo",

                    "iptables",

                    "-L"

                ]

            )

        else:

            df = pd.read_csv(BLOCK_FILE)

            print(df)


# ------------------------------------------------
# Testing
# ------------------------------------------------

if __name__ == "__main__":

    fw = IPTablesController()

    fw.block_ip(

        "185.22.11.5"

    )

    fw.show_rules()