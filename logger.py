"""
===========================================================
Live Asterisk Firewall

logger.py

Purpose
--------
Logs every firewall action.

Creates:
    data/alerts.csv

Author:
    Jai
===========================================================
"""

import os
import pandas as pd
from datetime import datetime


ALERT_FILE = "data/alerts.csv"

os.makedirs("data", exist_ok=True)


class FirewallLogger:

    def __init__(self):

        if not os.path.exists(ALERT_FILE):

            df = pd.DataFrame(columns=[
                "timestamp",
                "source_ip",
                "attack",
                "severity",
                "action"
            ])

            df.to_csv(ALERT_FILE, index=False)

    # ---------------------------------------------------
    # Write Alert
    # ---------------------------------------------------

    def log(self, ip, attack, severity, action):

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        df = pd.read_csv(ALERT_FILE)

        df.loc[len(df)] = [timestamp, ip, attack, severity, action]

        df.to_csv(ALERT_FILE, index=False)

        print()
        print("================================")
        print("FIREWALL LOG")
        print("================================")
        print("Time      :", timestamp)
        print("IP        :", ip)
        print("Attack    :", attack)
        print("Severity  :", severity)
        print("Action    :", action)
        print()
        print("Saved ->", ALERT_FILE)

    # ---------------------------------------------------
    # Show Alerts
    # ---------------------------------------------------

    def show_logs(self):
        df = pd.read_csv(ALERT_FILE)
        print(df)

    # ---------------------------------------------------
    # Clear Logs
    # ---------------------------------------------------

    def clear_logs(self):

        df = pd.DataFrame(columns=[
            "timestamp",
            "source_ip",
            "attack",
            "severity",
            "action"
        ])

        df.to_csv(ALERT_FILE, index=False)
        print("Logs Cleared")


# -------------------------------------------------------
# Testing
# -------------------------------------------------------

if __name__ == "__main__":

    logger = FirewallLogger()

    logger.log(
        ip="185.22.11.5",
        attack="BRUTE_FORCE",
        severity="HIGH",
        action="BLOCK"
    )

    logger.show_logs()
