"""
=========================================
Live Asterisk Firewall

Configuration
=========================================
"""

import os

# Default Linux Asterisk log

ASTERISK_LOG = os.getenv(

    "ASTERISK_LOG",

    "/var/log/asterisk/full"

)

# Detection Thresholds

FAILED_AUTH_THRESHOLD = 10

REGISTER_THRESHOLD = 20

INVITE_THRESHOLD = 20

OPTIONS_THRESHOLD = 20

# Number of outbound calls to the SAME destination number
# (or matching international pattern) before flagging TOLL_FRAUD.
# Kept low (2) because a legitimate user rarely calls the exact
# same international number twice within a monitoring session.
TOLL_FRAUD_THRESHOLD = 2

BAN_TIME = 600

DEBUG = True
