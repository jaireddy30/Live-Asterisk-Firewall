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

BAN_TIME = 600

DEBUG = True