"""
====================================================
LIVE ASTERISK FIREWALL
config.py
====================================================
"""

import os

# --------------------------------------------------
# Asterisk Log File Path
# --------------------------------------------------
ASTERISK_LOG = os.environ.get(
    "ASTERISK_LOG",
    "/var/log/asterisk/full"
)

# --------------------------------------------------
# Mode Selection
# Set only ONE to True at a time.
#
#   USE_AMI     = True  → AMI direct connection (recommended)
#   USE_SNIFFER = True  → Packet sniffer port 5060
#   Both False          → Log file watcher (default)
# --------------------------------------------------
USE_AMI     = False
USE_SNIFFER = False

# --------------------------------------------------
# AMI Settings
# Enable in /etc/asterisk/manager.conf first.
#
# [general]
# enabled  = yes
# port     = 5038
# bindaddr = 127.0.0.1
#
# [firewall]
# secret = yourpassword
# read   = security,call,log
# write  = system
# --------------------------------------------------
AMI_HOST     = "127.0.0.1"
AMI_PORT     = 5038
AMI_USERNAME = "firewall"
AMI_SECRET   = "yourpassword"

# --------------------------------------------------
# Packet Sniffer Settings
# --------------------------------------------------
SNIFF_INTERFACE = "eth0"
SNIFF_PORT      = 5060

# --------------------------------------------------
# Attack Detection Thresholds
# Change these values to adjust sensitivity.
#
#  Lower  = more sensitive (blocks sooner)
#  Higher = less sensitive (allows more attempts)
# --------------------------------------------------
INVITE_THRESHOLD       = 20   # INVITE flood — block after N INVITEs
AUTH_FAIL_THRESHOLD    = 10   # Brute force — block after N failed auths
REGISTER_THRESHOLD     = 15   # REGISTER flood — block after N REGISTERs
OPTIONS_THRESHOLD      = 30   # OPTIONS flood — block after N OPTIONS
TOLL_FRAUD_THRESHOLD   = 5    # Toll fraud — alert after N suspicious calls
ACL_BLOCK_THRESHOLD    = 3    # ACL blocked — block after N ACL violations
