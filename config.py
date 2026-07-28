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
# --------------------------------------------------
USE_AMI     = False
USE_SNIFFER = False

# --------------------------------------------------
# AMI Settings
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
# --------------------------------------------------
INVITE_THRESHOLD     = 20
AUTH_FAIL_THRESHOLD  = 10
REGISTER_THRESHOLD   = 15
OPTIONS_THRESHOLD    = 30
TOLL_FRAUD_THRESHOLD = 5
ACL_BLOCK_THRESHOLD  = 3

# --------------------------------------------------
# Log Filtering
#
# VERBOSE_LOGGING  = True  → show every event
# VERBOSE_LOGGING  = False → show only important events
#
# SKIP_PRIVATE_IPS = True  → hide 127.0.0.1 / local traffic
# SKIP_EVENT_TYPES = set of event types to skip silently
# --------------------------------------------------
VERBOSE_LOGGING  = False

SKIP_PRIVATE_IPS = True

SKIP_EVENT_TYPES = {
    "OPTIONS",       # keepalive pings — too noisy
    "PJSIP_LOG",     # internal Asterisk logs
    "DATABASE_LOG",  # SQL / ODBC logs
    "SYSTEM_LOG",    # Asterisk system messages
    "CHAN_SIP_LOG",  # chan_sip internal
    "RTP_LOG",       # RTP media logs
    "OTHER",         # unknown/unclassified
}

# Private IP prefixes to skip
PRIVATE_IP_PREFIXES = (
    "127.", "10.", "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "0.0.0.0",
)
