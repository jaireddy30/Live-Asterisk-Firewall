"""
====================================================
LIVE ASTERISK FIREWALL

MODULE 1 - MAIN ENTRY POINT
====================================================
"""

import os
import time

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from colorama import Fore
from colorama import init

from config import ASTERISK_LOG

# FIX: renamed from 'parser' to 'log_parser' to avoid collision
# with Python's stdlib 'parser' module (removed in Python 3.12).
from log_parser import LogParser
from detector import Detector
from firewall import Firewall

init(autoreset=True)


STATIC_NON_ATTACK_REASONS = {
    "AUTH_CHALLENGE":   "Authentication challenge sent (normal SIP handshake)",
    "AUTH_SUCCESS":     "Successful authentication",
    "REGISTER_SUCCESS": "Successful registration",
}

DYNAMIC_MODULE_EVENTS = {
    "SYSTEM_LOG",
    "DATABASE_LOG",
    "PJSIP_LOG",
    "CHAN_SIP_LOG",
    "RTP_LOG",
}

# Marker that starts a multi-line raw SIP message dump.
# Everything until the NEXT bracketed Asterisk log line belongs
# to THIS message and must be parsed together, not line-by-line.
SIP_BLOCK_MARKER = "<---"


def is_new_log_entry(line):
    """
    True if this line looks like the start of a brand new
    Asterisk log statement (starts with a bracketed timestamp),
    e.g. "[Jul 25 07:46:53] VERBOSE[...] ...".
    SIP header/body lines (Via:, Call-ID:, blank lines, SDP
    fields like "v=0") never start this way.
    """
    stripped = line.lstrip()
    return stripped.startswith("[")


class LogMonitor(FileSystemEventHandler):

    def __init__(self):

        self.file = open(ASTERISK_LOG, "r")
        self.file.seek(0, os.SEEK_END)

        self.parser = LogParser()
        self.detector = Detector()
        self.firewall = Firewall()

        # Buffering state for multi-line SIP message blocks
        self._in_sip_block = False
        self._sip_block_lines = []

    # -----------------------------------------------------
    # Process one fully-assembled "line" (either a normal
    # single log line, or a joined multi-line SIP block)
    # -----------------------------------------------------

    def process_entry(self, text):

        print(Fore.GREEN + "\n============================================================")
        print(Fore.GREEN + "LIVE LOG")
        print(Fore.GREEN + "============================================================")
        print(text.strip())

        parsed_event = self.parser.parse(text)

        print(Fore.CYAN + "\n============================================================")
        print(Fore.CYAN + "PARSER ANALYSIS")
        print(Fore.CYAN + "============================================================")

        print(Fore.GREEN + f"🕒 Timestamp        : {parsed_event['timestamp']}")

        if parsed_event["source_ip"] != "UNKNOWN":
            print(Fore.GREEN + f"✅ Source IP        : {parsed_event['source_ip']}")
        else:
            print(Fore.RED + "❌ Source IP        : Not Found")

        if parsed_event["method"] != "UNKNOWN":
            print(Fore.GREEN + f"✅ SIP Method       : {parsed_event['method']}")
        else:
            print(Fore.RED + "❌ SIP Method       : Not Found")

        if parsed_event["event"] != "OTHER":
            print(Fore.GREEN + f"✅ Event Type       : {parsed_event['event']}")
        else:
            print(Fore.RED + "❌ Event Type       : Unknown")

        if parsed_event["event"] == "FAILED_AUTH":
            print(Fore.GREEN + "✅ Authentication   : Failed")
        elif parsed_event["event"] == "AUTH_SUCCESS":
            print(Fore.GREEN + "✅ Authentication   : Success")
        else:
            print(Fore.RED + "❌ Authentication   : Not Found")

        if parsed_event["method"] == "REGISTER":
            print(Fore.GREEN + "✅ REGISTER         : Detected")
        else:
            print(Fore.RED + "❌ REGISTER         : Not Found")

        if parsed_event["method"] == "INVITE":
            print(Fore.GREEN + "✅ INVITE           : Detected")
        else:
            print(Fore.RED + "❌ INVITE           : Not Found")

        if parsed_event["method"] == "OPTIONS":
            print(Fore.GREEN + "✅ OPTIONS          : Detected")
        else:
            print(Fore.RED + "❌ OPTIONS          : Not Found")

        if parsed_event["module"] != "UNKNOWN":
            print(Fore.YELLOW + f"ℹ️ Module           : {parsed_event['module']}")

        print(Fore.CYAN + "============================================================")

        attack = self.detector.detect(parsed_event)

        if attack:

            self.firewall.process_attack(attack)

        else:

            print(Fore.YELLOW + "\n============================================================")
            print(Fore.YELLOW + "FIREWALL ANALYSIS")
            print(Fore.YELLOW + "============================================================")

            event_type = parsed_event["event"]
            module = parsed_event["module"]

            print(Fore.YELLOW + "Status          : Ignored")

            if event_type in STATIC_NON_ATTACK_REASONS:
                print(Fore.YELLOW + f"Reason          : {STATIC_NON_ATTACK_REASONS[event_type]}")
                print(Fore.YELLOW + f"Event Type      : {event_type}")

            elif event_type in DYNAMIC_MODULE_EVENTS:
                print(Fore.YELLOW + "Reason          : Internal Asterisk log, not a security event")
                print(Fore.YELLOW + f"Module          : {module}")
                print(Fore.YELLOW + f"Event Type      : {event_type}")

            elif event_type == "OTHER":
                print(Fore.YELLOW + "Reason          : Unsupported or Unknown Log")
                print(Fore.YELLOW + f"Module          : {module}")

            else:
                print(Fore.YELLOW + "Reason          : Recognized event, below attack threshold")
                print(Fore.YELLOW + f"Event Type      : {event_type}")

            print(Fore.YELLOW + "Threat Level    : None")
            print(Fore.YELLOW + "Firewall Action : No Action")
            print(Fore.YELLOW + "Monitoring      : Continue")
            print(Fore.YELLOW + "============================================================")

    # -----------------------------------------------------
    # File
