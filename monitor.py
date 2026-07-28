"""
====================================================
LIVE ASTERISK FIREWALL

monitor.py

Main entry point. Supports 3 modes:
  1. AMI MODE     — direct Asterisk connection (best)
  2. SNIFFER MODE — captures packets from port 5060
  3. FILE MODE    — watches Asterisk log file (default)

Set mode in config.py:
  USE_AMI     = True  → AMI mode
  USE_SNIFFER = True  → Packet sniffer mode
  Both False          → File watcher mode (default)
====================================================
"""

import os
import time

from watchdog.observers import Observer
from watchdog.events    import FileSystemEventHandler

from colorama import Fore, init

from config import (
    ASTERISK_LOG,
    USE_AMI,     AMI_HOST, AMI_PORT, AMI_USERNAME, AMI_SECRET,
    USE_SNIFFER, SNIFF_INTERFACE, SNIFF_PORT,
    VERBOSE_LOGGING, SKIP_PRIVATE_IPS,
    SKIP_EVENT_TYPES, PRIVATE_IP_PREFIXES,
)

from log_parser import LogParser
from detector   import Detector
from firewall   import Firewall
from ip_lookup  import lookup_ip, format_ip_info, lookup_phone_country

init(autoreset=True)


# ===========================================================
# Status / Action / Reason label maps
# ===========================================================

STATUS_LABELS = {
    "AUTH_CHALLENGE":   "Informational",
    "AUTH_SUCCESS":     "Allowed",
    "REGISTER_SUCCESS": "Allowed",
    "FAILED_AUTH":      "Warning",
    "UNKNOWN_ENDPOINT": "Warning",
    "ACL_BLOCKED":      "Warning",
    "TOLL_FRAUD":       "Critical",
    "INVITE":           "Allowed",
    "REGISTER":         "Allowed",
    "OPTIONS":          "Allowed",
    "BYE":              "Allowed",
    "ACK":              "Allowed",
    "OTHER":            "Allowed",
    "SYSTEM_LOG":       "Internal",
    "DATABASE_LOG":     "Internal",
    "PJSIP_LOG":        "Internal",
    "CHAN_SIP_LOG":     "Internal",
    "RTP_LOG":          "Internal",
}

ACTION_LABELS = {
    "AUTH_CHALLENGE":   "Monitoring",
    "AUTH_SUCCESS":     "Monitoring",
    "REGISTER_SUCCESS": "Monitoring",
    "FAILED_AUTH":      "Tracking",
    "UNKNOWN_ENDPOINT": "Tracking",
    "ACL_BLOCKED":      "Tracking",
    "TOLL_FRAUD":       "Tracking",
    "INVITE":           "Monitoring",
    "REGISTER":         "Monitoring",
    "OPTIONS":          "Monitoring",
    "BYE":              "Monitoring",
    "ACK":              "Monitoring",
    "OTHER":            "Monitoring",
    "SYSTEM_LOG":       "Skip",
    "DATABASE_LOG":     "Skip",
    "PJSIP_LOG":        "Skip",
}

REASON_LABELS = {
    "AUTH_CHALLENGE":   "Authentication challenge — normal SIP handshake",
    "AUTH_SUCCESS":     "Successful authentication — call permitted",
    "FAILED_AUTH":      "Failed authentication — tracking for brute force",
    "UNKNOWN_ENDPOINT": "Unknown SIP account — possible scanning",
    "ACL_BLOCKED":      "ACL violation — tracking for block",
    "TOLL_FRAUD":       "Suspicious outbound call — tracking for toll fraud",
    "INVITE":           "Call INVITE tracked — below flood threshold",
    "REGISTER":         "REGISTER tracked — below flood threshold",
    "OPTIONS":          "OPTIONS tracked — below flood threshold",
    "SYSTEM_LOG":       "Internal Asterisk log — not a security event",
    "DATABASE_LOG":     "Internal Asterisk log — not a security event",
    "PJSIP_LOG":        "Internal Asterisk log — not a security event",
}

DYNAMIC_MODULE_EVENTS = {
    "SYSTEM_LOG", "DATABASE_LOG",
    "PJSIP_LOG",  "CHAN_SIP_LOG", "RTP_LOG",
}

SIP_BLOCK_MARKER = "<---"


def is_new_log_entry(line):
    """True if line starts a new Asterisk log entry."""
    return line.lstrip().startswith("[")


# ===========================================================
# BASE CLASS — shared logic for all 3 modes
# ===========================================================

class BaseMonitor:

    def _init_components(self):
        self.parser   = LogParser()
        self.detector = Detector()
        self.firewall = Firewall()
        self._in_sip_block    = False
        self._sip_block_lines = []

    # ----------------------------------------------------------
    # Filter — returns True if event should be skipped
    # ----------------------------------------------------------

    def _should_skip(self, parsed_event):
        """
        Silently skip noisy / irrelevant events.
        Controlled by VERBOSE_LOGGING, SKIP_PRIVATE_IPS,
        SKIP_EVENT_TYPES in config.py.
        """

        # Verbose mode — show everything
        if VERBOSE_LOGGING:
            return False

        src_ip     = parsed_event.get("source_ip", "UNKNOWN")
        event_type = parsed_event.get("event",     "OTHER")

        # Skip private / localhost IPs
        if SKIP_PRIVATE_IPS and src_ip.startswith(PRIVATE_IP_PREFIXES):
            return True

        # Skip noisy event types (OPTIONS, internal logs, etc.)
        if event_type in SKIP_EVENT_TYPES:
            return True

        return False

    # ----------------------------------------------------------
    # Process one fully assembled log entry
    # ----------------------------------------------------------

    def process_entry(self, text):

        parsed_event = self.parser.parse(text)

        # Apply filter — skip noisy events
        if self._should_skip(parsed_event):
            return

        # Show only the first summary line — raw SIP body hidden
        first_line = text.strip().split('\n')[0]

        print(Fore.GREEN + "\n============================================================")
        print(Fore.GREEN + "LIVE LOG")
        print(Fore.GREEN + "============================================================")
        print(first_line)

        # --------------------------------------------------
        # Parser Analysis
        # --------------------------------------------------

        print(Fore.CYAN + "\n============================================================")
        print(Fore.CYAN + "PARSER ANALYSIS")
        print(Fore.CYAN + "============================================================")

        print(Fore.GREEN + f"[TIME] Timestamp        : {parsed_event['timestamp']}")

        if parsed_event["source_ip"] != "UNKNOWN":
            print(Fore.GREEN + f"[OK]  Source IP        : {parsed_event['source_ip']}")
        else:
            print(Fore.RED   + "[--]  Source IP        : Not Found")

        if parsed_event["method"] != "UNKNOWN":
            print(Fore.GREEN + f"[OK]  SIP Method       : {parsed_event['method']}")
        else:
            print(Fore.RED   + "[--]  SIP Method       : Not Found")

        if parsed_event["event"] != "OTHER":
            print(Fore.GREEN + f"[OK]  Event Type       : {parsed_event['event']}")
        else:
            print(Fore.RED   + "[--]  Event Type       : Unknown")

        if parsed_event["event"] == "FAILED_AUTH":
            print(Fore.RED   + "[!!]  Authentication   : Failed")
        elif parsed_event["event"] == "AUTH_SUCCESS":
            print(Fore.GREEN + "[OK]  Authentication   : Success")
        else:
            print(Fore.RED   + "[--]  Authentication   : Not Found")

        if parsed_event["method"] == "REGISTER":
            print(Fore.GREEN + "[OK]  REGISTER         : Detected")
        else:
            print(Fore.RED   + "[--]  REGISTER         : Not Found")

        if parsed_event["method"] == "INVITE":
            print(Fore.GREEN + "[OK]  INVITE           : Detected")
        else:
            print(Fore.RED   + "[--]  INVITE           : Not Found")

        if parsed_event["method"] == "OPTIONS":
            print(Fore.GREEN + "[OK]  OPTIONS          : Detected")
        else:
            print(Fore.RED   + "[--]  OPTIONS          : Not Found")

        if parsed_event["module"] != "UNKNOWN":
            print(Fore.YELLOW + f"[i]   Module           : {parsed_event['module']}")

        print(Fore.CYAN + "============================================================")

        # --------------------------------------------------
        # IP Geolocation
        # --------------------------------------------------

        src_ip = parsed_event["source_ip"]
        if src_ip and src_ip != "UNKNOWN":
            print(Fore.MAGENTA + "\n============================================================")
            print(Fore.MAGENTA + "IP GEOLOCATION")
            print(Fore.MAGENTA + "============================================================")
            print(Fore.MAGENTA + f"  IP        : {src_ip}")
            geo = lookup_ip(src_ip)
            print(Fore.MAGENTA + format_ip_info(geo))
            print(Fore.MAGENTA + "============================================================")

        # --------------------------------------------------
        # Toll Fraud destination
        # --------------------------------------------------

        destination = parsed_event.get("destination")
        if destination and parsed_event["event"] == "TOLL_FRAUD":
            country, prefix = lookup_phone_country(destination)
            print(Fore.MAGENTA + "\n============================================================")
            print(Fore.MAGENTA + "TOLL FRAUD DESTINATION")
            print(Fore.MAGENTA + "============================================================")
            print(Fore.MAGENTA + f"  Number    : +{destination}")
            print(Fore.MAGENTA + f"  Prefix    : {prefix}")
            print(Fore.MAGENTA + f"  Country   : {country}")
            print(Fore.MAGENTA + "============================================================")

        # --------------------------------------------------
        # Detection + Firewall
        # --------------------------------------------------

        attack = self.detector.detect(parsed_event)

        if attack:
            self.firewall.process_attack(attack)
        else:
            self._display_firewall_status(parsed_event)

    # ----------------------------------------------------------
    # Firewall status display (no attack)
    # ----------------------------------------------------------

    def _display_firewall_status(self, parsed_event):

        event_type = parsed_event.get("event",  "OTHER")
        module     = parsed_event.get("module", "UNKNOWN")

        status = STATUS_LABELS.get(event_type, "Allowed")
        action = ACTION_LABELS.get(event_type, "Monitoring")
        reason = REASON_LABELS.get(event_type, "Event tracked, below block threshold")

        print(Fore.YELLOW + "\n============================================================")
        print(Fore.YELLOW + "FIREWALL ANALYSIS")
        print(Fore.YELLOW + "============================================================")
        print(Fore.YELLOW + f"Status          : {status}")
        print(Fore.YELLOW + f"Reason          : {reason}")

        if event_type in DYNAMIC_MODULE_EVENTS:
            print(Fore.YELLOW + f"Module          : {module}")

        print(Fore.YELLOW + f"Event Type      : {event_type}")
        print(Fore.YELLOW + "Threat Level    : None")
        print(Fore.YELLOW + f"Firewall Action : {action}")
        print(Fore.YELLOW + "============================================================")

    # ----------------------------------------------------------
    # Shared line buffer — assembles multi-line SIP blocks
    # ----------------------------------------------------------

    def _handle_line(self, line):

        is_marker = SIP_BLOCK_MARKER in line and (
            "Transmitting SIP" in line or "Received SIP" in line
        )

        if self._in_sip_block:
            if is_new_log_entry(line):
                full_block = "".join(self._sip_block_lines)
                self._in_sip_block    = False
                self._sip_block_lines = []
                self.process_entry(full_block)
            else:
                self._sip_block_lines.append(line)
                return

        if is_marker:
            self._in_sip_block    = True
            self._sip_block_lines = [line]
            return

        if not line.strip():
            return

        self.process_entry(line)


# ===========================================================
# MODE 1 — FILE WATCHER (default)
# ===========================================================

class LogMonitor(BaseMonitor, FileSystemEventHandler):

    def __init__(self):
        super().__init__()
        self._init_components()

        try:
            self.file = open(
                ASTERISK_LOG, "r",
                encoding="utf-8",
                errors="replace"
            )
        except FileNotFoundError:
            print(Fore.RED + f"[ERROR] Log file not found: {ASTERISK_LOG}")
            print(Fore.RED + "       Make sure Asterisk is running.")
            raise SystemExit(1)

        self.file.seek(0, os.SEEK_END)

    def __del__(self):
        try:
            if self.file and not self.file.closed:
                self.file.close()
        except AttributeError:
            pass

    def on_modified(self, event):
        if event.src_path != ASTERISK_LOG:
            return
        while True:
            line = self.file.readline()
            if not line:
                break
            self._handle_line(line)


# ===========================================================
# MAIN
# ===========================================================

def main():

    print("=" * 60)
    print("LIVE ASTERISK FIREWALL")
    print("=" * 60)
    print()

    mode_label = "VERBOSE" if VERBOSE_LOGGING else "FILTERED"
    print(Fore.CYAN + f"Log Mode  : {mode_label}")

    if not VERBOSE_LOGGING:
        print(Fore.CYAN + "Filtering : Private IPs hidden | Noisy events skipped")

    print()

    # --------------------------------------------------
    # AMI MODE
    # --------------------------------------------------
    if USE_AMI:

        from ami_monitor import AMIMonitor

        print(Fore.CYAN + "Mode      : AMI DIRECT CONNECTION")
        print(Fore.CYAN + f"Host      : {AMI_HOST}:{AMI_PORT}")
        print(Fore.CYAN + f"Username  : {AMI_USERNAME}")
        print()

        AMIMonitor(
            host     = AMI_HOST,
            port     = AMI_PORT,
            username = AMI_USERNAME,
            secret   = AMI_SECRET,
        ).start()

    # --------------------------------------------------
    # PACKET SNIFFER MODE
    # --------------------------------------------------
    elif USE_SNIFFER:

        from packet_sniffer import SIPPacketSniffer

        print(Fore.CYAN + "Mode      : PACKET SNIFFER")
        print(Fore.CYAN + f"Interface : {SNIFF_INTERFACE}")
        print(Fore.CYAN + f"Port      : {SNIFF_PORT}")
        print()

        SIPPacketSniffer(
            interface = SNIFF_INTERFACE,
            port      = SNIFF_PORT,
        ).run()

    # --------------------------------------------------
    # FILE WATCHER MODE (default)
    # --------------------------------------------------
    else:

        print(Fore.GREEN + "Mode      : FILE WATCHER")
        print(Fore.GREEN + f"Watching  : {ASTERISK_LOG}")
        print()

        observer = Observer()
        observer.schedule(
            LogMonitor(),
            path      = os.path.dirname(ASTERISK_LOG) or ".",
            recursive = False,
        )
        observer.start()

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()

        observer.join()


if __name__ == "__main__":
    main()
