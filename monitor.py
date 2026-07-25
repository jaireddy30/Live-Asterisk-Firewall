"""
====================================================

LIVE ASTERISK FIREWALL

MODULE 1

MAIN ENTRY POINT

====================================================
"""

import os
import time

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from colorama import Fore
from colorama import init

from config import ASTERISK_LOG

from log_parser import LogParser
from detector import Detector
from firewall import Firewall
from ip_lookup import lookup_ip, format_ip_info, lookup_phone_country

init(autoreset=True)


STATIC_NON_ATTACK_REASONS = {

    "AUTH_CHALLENGE": "Authentication challenge sent (normal SIP handshake)",
    "AUTH_SUCCESS": "Successful authentication",
    "REGISTER_SUCCESS": "Successful registration",

}

DYNAMIC_MODULE_EVENTS = {
    "SYSTEM_LOG",
    "DATABASE_LOG",
    "PJSIP_LOG",
    "CHAN_SIP_LOG",
    "RTP_LOG",
}

SIP_BLOCK_MARKER = "<---"


def is_new_log_entry(line):
    stripped = line.lstrip()
    return stripped.startswith("[")


class LogMonitor(FileSystemEventHandler):

    def __init__(self):

        # FIX 1: Call super().__init__() so watchdog's
        # FileSystemEventHandler is properly initialised.
        super().__init__()

        # FIX 2: Wrap open() so a missing log file prints a
        # clear message instead of an unhandled traceback.
        try:
            self.file = open(ASTERISK_LOG, "r", encoding="utf-8", errors="replace")
        except FileNotFoundError:
            print(Fore.RED + f"[ERROR] Log file not found: {ASTERISK_LOG}")
            print(Fore.RED + "       Make sure Asterisk is running and the path is correct.")
            raise SystemExit(1)

        self.file.seek(0, os.SEEK_END)

        self.parser   = LogParser()
        self.detector = Detector()
        self.firewall = Firewall()

        # Buffering state for multi-line SIP message blocks
        self._in_sip_block    = False
        self._sip_block_lines = []

    # FIX 3: Close the file handle when the monitor is destroyed
    def __del__(self):
        try:
            if self.file and not self.file.closed:
                self.file.close()
        except AttributeError:
            pass

    def process_entry(self, text):

        print(Fore.GREEN + "\n============================================================")
        print(Fore.GREEN + "LIVE LOG")
        print(Fore.GREEN + "============================================================")
        print(text.strip())

        parsed_event = self.parser.parse(text)

        print(Fore.CYAN + "\n============================================================")
        print(Fore.CYAN + "PARSER ANALYSIS")
        print(Fore.CYAN + "============================================================")

        print(Fore.GREEN + f"[TIME] Timestamp        : {parsed_event['timestamp']}")

        if parsed_event["source_ip"] != "UNKNOWN":
            print(Fore.GREEN + f"[OK] Source IP         : {parsed_event['source_ip']}")
        else:
            print(Fore.RED + "[--] Source IP         : Not Found")

        if parsed_event["method"] != "UNKNOWN":
            print(Fore.GREEN + f"[OK] SIP Method        : {parsed_event['method']}")
        else:
            print(Fore.RED + "[--] SIP Method        : Not Found")

        if parsed_event["event"] != "OTHER":
            print(Fore.GREEN + f"[OK] Event Type        : {parsed_event['event']}")
        else:
            print(Fore.RED + "[--] Event Type        : Unknown")

        if parsed_event["event"] == "FAILED_AUTH":
            print(Fore.GREEN + "[OK] Authentication    : Failed")
        elif parsed_event["event"] == "AUTH_SUCCESS":
            print(Fore.GREEN + "[OK] Authentication    : Success")
        else:
            print(Fore.RED + "[--] Authentication    : Not Found")

        if parsed_event["method"] == "REGISTER":
            print(Fore.GREEN + "[OK] REGISTER          : Detected")
        else:
            print(Fore.RED + "[--] REGISTER          : Not Found")

        if parsed_event["method"] == "INVITE":
            print(Fore.GREEN + "[OK] INVITE            : Detected")
        else:
            print(Fore.RED + "[--] INVITE            : Not Found")

        if parsed_event["method"] == "OPTIONS":
            print(Fore.GREEN + "[OK] OPTIONS           : Detected")
        else:
            print(Fore.RED + "[--] OPTIONS           : Not Found")

        if parsed_event["module"] != "UNKNOWN":
            print(Fore.YELLOW + f"[i]  Module            : {parsed_event['module']}")

        print(Fore.CYAN + "============================================================")

        # --------------------------------------------------
        # IP Geolocation — show where the IP is coming from
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
        # Toll Fraud destination country
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

        attack = self.detector.detect(parsed_event)

        if attack:

            self.firewall.process_attack(attack)

        else:

            print(Fore.YELLOW + "\n============================================================")
            print(Fore.YELLOW + "FIREWALL ANALYSIS")
            print(Fore.YELLOW + "============================================================")

            event_type = parsed_event["event"]
            module     = parsed_event["module"]

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

    def on_modified(self, event):

        if event.src_path != ASTERISK_LOG:
            return

        while True:

            line = self.file.readline()

            if not line:
                break

            is_marker_line = SIP_BLOCK_MARKER in line and (
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
                    continue

            if is_marker_line:
                self._in_sip_block    = True
                self._sip_block_lines = [line]
                continue

            if not line.strip():
                continue

            self.process_entry(line)


def main():

    print("=" * 60)
    print("LIVE ASTERISK FIREWALL")
    print("=" * 60)

    print()
    print("Watching")
    print(ASTERISK_LOG)
    print()

    observer = Observer()

    observer.schedule(
        LogMonitor(),
        path=os.path.dirname(ASTERISK_LOG) or ".",
        recursive=False
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
