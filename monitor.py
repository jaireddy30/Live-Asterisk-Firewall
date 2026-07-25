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

from parser import LogParser
from detector import Detector
from firewall import Firewall

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

# Marker that starts a multi-line raw SIP message dump, e.g.:
#   VERBOSE[20588] res_pjsip_logger.c: <--- Transmitting SIP response (521 bytes) to UDP:192.168.1.15:55714 --->
# Everything until the next blank line belongs to THIS message
# and must be parsed together, not line-by-line - otherwise the
# IP (in Via:/Contact:) and the method (in the request line or
# CSeq:) end up split across separate, uncorrelated events.
SIP_BLOCK_MARKER = "<---"


class LogMonitor(FileSystemEventHandler):

    def __init__(self):

        self.file = open(
            ASTERISK_LOG,
            "r"
        )

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
    # File watcher callback - reads raw lines and buffers
    # multi-line SIP blocks before handing off to process_entry
    # -----------------------------------------------------

    def on_modified(self, event):

        if event.src_path != ASTERISK_LOG:
            return

        while True:

            line = self.file.readline()

            if not line:
                break

            # Start of a new multi-line raw SIP message dump
            if SIP_BLOCK_MARKER in line and (
                "Transmitting SIP" in line or "Received SIP" in line
            ):
                self._in_sip_block = True
                self._sip_block_lines = [line]
                continue

            if self._in_sip_block:

                if line.strip() == "":
                    # Blank line = end of this SIP message block.
                    # Join everything and process it as ONE entry.
                    full_block = "".join(self._sip_block_lines)
                    self._in_sip_block = False
                    self._sip_block_lines = []
                    self.process_entry(full_block)
                else:
                    self._sip_block_lines.append(line)

                continue

            # Normal single-line log entry (SecurityEvent, VERBOSE
            # call-flow lines, etc.) - process immediately as before
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

        path=os.path.dirname(
            ASTERISK_LOG
        ),

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
