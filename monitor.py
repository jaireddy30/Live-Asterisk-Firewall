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


# Event types that are recognized but are NOT attacks. Reason
# text is static for auth-related events, and built dynamically
# (using the module field) for internal system log events.
STATIC_NON_ATTACK_REASONS = {

    "AUTH_CHALLENGE": "Authentication challenge sent (normal SIP handshake)",
    "AUTH_SUCCESS": "Successful authentication",
    "REGISTER_SUCCESS": "Successful registration",

}

# These event types get a reason built from parsed_event['module']
# instead of a fixed string, since they can come from several
# different modules (pbx.c, app_dial.c, bridge_channel.c, etc.)
DYNAMIC_MODULE_EVENTS = {
    "SYSTEM_LOG",
    "DATABASE_LOG",
    "PJSIP_LOG",
    "CHAN_SIP_LOG",
    "RTP_LOG",
}


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

    def on_modified(self, event):

        if event.src_path != ASTERISK_LOG:
            return

        while True:

            line = self.file.readline()

            if not line:
                break

            print(Fore.GREEN + "\n============================================================")
            print(Fore.GREEN + "LIVE LOG")
            print(Fore.GREEN + "============================================================")
            print(line.strip())

            # --------------------------------------------------
            # Parse
            # --------------------------------------------------

            parsed_event = self.parser.parse(line)

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

            # Module - use the parser's own detection instead of
            # a separate, incomplete hardcoded check.
            if parsed_event["module"] != "UNKNOWN":
                print(Fore.YELLOW + f"ℹ️ Module           : {parsed_event['module']}")

            print(Fore.CYAN + "============================================================")

            # --------------------------------------------------
            # Detection
            # --------------------------------------------------

            attack = self.detector.detect(parsed_event)

            # --------------------------------------------------
            # Firewall
            # --------------------------------------------------

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

                    print(Fore.YELLOW + f"Reason          : Internal Asterisk log, not a security event")
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
