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


# Events the parser can classify but that are NOT attacks by
# themselves. These should be reported as "recognized, no
# action needed" rather than "unsupported/unknown".
KNOWN_NON_ATTACK_EVENTS = {

    "AUTH_CHALLENGE": "Authentication challenge sent (normal SIP handshake)",
    "AUTH_SUCCESS": "Successful authentication",
    "REGISTER_SUCCESS": "Successful registration",
    "SYSTEM_LOG": "Internal system log (channel.c)",
    "DATABASE_LOG": "Internal database log (func_odbc.c)",
    "PJSIP_LOG": "PJSIP stack log, not a security event",
    "CHAN_SIP_LOG": "chan_sip stack log, not a security event",
    "RTP_LOG": "RTP media log, not a security event",

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

            # Source IP
            if parsed_event["source_ip"] != "UNKNOWN":
                print(Fore.GREEN + f"✅ Source IP        : {parsed_event['source_ip']}")
            else:
                print(Fore.RED + "❌ Source IP        : Not Found")

            # SIP Method
            if parsed_event["method"] != "UNKNOWN":
                print(Fore.GREEN + f"✅ SIP Method       : {parsed_event['method']}")
            else:
                print(Fore.RED + "❌ SIP Method       : Not Found")

            # Event Type
            if parsed_event["event"] != "OTHER":
                print(Fore.GREEN + f"✅ Event Type       : {parsed_event['event']}")
            else:
                print(Fore.RED + "❌ Event Type       : Unknown")

            # Authentication
            if parsed_event["event"] == "FAILED_AUTH":
                print(Fore.GREEN + "✅ Authentication   : Failed")
            elif parsed_event["event"] == "AUTH_SUCCESS":
                print(Fore.GREEN + "✅ Authentication   : Success")
            else:
                print(Fore.RED + "❌ Authentication   : Not Found")

            # REGISTER
            if parsed_event["method"] == "REGISTER":
                print(Fore.GREEN + "✅ REGISTER         : Detected")
            else:
                print(Fore.RED + "❌ REGISTER         : Not Found")

            # INVITE
            if parsed_event["method"] == "INVITE":
                print(Fore.GREEN + "✅ INVITE           : Detected")
            else:
                print(Fore.RED + "❌ INVITE           : Not Found")

            # OPTIONS
            if parsed_event["method"] == "OPTIONS":
                print(Fore.GREEN + "✅ OPTIONS          : Detected")
            else:
                print(Fore.RED + "❌ OPTIONS          : Not Found")

            # Module Detection
            if "func_odbc.c" in line:
                print(Fore.YELLOW + "ℹ️ Module           : func_odbc.c")
            elif "res_pjsip" in line:
                print(Fore.YELLOW + "ℹ️ Module           : res_pjsip")
            elif "chan_sip" in line:
                print(Fore.YELLOW + "ℹ️ Module           : chan_sip")

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

                # --------------------------------------------
                # Case 1: Parser recognized the event, it's just
                # not an attack (e.g. AUTH_SUCCESS, AUTH_CHALLENGE)
                # --------------------------------------------

                if event_type in KNOWN_NON_ATTACK_EVENTS:

                    print(Fore.YELLOW + "Status          : Ignored")
                    print(Fore.YELLOW + f"Reason          : {KNOWN_NON_ATTACK_EVENTS[event_type]}")
                    print(Fore.YELLOW + f"Event Type      : {event_type}")

                # --------------------------------------------
                # Case 2: Parser genuinely could not classify
                # the line (event == "OTHER")
                # --------------------------------------------

                elif event_type == "OTHER":

                    print(Fore.YELLOW + "Status          : Ignored")

                    if "func_odbc.c" in line:
                        print(Fore.YELLOW + "Reason          : Not a SIP Security Event")
                        print(Fore.YELLOW + "Module          : func_odbc.c")
                    elif "res_pjsip" in line:
                        print(Fore.YELLOW + "Reason          : SIP Event Not Matching Detection Rules")
                        print(Fore.YELLOW + "Module          : res_pjsip")
                    elif "chan_sip" in line:
                        print(Fore.YELLOW + "Reason          : SIP Event Not Matching Detection Rules")
                        print(Fore.YELLOW + "Module          : chan_sip")
                    else:
                        print(Fore.YELLOW + "Reason          : Unsupported or Unknown Log")
                        print(Fore.YELLOW + "Module          : Unknown")

                # --------------------------------------------
                # Case 3: Recognized event, below attack
                # threshold (e.g. one failed auth, one OPTIONS)
                # --------------------------------------------

                else:

                    print(Fore.YELLOW + "Status          : Ignored")
                    print(Fore.YELLOW + f"Reason          : Recognized event, below attack threshold")
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
