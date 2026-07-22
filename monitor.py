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

            print(
                Fore.GREEN +
                "\n[LIVE LOG]\n"
            )

            print(line.strip())

            # -----------------------------
            # Parse
            # -----------------------------

            parsed_event = self.parser.parse(line)

            print(
                Fore.CYAN +
                "\n[PARSED EVENT]"
            )

            print(parsed_event)

            # -----------------------------
            # Detect
            # -----------------------------

            attack = self.detector.detect(parsed_event)

            # -----------------------------
            # Firewall
            # -----------------------------

            if attack:

                self.firewall.process_attack(attack)


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