"""
===========================================================
Live Asterisk Firewall

simulate.py

Purpose:
    Simulates a live Asterisk log on Windows for testing.
    Writes real-world attack log lines into a temporary
    file, then runs monitor.py against it.

Usage:
    python simulate.py
===========================================================
"""

import os
import sys
import time
import threading
import subprocess

SIM_LOG = os.path.abspath("data/sim_asterisk.log")
os.makedirs("data", exist_ok=True)

LOG_LINES = [
    '[Jul 25 17:20:01] SECURITY[1234] res_security_log.c: SecurityEvent="ChallengeSent",EventTV="2026-07-25T17:20:01.000+0000",Severity="Informational",Service="PJSIP",AccountID="2001",SessionID="abc123",LocalAddress="IPV4/UDP/192.168.1.1/5060",RemoteAddress="IPV4/UDP/185.22.11.5/55060",Challenge="abc"\n',
    '[Jul 25 17:20:02] SECURITY[1234] res_security_log.c: SecurityEvent="InvalidPassword",EventTV="2026-07-25T17:20:02.000+0000",Severity="Error",Service="PJSIP",AccountID="2001",SessionID="s1",LocalAddress="IPV4/UDP/192.168.1.1/5060",RemoteAddress="IPV4/UDP/185.22.11.5/55060",Challenge="abc",ReceivedChallenge="xyz"\n',
    '[Jul 25 17:20:03] SECURITY[1234] res_security_log.c: SecurityEvent="InvalidPassword",EventTV="2026-07-25T17:20:03.000+0000",Severity="Error",Service="PJSIP",AccountID="2001",SessionID="s2",LocalAddress="IPV4/UDP/192.168.1.1/5060",RemoteAddress="IPV4/UDP/185.22.11.5/55060",Challenge="abc",ReceivedChallenge="xyz"\n',
    '[Jul 25 17:20:04] SECURITY[1234] res_security_log.c: SecurityEvent="InvalidPassword",EventTV="2026-07-25T17:20:04.000+0000",Severity="Error",Service="PJSIP",AccountID="2001",SessionID="s3",LocalAddress="IPV4/UDP/192.168.1.1/5060",RemoteAddress="IPV4/UDP/185.22.11.5/55060",Challenge="abc",ReceivedChallenge="xyz"\n',
    '[Jul 25 17:20:05] SECURITY[1234] res_security_log.c: SecurityEvent="InvalidPassword",EventTV="2026-07-25T17:20:05.000+0000",Severity="Error",Service="PJSIP",AccountID="2001",SessionID="s4",LocalAddress="IPV4/UDP/192.168.1.1/5060",RemoteAddress="IPV4/UDP/185.22.11.5/55060",Challenge="abc",ReceivedChallenge="xyz"\n',
    '[Jul 25 17:20:06] SECURITY[1234] res_security_log.c: SecurityEvent="InvalidPassword",EventTV="2026-07-25T17:20:06.000+0000",Severity="Error",Service="PJSIP",AccountID="2001",SessionID="s5",LocalAddress="IPV4/UDP/192.168.1.1/5060",RemoteAddress="IPV4/UDP/185.22.11.5/55060",Challenge="abc",ReceivedChallenge="xyz"\n',
    '[Jul 25 17:20:07] SECURITY[1234] res_security_log.c: SecurityEvent="InvalidPassword",EventTV="2026-07-25T17:20:07.000+0000",Severity="Error",Service="PJSIP",AccountID="2001",SessionID="s6",LocalAddress="IPV4/UDP/192.168.1.1/5060",RemoteAddress="IPV4/UDP/185.22.11.5/55060",Challenge="abc",ReceivedChallenge="xyz"\n',
    '[Jul 25 17:20:08] SECURITY[1234] res_security_log.c: SecurityEvent="InvalidPassword",EventTV="2026-07-25T17:20:08.000+0000",Severity="Error",Service="PJSIP",AccountID="2001",SessionID="s7",LocalAddress="IPV4/UDP/192.168.1.1/5060",RemoteAddress="IPV4/UDP/185.22.11.5/55060",Challenge="abc",ReceivedChallenge="xyz"\n',
    '[Jul 25 17:20:09] SECURITY[1234] res_security_log.c: SecurityEvent="InvalidPassword",EventTV="2026-07-25T17:20:09.000+0000",Severity="Error",Service="PJSIP",AccountID="2001",SessionID="s8",LocalAddress="IPV4/UDP/192.168.1.1/5060",RemoteAddress="IPV4/UDP/185.22.11.5/55060",Challenge="abc",ReceivedChallenge="xyz"\n',
    '[Jul 25 17:20:10] SECURITY[1234] res_security_log.c: SecurityEvent="InvalidPassword",EventTV="2026-07-25T17:20:10.000+0000",Severity="Error",Service="PJSIP",AccountID="2001",SessionID="s9",LocalAddress="IPV4/UDP/192.168.1.1/5060",RemoteAddress="IPV4/UDP/185.22.11.5/55060",Challenge="abc",ReceivedChallenge="xyz"\n',
    '[Jul 25 17:20:11] SECURITY[1234] res_security_log.c: SecurityEvent="InvalidPassword",EventTV="2026-07-25T17:20:11.000+0000",Severity="Error",Service="PJSIP",AccountID="2001",SessionID="s10",LocalAddress="IPV4/UDP/192.168.1.1/5060",RemoteAddress="IPV4/UDP/185.22.11.5/55060",Challenge="abc",ReceivedChallenge="xyz"\n',
    '[Jul 25 17:20:15] VERBOSE[22417][C-00000009] pbx.c: Executing [2001@internal:1] Dial("PJSIP/2002-00000010", "PJSIP/2001") in new stack\n',
    '[Jul 25 17:20:16] VERBOSE[22417][C-00000009] app_dial.c: Called PJSIP/2001\n',
    '[Jul 25 17:20:20] SECURITY[1234] res_security_log.c: SecurityEvent="InvalidAccountID",EventTV="2026-07-25T17:20:20.000+0000",Severity="Error",Service="PJSIP",AccountID="hacker",SessionID="h1",LocalAddress="IPV4/UDP/192.168.1.1/5060",RemoteAddress="IPV4/UDP/91.55.77.22/55060"\n',
    '[2026-07-25 17:20:25.311] WARNING[1643562] core_local.c: Someone used Local/919566704154__7e36d5ab-7958-43ac-b89e-b3889244b808__8d18d75e-0dac-4e97 somewhere without a @context. This is bad.\n',
    '[2026-07-25 17:20:27.311] WARNING[1643562] core_local.c: Someone used Local/919566704154__8a47e6bc-8069-54bd-c90f-c4990355c909__9e29e86f-1ebd-5f08 somewhere without a @context. This is bad.\n',
]


def write_lines(log_path):
    time.sleep(1.5)
    with open(log_path, "a", encoding="utf-8") as f:
        for line in LOG_LINES:
            f.write(line)
            f.flush()
            time.sleep(0.4)


def main():

    with open(SIM_LOG, "w", encoding="utf-8") as f:
        f.write("")

    print("=" * 60)
    print("LIVE ASTERISK FIREWALL - SIMULATION MODE")
    print("=" * 60)
    print(f"Simulated log file : {SIM_LOG}")
    print(f"Attack lines       : {len(LOG_LINES)}")
    print("Starting monitor in 1.5 seconds...")
    print("=" * 60)
    print()

    writer = threading.Thread(target=write_lines, args=(SIM_LOG,), daemon=True)
    writer.start()

    env = os.environ.copy()
    env["ASTERISK_LOG"] = SIM_LOG

    try:
        subprocess.run(
            [sys.executable, "monitor.py"],
            env=env,
            timeout=len(LOG_LINES) * 0.4 + 4
        )
    except subprocess.TimeoutExpired:
        print()
        print("=" * 60)
        print("SIMULATION COMPLETE")
        print("=" * 60)


if __name__ == "__main__":
    main()
