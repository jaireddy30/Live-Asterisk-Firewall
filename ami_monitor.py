"""
====================================================
LIVE ASTERISK FIREWALL

ami_monitor.py

Purpose:
    Direct connection to Asterisk via AMI (port 5038).
    Receives real-time security and call events
    without needing log files or PJSIP logger.

AMI Setup in /etc/asterisk/manager.conf:
    [general]
    enabled  = yes
    port     = 5038
    bindaddr = 127.0.0.1

    [firewall]
    secret = yourpassword
    read   = security,call,log,verbose
    write  = system

Then reload:
    sudo asterisk -rx "manager reload"
====================================================
"""

import socket
import time

from datetime import datetime
from colorama import Fore, init

from detector import Detector
from firewall import Firewall
from ip_lookup import lookup_ip, format_ip_info, lookup_phone_country

init(autoreset=True)


# ----------------------------------------------------------
# AMI Security Event → Internal Event Type mapping
# ----------------------------------------------------------

AMI_SECURITY_EVENT_MAP = {
    "ChallengeSent":        "AUTH_CHALLENGE",
    "SuccessfulAuth":       "AUTH_SUCCESS",
    "InvalidPassword":      "FAILED_AUTH",
    "InvalidAccountID":     "UNKNOWN_ENDPOINT",
    "ChallengeResponseFailed": "FAILED_AUTH",
    "MemoryLimitReached":   "SYSTEM_LOG",
    "LoadAverageLimit":     "SYSTEM_LOG",
    "RequestNotSupported":  "SYSTEM_LOG",
    "SessionLimit":         "SYSTEM_LOG",
    "ACL":                  "ACL_BLOCKED",
    "RequestNotAllowed":    "ACL_BLOCKED",
    "AuthMethodNotAllowed": "FAILED_AUTH",
    "TollFraud":            "TOLL_FRAUD",
}

# ----------------------------------------------------------
# AMI Event → SIP Method mapping
# ----------------------------------------------------------

AMI_CHANNEL_METHOD_MAP = {
    "Newchannel": "INVITE",
    "Hangup":     "BYE",
    "Registry":   "REGISTER",
}

# Status/action labels
STATUS_LABELS = {
    "AUTH_CHALLENGE":   "Informational",
    "AUTH_SUCCESS":     "Allowed",
    "REGISTER":         "Allowed",
    "INVITE":           "Allowed",
    "OPTIONS":          "Allowed",
    "BYE":              "Allowed",
    "ACK":              "Allowed",
    "OTHER":            "Allowed",
}

FIREWALL_ACTION_LABELS = {
    "AUTH_CHALLENGE":   "Monitoring",
    "AUTH_SUCCESS":     "Monitoring",
    "REGISTER":         "Monitoring",
    "INVITE":           "Monitoring",
    "OPTIONS":          "Monitoring",
    "BYE":              "Monitoring",
    "ACK":              "Monitoring",
    "OTHER":            "Monitoring",
}


# ===========================================================
# AMI Client — raw TCP socket connection to Asterisk
# ===========================================================

class AMIClient:

    def __init__(self, host, port, username, secret):
        self.host     = host
        self.port     = port
        self.username = username
        self.secret   = secret
        self.sock     = None

    def connect(self):
        """Connect and log in to Asterisk AMI."""

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect((self.host, self.port))
        self.sock.settimeout(None)

        # Read AMI banner
        banner = self._read_message()
        print(Fore.CYAN + f"[AMI] Connected  : {banner.strip()}")

        # Send login
        self._send({
            "Action":   "Login",
            "Username": self.username,
            "Secret":   self.secret,
        })

        response = self._read_message()

        if "Success" in response:
            print(Fore.GREEN + "[AMI] Login      : Success")
            return True
        else:
            print(Fore.RED + f"[AMI] Login failed: {response}")
            return False

    def _send(self, action_dict):
        """Send an AMI action."""
        msg = ""
        for key, val in action_dict.items():
            msg += f"{key}: {val}\r\n"
        msg += "\r\n"
        self.sock.sendall(msg.encode("utf-8"))

    def _read_message(self):
        """
        Read one AMI message (ends with blank line).
        """
        data = b""
        while b"\r\n\r\n" not in data and b"\n\n" not in data:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            data += chunk
        return data.decode("utf-8", errors="replace")

    def listen(self, callback):
        """
        Continuously read AMI events and call callback(event_dict)
        for each complete event received.
        """
        buffer = ""

        while True:
            try:
                chunk = self.sock.recv(4096).decode("utf-8", errors="replace")
                if not chunk:
                    print(Fore.RED + "[AMI] Connection closed by Asterisk.")
                    break

                buffer += chunk

                # AMI events are separated by \r\n\r\n
                while "\r\n\r\n" in buffer:
                    raw, buffer = buffer.split("\r\n\r\n", 1)
                    event = self._parse(raw)
                    if event:
                        callback(event)

            except KeyboardInterrupt:
                break

            except Exception as e:
                print(Fore.RED + f"[AMI] Error: {e}")
                break

    @staticmethod
    def _parse(raw):
        """Parse a raw AMI event string into a dict."""
        event = {}
        for line in raw.strip().split("\r\n"):
            if ": " in line:
                key, _, val = line.partition(": ")
                event[key.strip()] = val.strip()
        return event or None

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass


# ===========================================================
# AMI Monitor — processes events and feeds detector/firewall
# ===========================================================

class AMIMonitor:

    def __init__(self, host, port, username, secret):
        self.client   = AMIClient(host, port, username, secret)
        self.detector = Detector()
        self.firewall = Firewall()

    def start(self):
        """Connect to AMI and start listening."""

        connected = False
        while not connected:
            try:
                connected = self.client.connect()
                if not connected:
                    print(Fore.RED + "[AMI] Retrying in 5s...")
                    time.sleep(5)
            except Exception as e:
                print(Fore.RED + f"[AMI] Connection failed: {e} — retrying in 5s...")
                time.sleep(5)

        print(Fore.GREEN + "[AMI] Listening for Asterisk events...")
        print()

        try:
            self.client.listen(self.handle_event)
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\n[AMI] Stopped.")
        finally:
            self.client.close()

    # ----------------------------------------------------------
    # Handle each AMI event
    # ----------------------------------------------------------

    def handle_event(self, ami_event):
        """Process one AMI event dict."""

        event_name = ami_event.get("Event", "")
        if not event_name:
            return

        # --------------------------------------------------
        # Security Events (from res_security_log)
        # --------------------------------------------------
        if event_name == "SecurityEvent":
            self._handle_security_event(ami_event)

        # --------------------------------------------------
        # Call Events
        # --------------------------------------------------
        elif event_name in AMI_CHANNEL_METHOD_MAP:
            self._handle_channel_event(ami_event, event_name)

    # ----------------------------------------------------------
    # Security Event Handler
    # ----------------------------------------------------------

    def _handle_security_event(self, ami_event):

        sub_event  = ami_event.get("SubEvent", "")
        event_type = AMI_SECURITY_EVENT_MAP.get(sub_event, "OTHER")

        # Extract IP from RemoteAddress field
        # Format: "IPV4/UDP/185.22.11.5/5060"
        remote_addr = ami_event.get("RemoteAddress", "")
        src_ip      = self._extract_ip(remote_addr)

        account_id = ami_event.get("AccountID", "")
        severity   = ami_event.get("Severity", "")
        service    = ami_event.get("Service", "")

        parsed_event = {
            "timestamp":  datetime.now().isoformat(),
            "source_ip":  src_ip or "UNKNOWN",
            "method":     "UNKNOWN",
            "event":      event_type,
            "module":     "AMI",
            "account_id": account_id,
            "service":    service,
            "destination": None,
        }

        self._display_event(ami_event, parsed_event, sub_event)

        # Run through detector + firewall
        attack = self.detector.detect(parsed_event)
        if attack:
            self.firewall.process_attack(attack)
        else:
            self._display_firewall_status(parsed_event)

    # ----------------------------------------------------------
    # Channel Event Handler (INVITE / BYE / REGISTER)
    # ----------------------------------------------------------

    def _handle_channel_event(self, ami_event, event_name):

        method    = AMI_CHANNEL_METHOD_MAP.get(event_name, "UNKNOWN")
        caller_id = ami_event.get("CallerIDNum", "")
        channel   = ami_event.get("Channel", "")
        context   = ami_event.get("Context", "")
        exten     = ami_event.get("Exten", "")

        # Try to extract IP from channel name
        # e.g. "PJSIP/185.22.11.5-0000001"
        src_ip = self._extract_ip_from_channel(channel)

        parsed_event = {
            "timestamp":  datetime.now().isoformat(),
            "source_ip":  src_ip or "UNKNOWN",
            "method":     method,
            "event":      method,
            "module":     "AMI",
            "caller_id":  caller_id,
            "destination": exten or None,
        }

        self._display_channel_event(ami_event, parsed_event, event_name)

        attack = self.detector.detect(parsed_event)
        if attack:
            self.firewall.process_attack(attack)
        else:
            self._display_firewall_status(parsed_event)

    # ----------------------------------------------------------
    # Display — Security Event
    # ----------------------------------------------------------

    def _display_event(self, ami_raw, parsed, sub_event):

        src_ip = parsed["source_ip"]

        print(Fore.GREEN + "\n============================================================")
        print(Fore.GREEN + "AMI EVENT RECEIVED")
        print(Fore.GREEN + "============================================================")
        print(Fore.GREEN + f"  SecurityEvent : {sub_event}")

        print(Fore.CYAN + "\n============================================================")
        print(Fore.CYAN + "AMI SECURITY ANALYSIS")
        print(Fore.CYAN + "============================================================")
        print(Fore.GREEN + f"[TIME] Timestamp   : {parsed['timestamp']}")

        if src_ip != "UNKNOWN":
            print(Fore.GREEN + f"[OK]  Source IP    : {src_ip}")
        else:
            print(Fore.RED   + "[--]  Source IP    : Not Found")

        print(Fore.GREEN + f"[OK]  Event Type   : {parsed['event']}")
        print(Fore.GREEN + f"[OK]  Sub Event    : {sub_event}")

        if parsed.get("account_id"):
            print(Fore.GREEN + f"[OK]  Account      : {parsed['account_id']}")
        if parsed.get("service"):
            print(Fore.GREEN + f"[OK]  Service      : {parsed['service']}")

        # AMI raw fields
        for field in ["Severity", "LocalAddress", "RemoteAddress", "Challenge", "UsingPassword"]:
            val = ami_raw.get(field)
            if val:
                print(Fore.YELLOW + f"[i]   {field:<16}: {val}")

        print(Fore.CYAN + "============================================================")

        # Geolocation
        if src_ip and src_ip != "UNKNOWN":
            self._display_geo(src_ip)

    # ----------------------------------------------------------
    # Display — Channel Event
    # ----------------------------------------------------------

    def _display_channel_event(self, ami_raw, parsed, event_name):

        src_ip = parsed["source_ip"]

        print(Fore.GREEN + "\n============================================================")
        print(Fore.GREEN + f"AMI CALL EVENT [{event_name}]")
        print(Fore.GREEN + "============================================================")

        print(Fore.CYAN + "\n============================================================")
        print(Fore.CYAN + "CALL ANALYSIS")
        print(Fore.CYAN + "============================================================")
        print(Fore.GREEN + f"[TIME] Timestamp   : {parsed['timestamp']}")
        print(Fore.GREEN + f"[OK]  Event        : {event_name}")
        print(Fore.GREEN + f"[OK]  SIP Method   : {parsed['method']}")

        if parsed.get("caller_id"):
            print(Fore.GREEN + f"[OK]  Caller ID    : {parsed['caller_id']}")
        if src_ip != "UNKNOWN":
            print(Fore.GREEN + f"[OK]  Source IP    : {src_ip}")

        for field in ["Channel", "Context", "Exten", "Priority", "Cause-txt"]:
            val = ami_raw.get(field)
            if val:
                print(Fore.YELLOW + f"[i]   {field:<16}: {val}")

        print(Fore.CYAN + "============================================================")

        if src_ip and src_ip != "UNKNOWN":
            self._display_geo(src_ip)

    # ----------------------------------------------------------
    # Display — Firewall Status (no attack)
    # ----------------------------------------------------------

    def _display_firewall_status(self, parsed_event):

        event_type = parsed_event.get("event", "OTHER")
        status     = STATUS_LABELS.get(event_type, "Allowed")
        action     = FIREWALL_ACTION_LABELS.get(event_type, "Monitoring")

        reason_map = {
            "AUTH_CHALLENGE": "Authentication challenge sent — normal SIP handshake",
            "AUTH_SUCCESS":   "Successful authentication — call allowed",
            "FAILED_AUTH":    "Failed auth tracked — below block threshold",
            "INVITE":         "Call INVITE tracked — below flood threshold",
            "REGISTER":       "REGISTER tracked — below flood threshold",
            "OPTIONS":        "OPTIONS tracked — below flood threshold",
        }

        print(Fore.YELLOW + "\n============================================================")
        print(Fore.YELLOW + "FIREWALL ANALYSIS")
        print(Fore.YELLOW + "============================================================")
        print(Fore.YELLOW + f"Status          : {status}")
        print(Fore.YELLOW + f"Reason          : {reason_map.get(event_type, 'Event tracked and monitored')}")
        print(Fore.YELLOW + f"Event Type      : {event_type}")
        print(Fore.YELLOW + "Threat Level    : None")
        print(Fore.YELLOW + f"Firewall Action : {action}")
        print(Fore.YELLOW + "============================================================")

    # ----------------------------------------------------------
    # Geolocation display
    # ----------------------------------------------------------

    def _display_geo(self, src_ip):

        private = ("127.", "10.", "192.168.", "172.16.", "0.0.0.0")
        if src_ip.startswith(private):
            return

        print(Fore.MAGENTA + "\n============================================================")
        print(Fore.MAGENTA + "IP GEOLOCATION")
        print(Fore.MAGENTA + "============================================================")
        print(Fore.MAGENTA + f"  IP        : {src_ip}")
        geo = lookup_ip(src_ip)
        print(Fore.MAGENTA + format_ip_info(geo))
        print(Fore.MAGENTA + "============================================================")

    # ----------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------

    @staticmethod
    def _extract_ip(remote_address):
        """
        Extract IP from AMI RemoteAddress field.
        Format: IPV4/UDP/185.22.11.5/5060
        """
        if not remote_address:
            return None
        parts = remote_address.split("/")
        if len(parts) >= 3:
            return parts[2]
        return None

    @staticmethod
    def _extract_ip_from_channel(channel):
        """
        Try to extract IP from channel name.
        e.g. PJSIP/185.22.11.5-00000001 → 185.22.11.5
        """
        if not channel:
            return None
        import re
        match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", channel)
        if match:
            return match.group(1)
        return None
