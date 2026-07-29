"""
====================================================
LIVE ASTERISK FIREWALL

ami_monitor.py

Purpose:
    Direct connection to Asterisk via AMI (port 5038).
    Receives real-time security and call events
    without needing log files or PJSIP logger.

AMI Setup in /etc/asterisk/manager.d/pbxshield.conf:
    [pbxshield]
    secret = internalp@ss567
    read   = security,call,log,verbose
    write  =

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
    "ChallengeSent":             "AUTH_CHALLENGE",
    "SuccessfulAuth":            "AUTH_SUCCESS",
    "InvalidPassword":           "FAILED_AUTH",
    "InvalidAccountID":          "UNKNOWN_ENDPOINT",
    "ChallengeResponseFailed":   "FAILED_AUTH",
    "MemoryLimitReached":        "SYSTEM_LOG",
    "LoadAverageLimit":          "SYSTEM_LOG",
    "RequestNotSupported":       "SYSTEM_LOG",
    "SessionLimit":              "SYSTEM_LOG",
    "ACL":                       "ACL_BLOCKED",
    "RequestNotAllowed":         "ACL_BLOCKED",
    "AuthMethodNotAllowed":      "FAILED_AUTH",
    "TollFraud":                 "TOLL_FRAUD",
}

# ----------------------------------------------------------
# AMI Channel Event → SIP Method mapping
# ----------------------------------------------------------

AMI_CHANNEL_METHOD_MAP = {
    "Newchannel": "INVITE",
    "Hangup":     "BYE",
    "Registry":   "REGISTER",
}

# ----------------------------------------------------------
# Status / Action labels for non-attack events
# ----------------------------------------------------------

STATUS_LABELS = {
    "AUTH_CHALLENGE":   "Informational",
    "AUTH_SUCCESS":     "Allowed",
    "FAILED_AUTH":      "Warning",
    "UNKNOWN_ENDPOINT": "Warning",
    "ACL_BLOCKED":      "Warning",
    "TOLL_FRAUD":       "Critical",
    "REGISTER":         "Allowed",
    "INVITE":           "Allowed",
    "OPTIONS":          "Allowed",
    "BYE":              "Allowed",
    "ACK":              "Allowed",
    "OTHER":            "Allowed",
}

ACTION_LABELS = {
    "AUTH_CHALLENGE":   "Monitoring",
    "AUTH_SUCCESS":     "Monitoring",
    "FAILED_AUTH":      "Tracking",
    "UNKNOWN_ENDPOINT": "Tracking",
    "ACL_BLOCKED":      "Tracking",
    "TOLL_FRAUD":       "Tracking",
    "REGISTER":         "Monitoring",
    "INVITE":           "Monitoring",
    "OPTIONS":          "Monitoring",
    "BYE":              "Monitoring",
    "ACK":              "Monitoring",
    "OTHER":            "Monitoring",
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
    "BYE":              "Call ended normally",
    "OTHER":            "Event tracked and monitored",
}

# Private IP prefixes — skip geolocation for these
PRIVATE_PREFIXES = (
    "127.", "10.", "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "0.0.0.0",
)


def is_private(ip):
    return not ip or ip.startswith(PRIVATE_PREFIXES)


# ===========================================================
# AMI CLIENT — raw TCP socket connection to Asterisk
# ===========================================================

class AMIClient:

    def __init__(self, host, port, username, secret):
        self.host     = host
        self.port     = port
        self.username = username
        self.secret   = secret
        self.sock     = None
        self.buffer   = ""       # persistent recv buffer, shared between
                                 # listen() and send_action_get_response()
        self._action_id_counter = 0

    def _next_action_id(self):
        self._action_id_counter += 1
        return f"pbxshield-{self._action_id_counter}"

    def connect(self):
        """Connect and log in to Asterisk AMI."""

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect((self.host, self.port))

        # ── Read banner as ONE line ──
        # Asterisk banner = "Asterisk Call Manager/9.0.0\r\n"
        # It has NO double newline after it — read until first \n only
        banner = b""
        while b"\n" not in banner:
            chunk = self.sock.recv(256)
            if not chunk:
                break
            banner += chunk

        print(Fore.CYAN + f"[AMI] Connected  : {banner.decode(errors='replace').strip()}")

        # ── Send login action ──
        self._send({
            "Action":   "Login",
            "Username": self.username,
            "Secret":   self.secret,
        })

        # ── Read login response (blank line terminated) ──
        response = b""
        self.sock.settimeout(5)
        try:
            while b"\r\n\r\n" not in response and b"\n\n" not in response:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        except socket.timeout:
            pass

        self.sock.settimeout(None)

        response_str = response.decode("utf-8", errors="replace")

        if "Success" in response_str:
            print(Fore.GREEN + "[AMI] Login      : Success")
            return True
        else:
            print(Fore.RED + f"[AMI] Login failed: {response_str[:300]}")
            return False

    def _send(self, action_dict):
        """Send an AMI action."""
        msg = ""
        for key, val in action_dict.items():
            msg += f"{key}: {val}\r\n"
        msg += "\r\n"
        self.sock.sendall(msg.encode("utf-8"))

    def _read_message(self):
        """Read one complete AMI message (blank line terminated)."""
        data = b""
        while b"\r\n\r\n" not in data and b"\n\n" not in data:
            try:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                data += chunk
            except Exception:
                break
        return data.decode("utf-8", errors="replace")

    def _pop_message(self):
        """Pop one complete \\r\\n\\r\\n-terminated message off self.buffer, if any."""
        if "\r\n\r\n" in self.buffer:
            raw, self.buffer = self.buffer.split("\r\n\r\n", 1)
            return raw
        return None

    def _read_more(self):
        """Blocking read of whatever is available into self.buffer."""
        chunk = self.sock.recv(4096).decode("utf-8", errors="replace")
        if not chunk:
            raise ConnectionError("AMI connection closed by Asterisk.")
        self.buffer += chunk

    def listen(self, callback):
        """
        Continuously read AMI events and call
        callback(event_dict) for each complete event.
        """
        while True:
            try:
                raw = self._pop_message()
                if raw is None:
                    self._read_more()
                    continue

                event = self._parse(raw)
                if event:
                    callback(event)

            except KeyboardInterrupt:
                break

            except Exception as e:
                print(Fore.RED + f"[AMI] Error: {e}")
                break

    def send_action_get_response(self, action_dict, callback=None, timeout=3):
        """
        Send an AMI action tagged with a unique ActionID and block until
        the matching response arrives (or timeout). Any other complete
        messages that show up on the wire in the meantime (i.e. normal
        async events interleaved with our response) are handed off to
        `callback` so nothing gets silently dropped.
        """
        action_id = self._next_action_id()
        action_dict = dict(action_dict)
        action_dict["ActionID"] = action_id
        self._send(action_dict)

        self.sock.settimeout(timeout)
        deadline = time.time() + timeout

        try:
            while time.time() < deadline:
                raw = self._pop_message()
                if raw is None:
                    try:
                        self._read_more()
                    except socket.timeout:
                        break
                    continue

                parsed = self._parse(raw)
                if not parsed:
                    continue

                if parsed.get("ActionID") == action_id:
                    return parsed

                # Not our response — it's a real-time event that arrived
                # while we were waiting. Forward it so it still gets
                # processed/displayed instead of being swallowed.
                if callback:
                    callback(parsed)

        except socket.timeout:
            pass
        finally:
            self.sock.settimeout(None)

        return None

    @staticmethod
    def _parse(raw):
        """Parse raw AMI event string into a dict."""
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
# AMI MONITOR — processes events → detector → firewall
# ===========================================================

class AMIMonitor:

    def __init__(self, host, port, username, secret):
        self.client   = AMIClient(host, port, username, secret)
        self.detector = Detector()
        self.firewall = Firewall()
        self._ip_cache = {}   # Uniqueid -> source IP, so Hangup can reuse
                               # the IP captured at Newchannel time (the
                               # channel/peer may already be gone by Hangup)

    def start(self):
        """Connect to AMI and start listening for events."""

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
    # Route each AMI event to the correct handler
    # ----------------------------------------------------------

    def handle_event(self, ami_event):
        """Process one AMI event dict."""

        event_name = ami_event.get("Event", "")
        if not event_name:
            return

        # Security events
        if event_name == "SecurityEvent":
            self._handle_security_event(ami_event)

        # Call channel events
        elif event_name in AMI_CHANNEL_METHOD_MAP:
            self._handle_channel_event(ami_event, event_name)

    # ----------------------------------------------------------
    # Security Event Handler
    # ----------------------------------------------------------

    def _handle_security_event(self, ami_event):

        sub_event  = ami_event.get("SubEvent", "")
        event_type = AMI_SECURITY_EVENT_MAP.get(sub_event, "OTHER")

        # Extract IP from RemoteAddress: IPV4/UDP/185.22.11.5/5060
        remote_addr = ami_event.get("RemoteAddress", "")
        src_ip      = self._extract_ip(remote_addr) or "UNKNOWN"

        account_id  = ami_event.get("AccountID", "")
        service     = ami_event.get("Service", "")

        parsed_event = {
            "timestamp":   datetime.now().isoformat(),
            "source_ip":   src_ip,
            "method":      "UNKNOWN",
            "event":       event_type,
            "module":      "AMI",
            "account_id":  account_id,
            "service":     service,
            "destination": None,
        }

        self._display_security_event(ami_event, parsed_event, sub_event)

        attack = self.detector.detect(parsed_event)
        if attack:
            self.firewall.process_attack(attack)
        else:
            self._display_firewall_status(parsed_event)

    # ----------------------------------------------------------
    # Channel Event Handler (calls / registrations)
    # ----------------------------------------------------------

    def _handle_channel_event(self, ami_event, event_name):

        method    = AMI_CHANNEL_METHOD_MAP.get(event_name, "UNKNOWN")
        caller_id = ami_event.get("CallerIDNum", "")
        channel   = ami_event.get("Channel", "")
        exten     = ami_event.get("Exten", "")
        uniqueid  = ami_event.get("Uniqueid", "")

        src_ip = self._get_remote_ip(channel, uniqueid)

        parsed_event = {
            "timestamp":   datetime.now().isoformat(),
            "source_ip":   src_ip,
            "method":      method,
            "event":       method,
            "module":      "AMI",
            "caller_id":   caller_id,
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

    def _display_security_event(self, ami_raw, parsed, sub_event):

        src_ip = parsed["source_ip"]

        print(Fore.GREEN + "\n============================================================")
        print(Fore.GREEN + "AMI SECURITY EVENT")
        print(Fore.GREEN + "============================================================")
        print(Fore.GREEN + f"  SubEvent : {sub_event}")

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

        for field in ["Severity", "LocalAddress", "RemoteAddress", "Challenge", "UsingPassword"]:
            val = ami_raw.get(field)
            if val:
                print(Fore.YELLOW + f"[i]   {field:<18}: {val}")

        print(Fore.CYAN + "============================================================")

        if not is_private(src_ip) and src_ip != "UNKNOWN":
            self._display_geo(src_ip)

    # ----------------------------------------------------------
    # Display — Channel Event
    # ----------------------------------------------------------

    def _display_channel_event(self, ami_raw, parsed, event_name):

        src_ip = parsed["source_ip"]

        print(Fore.GREEN + "\n============================================================")
        print(Fore.GREEN + f"AMI CALL EVENT  [{event_name}]")
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
                print(Fore.YELLOW + f"[i]   {field:<18}: {val}")

        print(Fore.CYAN + "============================================================")

        if not is_private(src_ip) and src_ip != "UNKNOWN":
            self._display_geo(src_ip)

    # ----------------------------------------------------------
    # Firewall Status Display (no attack detected)
    # ----------------------------------------------------------

    def _display_firewall_status(self, parsed_event):

        event_type = parsed_event.get("event", "OTHER")

        status = STATUS_LABELS.get(event_type, "Allowed")
        action = ACTION_LABELS.get(event_type, "Monitoring")
        reason = REASON_LABELS.get(event_type, "Event tracked and monitored")

        print(Fore.YELLOW + "\n============================================================")
        print(Fore.YELLOW + "FIREWALL ANALYSIS")
        print(Fore.YELLOW + "============================================================")
        print(Fore.YELLOW + f"Status          : {status}")
        print(Fore.YELLOW + f"Reason          : {reason}")
        print(Fore.YELLOW + f"Event Type      : {event_type}")
        print(Fore.YELLOW + "Threat Level    : None")
        print(Fore.YELLOW + f"Firewall Action : {action}")
        print(Fore.YELLOW + "============================================================")

    # ----------------------------------------------------------
    # Geolocation display
    # ----------------------------------------------------------

    def _display_geo(self, src_ip):

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
        e.g. PJSIP/185.22.11.5-00000001
        NOTE: this only ever matches on legacy chan_sip-style channel
        names. Modern PJSIP channels are named after the endpoint
        (e.g. PJSIP/myendpoint-00000001) and never contain an IP, which
        is why this alone was returning UNKNOWN for Newchannel/Hangup.
        """
        if not channel:
            return None
        import re
        match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", channel)
        if match:
            return match.group(1)
        return None

    def _get_remote_ip(self, channel, uniqueid):
        """
        Resolve the real source IP for a call channel.

        Newchannel/Hangup AMI events don't carry the remote IP directly —
        PJSIP channel names only contain the endpoint name, not an
        address. So we:
          1. Check the cache (keyed by Uniqueid) first — cheap, and the
             only option left by the time Hangup fires, since the
             channel/peer info may no longer be queryable.
          2. Fall back to the legacy regex, in case chan_sip is in use.
          3. Otherwise, actively ask Asterisk via an AMI GetVar action
             for CHANNEL(pjsip,remote_address), which returns "ip:port".
        """

        if uniqueid and uniqueid in self._ip_cache:
            return self._ip_cache[uniqueid]

        ip = self._extract_ip_from_channel(channel)

        if not ip and channel:
            try:
                resp = self.client.send_action_get_response(
                    {
                        "Action":   "Getvar",
                        "Channel":  channel,
                        "Variable": "CHANNEL(pjsip,remote_address)",
                    },
                    callback=self.handle_event,
                )
                if resp:
                    value = resp.get("Value", "")
                    if value and value != "0":
                        ip = value.split(":")[0]
            except Exception as e:
                print(Fore.RED + f"[AMI] GetVar lookup failed: {e}")

        ip = ip or "UNKNOWN"

        if uniqueid:
            self._ip_cache[uniqueid] = ip

        return ip
