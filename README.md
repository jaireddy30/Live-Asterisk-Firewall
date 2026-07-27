# 🛡️ Live Asterisk Firewall

A lightweight, real-time **Intrusion Prevention System (IPS)** for Asterisk PBX. It tails the live Asterisk log, classifies SIP security events, detects common attack patterns, and automatically blocks malicious IPs with `iptables`.

---

## 📌 Overview

Live Asterisk Firewall watches `/var/log/asterisk/full` as it grows, parses each new line into a structured event, runs it through a threshold-based detector, and hands anything malicious to a decision engine that blocks the source IP and writes an audit trail to CSV.

It's built for small-to-medium VoIP deployments that want basic fail2ban-style protection for Asterisk without standing up a separate service.

> **Educational / authorized-use project.** See [Disclaimer](#-disclaimer).

---

## 🚀 Features

- 📡 Real-time log monitoring via `watchdog` (no polling)
- 🔍 Structured SIP/security event parsing, with geolocation enrichment
- 🚨 Brute-force login detection (`InvalidPassword` / failed auth)
- 📞 REGISTER flood detection
- ☎️ INVITE flood detection
- 🔎 SIP enumeration (OPTIONS scan) detection
- 🕵️ Unknown-endpoint scan detection
- 💰 Toll-fraud detection, tracked **by destination number**, not source IP
- 🌍 IP geolocation (ip-api.com) and phone-prefix → country lookup for toll fraud
- 🔥 Automatic blocking via Linux `iptables`
- 📝 CSV-based alert log and blocked-IP registry
- 💻 Cross-platform dev loop — simulate and test on Windows/Mac, deploy on Ubuntu

---

## 🧩 Project Structure

```
Live-Asterisk-Firewall/
│
├── monitor.py               # Entry point — tails the log, orchestrates the pipeline
├── log_parser.py            # Turns raw log lines into structured events
├── detector.py               # Applies thresholds, decides if an event is an attack
├── firewall.py               # Decision engine: maps severity -> action
├── iptables_controller.py    # Executes / simulates iptables blocking
├── ip_lookup.py               # IP geolocation + phone-prefix country lookup
├── logger.py                  # Writes alerts.csv
├── simulate.py                # Generates fake attack traffic for local testing
│
├── config.py                  # Thresholds, log path, ban settings
├── requirements.txt
├── README.md
│
└── data/                       # Created at runtime
    ├── alerts.csv
    └── blocked_ips.csv
```

---

## 🏗️ Architecture

```
              Attacker
                  │
                  ▼
            Asterisk PBX
                  │
                  ▼
      /var/log/asterisk/full
                  │
                  ▼
             monitor.py  ──▶  ip_lookup.py (geolocation)
                  │
                  ▼
            log_parser.py
                  │
                  ▼
             detector.py
                  │
                  ▼
             firewall.py
                  │
                  ▼
      iptables_controller.py
                  │
                  ▼
               logger.py  ──▶  data/alerts.csv
```

---

## 📋 Detection Rules

| Attack | Trigger | Tracked By | Default Threshold | Action |
|---|---|---|---|---|
| Brute Force | Repeated `InvalidPassword` / failed auth | Source IP | 10 failures | Block |
| REGISTER Flood | Excessive REGISTER requests | Source IP | 20 requests | Block |
| INVITE Flood | Excessive INVITE requests | Source IP | 20 requests | Block |
| SIP Enumeration | Excessive OPTIONS requests | Source IP | 20 requests | Monitor |
| Unknown Endpoint Scan | Requests to non-existent extensions | Source IP | 1 occurrence | Monitor |
| ACL Violation | Request blocked by Asterisk ACL | Source IP | 1 occurrence | Monitor |
| Toll Fraud | Repeated outbound calls to the same destination number | **Destination number**, not IP | 2 calls | Block (logged only — see [Limitations](#-known-limitations--things-to-check-before-going-live)) |

A successful authentication (`AUTH_SUCCESS`) resets that IP's failed-auth counter, so a user who mistypes a password once or twice won't get blocked right after logging in correctly.

---

## ⚙️ Requirements

**OS:** Ubuntu 20.04+ recommended for production (real `iptables` blocking). Windows/macOS work for development via `simulate.py` (blocking is simulated, not applied).

**Software:** Python 3.10+, Asterisk, iptables.

**Python packages** — see `requirements.txt`:
```
watchdog==6.0.0
colorama==0.4.6
pandas==3.0.3
requests==2.34.2
```

---

## 📦 Installation

```bash
git clone https://github.com/YOUR_USERNAME/Live-Asterisk-Firewall.git
cd Live-Asterisk-Firewall
pip install -r requirements.txt
```

### Production permissions (required for real blocking)

`iptables_controller.py` runs `sudo iptables -A INPUT -s <ip> -j DROP`. If `monitor.py` isn't run as root, or the user doesn't have passwordless sudo for `iptables`, blocks will fail silently — you'll see `"iptables failed"` in the logs but the IP won't actually be blocked. Either:

```bash
sudo python3 monitor.py
```

or grant your service user passwordless sudo scoped to iptables only:

```bash
echo "asterisk-fw ALL=(ALL) NOPASSWD: /usr/sbin/iptables" | sudo tee /etc/sudoers.d/asterisk-fw
```

---

## 🔧 Configuration

Edit `config.py`:

```python
ASTERISK_LOG = "/var/log/asterisk/full"   # or set ASTERISK_LOG env var

FAILED_AUTH_THRESHOLD = 10
REGISTER_THRESHOLD    = 20
INVITE_THRESHOLD      = 20
OPTIONS_THRESHOLD     = 20
TOLL_FRAUD_THRESHOLD  = 2

BAN_TIME = 600   # currently informational only — see limitations below
```

---

## ▶️ Running

**Live, against real Asterisk logs:**
```bash
sudo python3 monitor.py
```

**Local test with simulated attack traffic (no Asterisk required):**
```bash
python3 simulate.py
```
This writes a batch of realistic brute-force, scan, and toll-fraud log lines to a temp file and runs `monitor.py` against it so you can see the full pipeline fire end-to-end.

---

## 📁 Generated Files

**`data/alerts.csv`**

| timestamp | source_ip | attack | severity | action |
|---|---|---|---|---|
| 2026-07-25 15:38:34 | 185.22.11.5 | BRUTE_FORCE | HIGH | BLOCK |
| 2026-07-25 15:38:35 | 91.55.77.22 | UNKNOWN_ENDPOINT_SCAN | MEDIUM | MONITOR |
| 2026-07-25 15:38:36 | UNKNOWN | TOLL_FRAUD | CRITICAL | BLOCK |

**`data/blocked_ips.csv`**

| ip | status |
|---|---|
| 185.22.11.5 | BLOCKED |

---

## ⚠️ Known Limitations / Things to Check Before Going Live

This has been tested end-to-end against the bundled simulated traffic (`simulate.py`), not against a live production Asterisk box. Before relying on it:

- **Log rotation is not handled.** The log file is opened once and the handle is never refreshed. When `logrotate` rotates `/var/log/asterisk/full`, the monitor keeps watching the old (now-dead) file handle and silently stops seeing new events. Restart the process after rotation, or run it under a supervisor that restarts on a schedule, until this is fixed.
- **No auto-unban.** `BAN_TIME` is defined in `config.py` but isn't used anywhere, and `unblock_ip()` is never called automatically. Blocks are permanent until manually removed.
- **No de-duplication above threshold.** Once a counter crosses its threshold, every further matching event re-fires detection — appending another `iptables` DROP rule for the same IP and another row in `alerts.csv`. Under a sustained attack this can spam both.
- **Toll fraud isn't actually stopped.** Its source IP is `UNKNOWN` (it's your own PBX making the outbound call), so `iptables_controller` deliberately skips blocking it. Detection and CRITICAL logging work, but nothing currently disables the compromised extension or trunk.
- **Synchronous network calls in the hot path.** IP geolocation (ip-api.com) and `iptables` calls run inline in the log-reading loop. Under a real flood, this can cause the reader to fall behind. ip-api.com's free tier is also capped at 45 req/min.
- **Log format assumptions.** Parsing relies on Asterisk's standard `SecurityEvent="..."` fields (PJSIP-style). Older `chan_sip` setups or heavily customized logging may need regex adjustments in `log_parser.py`.

---

## 🗺️ Future Improvements

- Log rotation / re-open on truncate detection
- Time-windowed thresholds instead of monotonic counters
- Automatic unblock after `BAN_TIME`
- Cooldown/de-dup on repeated detections for the same IP or destination
- Async/queued IP lookups and iptables calls
- Extension/trunk-level action for toll fraud (not just IP blocking)
- Email/Slack notifications
- Web dashboard
- Docker deployment

---

## 📄 License

MIT License.

---

## ✍️ Author

**B. Jai Bhavin Reddy** — B.Tech Computer Science Engineering, Cybersecurity Enthusiast
GitHub: https://github.com/YOUR_USERNAME

---

## ⚖️ Disclaimer

This project is intended for educational purposes and authorized security testing only. Do not use it against systems without proper permission. Unauthorized use may violate applicable laws and organizational policies.
