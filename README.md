# 🛡️ Live Asterisk Firewall

A **real-time Intrusion Prevention System (IPS)** for Asterisk PBX that monitors live logs, detects common SIP attacks, and automatically blocks malicious IP addresses using Linux `iptables`.

---

## 📌 Overview

Live Asterisk Firewall continuously monitors the Asterisk log file (`/var/log/asterisk/full`), parses SIP events, detects malicious activities, and automatically takes action based on predefined security rules.

The project is designed to provide lightweight, real-time protection for VoIP environments without requiring complex infrastructure.

---

## 🚀 Features

- 📡 Real-time Asterisk log monitoring
- 🔍 SIP log parsing
- 🚨 Brute Force detection
- 📞 REGISTER Flood detection
- ☎️ INVITE Flood detection
- 🔎 SIP Enumeration (OPTIONS Scan) detection
- 💰 Toll Fraud detection
- 🔥 Automatic IP blocking using Linux iptables
- 📝 CSV-based alert logging
- 💻 Cross-platform development (Windows simulation, Ubuntu deployment)
- 🧩 Modular architecture

---

# Project Structure

```
Live-Asterisk-Firewall/
│
├── monitor.py
├── parser.py
├── detector.py
├── firewall.py
├── iptables_controller.py
├── logger.py
│
├── config.py
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
│
├── data/
│   ├── alerts.csv
│   └── blocked_ips.csv
│
├── logs/
│
└── assets/
```

---

# Architecture

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
             monitor.py
                  │
                  ▼
             parser.py
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
             logger.py
```

---

# Detection Rules

| Attack | Description | Action |
|---------|-------------|--------|
| Brute Force | Multiple failed SIP authentication attempts | Block IP |
| REGISTER Flood | Excessive REGISTER requests | Block IP |
| INVITE Flood | Excessive INVITE requests | Block IP |
| SIP Enumeration | Excessive OPTIONS requests | Monitor |
| Unknown Endpoint Scan | Requests to invalid SIP endpoints | Monitor |
| Toll Fraud | Suspicious outbound call attempts | Block IP |

---

# Technologies Used

- Python 3
- Watchdog
- Colorama
- Pandas
- Linux iptables
- Asterisk PBX

---

# Requirements

## Operating System

- Ubuntu 20.04 or later (recommended)
- Windows (for development/testing)

## Software

- Python 3.10+
- Asterisk
- iptables

---

# Installation

Clone the repository.

```bash
git clone https://github.com/YOUR_USERNAME/Live-Asterisk-Firewall.git

cd Live-Asterisk-Firewall
```

Install the required Python packages.

```bash
pip install -r requirements.txt
```

---

# Configuration

Open `config.py` and configure the Asterisk log path.

```python
ASTERISK_LOG = "/var/log/asterisk/full"
```

Modify the detection thresholds if required.

```python
FAILED_AUTH_THRESHOLD = 10

REGISTER_THRESHOLD = 20

INVITE_THRESHOLD = 20

OPTIONS_THRESHOLD = 20
```

---

# Running the Firewall

Start the firewall using:

```bash
python3 monitor.py
```

The monitor will continuously watch the Asterisk log file and process every new log entry.

---

# Example Workflow

```
Attacker
    │
    ▼
Asterisk PBX
    │
    ▼
Live Log Entry
    │
    ▼
Log Monitor
    │
    ▼
Parser
    │
    ▼
Detector
    │
    ▼
Firewall Decision Engine
    │
    ▼
iptables Block
    │
    ▼
Alert Logger
```

---

# Generated Files

## alerts.csv

Stores all detected attacks.

Example:

| Timestamp | Source IP | Attack | Severity | Action |
|-----------|-----------|--------|----------|--------|
|2026-07-22 15:45:20|192.168.1.10|BRUTE_FORCE|HIGH|BLOCK|

---

## blocked_ips.csv

Stores all blocked IP addresses.

Example:

| IP | Status |
|----|--------|
|192.168.1.10|BLOCKED|

---

# Screenshots

Add screenshots after testing.

Example:

```
assets/

live_monitor.png

attack_detected.png

iptables_rules.png

alerts_csv.png
```

---

# Future Improvements

- Time-based attack detection
- Automatic IP unblocking after timeout
- Email notifications
- Web dashboard
- Database support
- Docker deployment
- Machine Learning-based anomaly detection
- Fail2Ban integration
- REST API

---

# License

This project is licensed under the MIT License.

---

# Author

**B. Jai Bhavin Reddy**

B.Tech Computer Science Engineering

Cybersecurity Enthusiast

GitHub: https://github.com/YOUR_USERNAME

---

# Disclaimer

This project is intended for educational purposes and authorized security testing only.

Do not use it against systems without proper permission.

Unauthorized use may violate applicable laws and organizational policies.
