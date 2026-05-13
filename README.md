# 🐺 CyberWolf SIEM Platform

![CyberWolf SIEM](https://img.shields.io/badge/Security-SIEM-00d4ff?style=for-the-badge&logo=shield)
![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-Web_App-black?style=for-the-badge&logo=flask)

**CyberWolf SIEM** is a lightweight, multi-tenant Security Information and Event Management (SIEM) platform designed for real-time threat detection, log monitoring, and incident response. 

Built with Python, it features a powerful terminal-based monitoring engine paired with a sleek, modern, web-based dashboard for Security Operations Center (SOC) visualization. It maps threats directly to the **MITRE ATT&CK** framework.

## 🚀 Key Features

- **Multi-Tenant Architecture**: Enforced user authentication with strict per-user database isolation (`siem.db`).
- **Real-Time Threat Engine (`Watchdog`)**: Detects Brute Force, SQL Injection, XSS, Path Traversal, Port Scanning, DDoS, and more.
- **Live Network Agent**: HIDS/NIDS capabilities to monitor file integrity and sniff malicious packets in real-time.
- **Dynamic Routing & Notifications**: Alerts are dispatched via SMTP (Email) dynamically to the platform administrator and the targeted user.
- **Modern Web Dashboard**: Glassmorphism UI, real-time KPI updates, interactive charts (Chart.js), and detailed alert forensics.
- **Live Attack Simulator**: Included scripts to perform real HTTP and TCP network attacks against your own local environment to test the engine's capabilities.

## 📂 Project Structure

```text
projet_mini_SIEM/
├── app.py                     # Flask web dashboard (GUI & API)
├── main.py                    # Terminal-based SIEM engine and log monitor
├── init_db.py                 # Initializes SQLite databases and schemas
├── start_siem_win.py          # Master launcher script for Windows
├── real_attack_simulator.py   # Live Network/HTTP attack simulator (XSS, SQLi, Ports)
├── attack_simulator.py        # Text-based mock log simulator
├── headless_monitor.py        # Headless monitor script for testing
├── config.example.json        # Template configuration for SMTP/Settings
├── requirements.txt           # Python dependencies
├── .gitignore                 # Secure Git ignore rules
├── database/                  # SQLite databases (Auto-generated)
│   ├── users.db               # Authentication database
│   └── user_{id}/             # Per-user isolated SIEM databases
├── logs/                      # Monitored log files (Auto-generated)
│   └── auth.log               # Main system log file
├── modules/
│   ├── threat_engine.py       # Core Watchdog engine with Regex detection rules
│   ├── log_collector.py       # Collects logs and records port scans
│   ├── notifier.py            # Email & Telegram dynamic notification system
│   ├── database.py            # Database insertion and connection utilities
│   └── RealTime_System_Monitor.py # HIDS/NIDS Agent (Scapy, Watchdog)
├── static/
│   ├── dashboard.css          # Dark-mode Dashboard styling
│   └── dashboard.js           # Dashboard logic (Charts, API fetching, Filtering)
└── templates/
    ├── dashboard.html         # Main dashboard layout
    └── login.html             # Secure Login/Setup portal
```

## ⚙️ Installation

1. **Clone the repository**
2. **Create a Virtual Environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate      # On Linux/Mac
   .\venv\Scripts\activate       # On Windows
   ```
3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
4. **Configuration**:
   Copy `config.example.json` to `config.json` and fill in your SMTP App Passwords if you want to enable email notifications.

## 🛡️ Usage

To see the SIEM in action, you need to start the components in parallel:

**1. Start the Web Dashboard**
```bash
python app.py
```
*Navigate to `http://127.0.0.1:5000` to create your Admin account and view the dashboard.*

**2. Start the SIEM Engine (The Brain)**
Open a new terminal window:
```bash
python main.py
```
*Log in with your credentials, then press **`M`** to start the Real-Time Monitor.*

**3. Launch the Live Attack Simulator**
Open a third terminal window:
```bash
python real_attack_simulator.py
```
*This will fire real XSS, SQLi, and Path Traversal payloads at your Flask app, which the interceptor will log, the Engine will analyze, and the Dashboard will visualize in real-time.*

## ⚠️ Disclaimer
**Educational Purposes Only.** The `real_attack_simulator.py` script generates live malicious network traffic. Do not run it against networks or systems you do not own or have explicit permission to test. Running this locally may trigger your antivirus software (e.g., Windows Defender).
