# 🚨 Mini SIEM - Python Open Source Project

## 📌 Overview

This project is a **Mini SIEM (Security Information and Event Management)** system developed in Python.

It simulates real-world cybersecurity monitoring by:
- Collecting logs
- Parsing events
- Detecting security threats
- Storing data in a database
- Visualizing results in a web dashboard

---

## 🎯 Objectives

- Understand how SIEM systems work
- Detect basic cyber attacks (brute force, access abuse, suspicious activity)
- Build a real-time monitoring dashboard
- Learn log analysis and security event processing

---

## 🧠 Features

### 📥 Log Management
- Reads system logs from file (`auth.log`)
- Supports simulated log generation

### 🔍 Detection Engine
- Brute force detection
- Access denied abuse detection
- Suspicious user activity detection
- Time-based attack detection

### 🗄️ Database
- SQLite storage for logs and alerts
- Historical analysis support

### 🌐 Web Dashboard (Flask)
- Real-time monitoring interface
- Security statistics
- Alerts display
- Top attackers tracking
- Event distribution charts

### 📊 Visualization
- Bar charts (event distribution)
- Line charts (alert trends)
- Cybersecurity-themed UI

### 🧪 Attack Simulation
- Automatic log generator
- Simulates real cyber attacks


---

## 🏗️ Project Architecture

mini_siem/
│
├── logs/ # Log files
├── database/ # SQLite database
├── modules/ # Core SIEM logic
│ ├── log_collector.py
│ ├── parser.py
│ ├── detector.py
│ └── database.py
│
├── templates/ # Flask HTML dashboard
│ └── dashboard.html
|
│
├── app.py # Flask web server
├── main.py # SIEM processing engine
├── attack_simulator.py # Log attack generator
├── config.json # Configuration file
└── requirements.txt # Dependencies


---

## ⚙️ Installation


### 1. Clone the project
```bash
git clone https://github.com/abdelhay-adloun/mini-siem.git
cd mini-siem
```

### 2. Install dependencies 
```bash
pip install -r requirements.txt
```

### 3.How to Run

## 1. Start attack simulation (optional)
```bash
python attack_simulator.py
```

## 2. Run SIEM engine
```bash
python main.py
```

## 3. Start dashboard
```bash
python app.py
```

## Then open in browser:

http://127.0.0.1:5000



