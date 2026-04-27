import os
import time
import argparse
import sqlite3
from datetime import datetime
from modules.threat_engine import Watchdog 

# إعداد المسارات
DB_PATH = "database/siem.db"
LOG_FILE = "logs/auth.log"

# ذاكرة مؤقتة لمنع التكرار (Deduplication Cache)
# { "Brute Force": timestamp, "SQL Injection": timestamp }
last_alerts_cache = {}
COOLDOWN_SECONDS = 20  # المدة اللي كيتسنى فيها قبل ما يعاود يسجل نفس الهجمة

# --- وظائف قاعدة البيانات ---

def insert_log(timestamp, event, attack_type):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO logs (timestamp, event, attack_type) VALUES (?, ?, ?)",
                       (timestamp, event, attack_type))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[-] Database Log Error: {e}")

def insert_alert(message, severity, attack_type):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO alerts (message, severity, attack_type) VALUES (?, ?, ?)",
                       (message, severity, attack_type))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[-] Database Alert Error: {e}")

# --- معالجة الأسطر بذكاء ---

def process_line(line, wdog):
    if not line.strip(): return

    # تحليل السطر
    alerts = wdog.analyze(line)
    
    now = datetime.now()
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
    time_only = now.strftime("%H:%M:%S")

    if alerts:
        for a in alerts:
            # --- منع التكرار المكثف (Deduplication Logic) ---
            alert_key = f"{a.attack_type}_{a.source_ip}"
            last_time = last_alerts_cache.get(alert_key)

            # إذا كانت الهجمة جديدة أو فات عليها الـ Cooldown
            if last_time is None or (now - last_time).total_seconds() > COOLDOWN_SECONDS:
                last_alerts_cache[alert_key] = now
                
                print(f"\033[91m[!] ALERT: {a.attack_type} ({a.severity}) - {a.description}\033[0m")
                
                display_msg = f"{a.description} at {time_only}"
                insert_alert(display_msg, a.severity, a.attack_type)
                insert_log(timestamp, a.description, a.attack_type)
            else:
                # هجمة مكررة في وقت قصير - نسجلها فـ الـ Logs فقط بلا ما نعمرو الـ Alerts
                insert_log(timestamp, f"[DUPLICATE BLOCKED] {a.description}", a.attack_type)
    else:
        # نشاط عادي
        insert_log(timestamp, line.strip(), "Normal")

# --- المراقبة الحقيقية مع دعم الـ Reset ---

def monitor_file_realtime(file_path):
    print(f"[*] Starting Nexus Engine - Real-time Mode")
    print(f"[*] Monitoring: {os.path.abspath(file_path)}")
    
    wdog = Watchdog()
    
    if not os.path.exists(file_path):
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        open(file_path, 'a').close()

    with open(file_path, "r") as f:
        f.seek(0, os.SEEK_END)
        last_pos = f.tell()
        
        try:
            while True:
                # دعم الـ Reset (إذا تم مسح الملف)
                current_size = os.path.getsize(file_path)
                if current_size < last_pos:
                    print("[!] Log Reset detected. Rewinding...")
                    f.seek(0)
                
                line = f.readline()
                if not line:
                    last_pos = f.tell()
                    time.sleep(0.5)
                    continue
                
                process_line(line, wdog)
                last_pos = f.tell()
        except KeyboardInterrupt:
            print("\n[*] Monitoring stopped.")
            print(wdog.summary())

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Nexus SIEM Core")
    parser.add_argument("--log", help="Log file path", default=LOG_FILE)
    args = parser.parse_args()

    print("=============================================")
    print("      CyberWolf - CORE MONITORING ENGINE    ")
    print("=============================================")
    
    monitor_file_realtime(args.log)