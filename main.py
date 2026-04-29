import os
import time
import argparse
import sqlite3
from datetime import datetime
from modules.threat_engine import Watchdog 
from modules.notifier import add_to_batch

# Configuration des chemins
DB_PATH = "database/siem.db"
LOG_FILE = "logs/auth.log"

# Cache de déduplication pour éviter les alertes répétitives
# { "Brute Force": timestamp, "SQL Injection": timestamp }
last_alerts_cache = {}
COOLDOWN_SECONDS = 20  # Délai d'attente avant d'autoriser la même alerte

# --- Fonctions de base de données ---

def insert_log(timestamp, event, attack_type):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("PRAGMA journal_mode=WAL;")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO logs (timestamp, event, attack_type) VALUES (?, ?, ?)",
                       (timestamp, event, attack_type))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[-] Erreur Log DB : {e}")

def insert_alert(message, severity, attack_type):
    try:
        # Ajout au batch de notification
        add_to_batch(attack_type, severity, message)
        
        conn = sqlite3.connect(DB_PATH)
        conn.execute("PRAGMA journal_mode=WAL;")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO alerts (message, severity, attack_type) VALUES (?, ?, ?)",
                       (message, severity, attack_type))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[-] Erreur Alerte DB : {e}")

# --- Traitement intelligent des lignes ---

def process_line(line, wdog):
    if not line.strip(): return

    # Analyse de la ligne par le moteur de menaces
    alerts = wdog.analyze(line)
    
    now = datetime.now()
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
    time_only = now.strftime("%H:%M:%S")

    if alerts:
        for a in alerts:
            add_to_batch(a.attack_type, a.severity, a.description)
            # --- Logique de déduplication ---
            alert_key = f"{a.attack_type}_{a.source_ip}"
            last_time = last_alerts_cache.get(alert_key)

            # Si l'attaque est nouvelle ou si le cooldown est dépassé
            if last_time is None or (now - last_time).total_seconds() > COOLDOWN_SECONDS:
                last_alerts_cache[alert_key] = now
                
                print(f"\033[91m[!] ALERTE : {a.attack_type} ({a.severity}) - {a.description}\033[0m")
                
                display_msg = f"{a.description} à {time_only}"
                insert_alert(display_msg, a.severity, a.attack_type)
                insert_log(timestamp, a.description, a.attack_type)
            else:
                # Attaque dupliquée - enregistrée uniquement dans les logs système
                insert_log(timestamp, f"[DUPLICATE BLOCKED] {a.description}", a.attack_type)
    else:
        # Activité normale
        insert_log(timestamp, line.strip(), "Normal")

# --- Surveillance en temps réel ---

def monitor_file_realtime(file_path):
    print(f"[*] Démarrage du moteur CyberWolf - Mode Temps Réel")
    print(f"[*] Surveillance de : {os.path.abspath(file_path)}")
    
    wdog = Watchdog()
    
    if not os.path.exists(file_path):
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        open(file_path, 'a').close()

    with open(file_path, "r") as f:
        f.seek(0, os.SEEK_END)
        last_pos = f.tell()
        
        try:
            while True:
                # Support du Reset (si le fichier est tronqué)
                current_size = os.path.getsize(file_path)
                if current_size < last_pos:
                    print("[!] Reset du log détecté. Reprise au début...")
                    f.seek(0)
                
                line = f.readline()
                if not line:
                    last_pos = f.tell()
                    time.sleep(0.5)
                    continue
                
                process_line(line, wdog)
                last_pos = f.tell()
        except KeyboardInterrupt:
            print("\n[*] Surveillance arrêtée.")
            print(wdog.summary())

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberWolf SIEM Core")
    parser.add_argument("--log", help="Chemin du fichier log", default=LOG_FILE)
    args = parser.parse_args()

    print("=============================================")
    print("      CyberWolf - MOTEUR DE SURVEILLANCE     ")
    print("=============================================")
    
    monitor_file_realtime(args.log)