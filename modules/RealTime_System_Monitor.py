import sqlite3
import time
import os
import threading
import socket
import re
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from threat_engine import Watchdog

# --- SAFETY IMPORTS ---
try:
    import win32evtlog
    WINDOWS_EVENTS_READY = True
except ImportError:
    WINDOWS_EVENTS_READY = False

try:
    from scapy.all import sniff, IP, Raw
    NETWORK_SNIFF_READY = True
except ImportError:
    NETWORK_SNIFF_READY = False

# --- CONFIGURATION ---
DB_PATH = "database/siem.db"
WATCH_PATH = os.getcwd()
wdog = Watchdog()

# --- DATABASE LOGGER (Optimisé) ---
def log_real_event(msg, severity, attack_type, source_ip="127.0.0.1"):
    """Enregistre les événements réels du PC dans la DB."""
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10) # Timeout pour éviter les verrous
        cursor = conn.cursor()
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        
        # Table LOGS
        cursor.execute("INSERT INTO logs (timestamp, event, attack_type) VALUES (?, ?, ?)", 
                       (timestamp, f"[REAL-PC] {msg}", attack_type))
        
        # Table ALERTS (Mise à jour avec attack_type pour ton Dashboard)
        cursor.execute("INSERT INTO alerts (message, severity, attack_type) VALUES (?, ?, ?)", 
                       (f"PC-THREAT: {msg}", severity, attack_type))

        conn.execute("PRAGMA journal_mode=WAL")
        
        conn.commit()
        conn.close()
        print(f"\033[91m[!] ALERT DETECTED: [{attack_type}] {msg}\033[0m")
    except Exception as e:
        print(f"[-] Database Error: {e}")

# --- 1. WINDOWS SECURITY LOGS ---
def monitor_windows_events():
    if not WINDOWS_EVENTS_READY: 
        print("[!] pywin32 non installé. Monitoring Windows Logs désactivé.")
        return
        
    print("[*] Windows Security Event Monitoring: START")
    try:
        hand = win32evtlog.OpenEventLog(None, "Security")
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        
        while True:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            for event in events:
                eid = event.EventID
                # Nettoyage des données de l'événement
                data_str = " ".join(str(i) for i in event.StringInserts) if event.StringInserts else ""
                
                # Analyse intelligente via ton Watchdog
                wd_alerts = wdog.analyze(data_str)
                if wd_alerts:
                    for a in wd_alerts:
                        log_real_event(a.description, a.severity, a.attack_type)
                
                # Détection par Event ID classiques
                if eid == 4625: # Échec de connexion
                    log_real_event("Windows Login Failure Detected", "High", "Brute Force")
                elif eid == 4720: # Création d'utilisateur
                    log_real_event("New User Account Created", "Critical", "Privilege Escalation")
                    
            time.sleep(1) # Un peu plus rapide que 2s pour ne rien rater
    except Exception as e:
        print(f"[-] Windows Event Error: {e}")

# --- 2. FILE INTEGRITY MONITOR (FIM) ---
class FIMHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            self.check_file(event.src_path, "Created")

    def on_modified(self, event):
        if not event.is_directory:
            self.check_file(event.src_path, "Modified")

    def check_file(self, path, action):
        filename = os.path.basename(path)
        # On ignore les fichiers temporaires et la DB elle-même
        if filename.endswith(('.db', '.tmp', '.log')): return
        
        # Le Watchdog vérifie si l'extension ou le nom est suspect (Ransomware)
        wd_alerts = wdog.analyze(filename)
        if wd_alerts:
            for a in wd_alerts:
                log_real_event(f"File {action}: {filename} ({a.description})", a.severity, a.attack_type)

# --- 3. NETWORK ANALYZER (NIDS) ---
def network_callback(packet):
    if packet.haslayer(IP) and packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            src_ip = packet[IP].src
            
            # Ton Watchdog cherche des payloads SQLi/XSS dans le trafic réseau
            wd_alerts = wdog.analyze(payload)
            for a in wd_alerts:
                log_real_event(f"Network Attack from {src_ip}: {a.description}", a.severity, a.attack_type, src_ip)
        except:
            pass

def start_network_sniff():
    if not NETWORK_SNIFF_READY:
        print("[!] Scapy non prêt. Monitoring Réseau désactivé.")
        return
    print("[*] Network Sniffing (NIDS): START")
    sniff(prn=network_callback, store=0)

# --- MAIN ENGINE ---
if __name__ == "__main__":
    print("\n" + "="*45)
    print("      NEXUS REAL-TIME AGENT (HIDS/NIDS)")
    print("="*45 + "\n")
    
    # Lancement des threads
    threading.Thread(target=monitor_windows_events, daemon=True).start()
    threading.Thread(target=start_network_sniff, daemon=True).start()
    
    # Lancement du monitoring de fichiers
    observer = Observer()
    observer.schedule(FIMHandler(), WATCH_PATH, recursive=False)
    observer.start()
    
    print(f"[*] Monitoring local folder: {WATCH_PATH}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping Nexus Agent...")
        observer.stop()
    observer.join()