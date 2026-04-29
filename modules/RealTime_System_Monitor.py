import sqlite3
import time
import os
import threading
import socket
import re
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from threat_engine import Watchdog
from notifier import add_to_batch

# --- SAFETY IMPORTS ---
try:
    import win32evtlog
    WINDOWS_EVENTS_READY = True
except ImportError:
    WINDOWS_EVENTS_READY = False

try:
    from scapy.all import sniff, IP, Raw, TCP, UDP
    NETWORK_SNIFF_READY = True
except ImportError:
    NETWORK_SNIFF_READY = False

# --- CONFIGURATION ---
DB_PATH = "database/siem.db"
WATCH_PATH = os.getcwd()
wdog = Watchdog()

def log_real_event(msg, severity, attack_type, source_ip="127.0.0.1"):
    try:
        # Ajout au batch de notification
        add_to_batch(attack_type, severity, msg)
        
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL;")
        cursor = conn.cursor()
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("INSERT INTO logs (timestamp, event, attack_type) VALUES (?, ?, ?)", 
                       (timestamp, f"[REAL-PC] {msg}", attack_type))
        cursor.execute("INSERT INTO alerts (message, severity, attack_type) VALUES (?, ?, ?)", 
                       (f"PC-THREAT: {msg}", severity, attack_type))
        conn.commit()
        conn.close()
        print(f"\033[91m[!] ALERTE DÉTECTÉE : [{attack_type}] {msg}\033[0m")
    except Exception as e:
        print(f"[-] Erreur DB : {e}")

# --- 1. MONITORING FICHIERS (HIDS) ---
class FIMHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory: self.check_file(event.src_path, "Création")
    def on_modified(self, event):
        if not event.is_directory: self.check_file(event.src_path, "Modification")

    def check_file(self, path, action):
        filename = os.path.basename(path)
        if filename.endswith(('.db', '.tmp', '.log')): return
        wd_alerts = wdog.analyze(filename)
        if wd_alerts:
            for a in wd_alerts:
                log_real_event(f"Fichier {action}: {filename} ({a.description})", a.severity, a.attack_type)

# --- 2. MONITORING RÉSEAU INTELLIGENT (NIDS) ---
def network_callback(packet):
    # A. Analyse du Contenu (Signatures comme SQLi, Nmap-version, etc.)
    if packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            if payload.strip():
                wd_alerts = wdog.analyze(payload)
                for a in wd_alerts:
                    log_real_event(f"Signature détectée: {a.description}", a.severity, a.attack_type)
        except: pass

    # B. Analyse du Comportement (Détection de Scan de Ports)
    if packet.haslayer(TCP) or packet.haslayer(UDP):
        src_ip = "127.0.0.1"
        if packet.haslayer(IP): src_ip = packet[IP].src
        
        # On extrait le port de destination
        port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
        
        # On simule une ligne de log de connexion pour le détecteur de seuil du Watchdog
        # Le Watchdog va compter ces tentatives pour détecter un scan
        sim_line = f"CONNECTION_ATTEMPT: source_ip={src_ip} target_port={port}"
        wd_alerts = wdog.analyze(sim_line)
        for a in wd_alerts:
            log_real_event(f"Comportement suspect: {a.description}", a.severity, a.attack_type, src_ip)

def start_network_sniff():
    if not NETWORK_SNIFF_READY: return
    print("[*] Network Sniffing (NIDS): ACTIF")
    # On écoute sur 'lo' (localhost) pour les tests et sur les autres interfaces
    # On utilise un filtre pour ne pas s'auto-analyser (port 5000) et éviter les boucles
    sniff(prn=network_callback, filter="not port 5000", store=0)

if __name__ == "__main__":
    print("\n" + "="*45)
    print("      AGENT CyberWolf TEMPS RÉEL (V2.0)")
    print("="*45 + "\n")
    
    threading.Thread(target=start_network_sniff, daemon=True).start()
    
    observer = Observer()
    observer.schedule(FIMHandler(), WATCH_PATH, recursive=False)
    observer.start()
    
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
