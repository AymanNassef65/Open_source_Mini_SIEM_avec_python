import logging
import json
from logging.handlers import RotatingFileHandler
import time
import os
import re
import socket
import threading
import sys

# Ajout du chemin pour importer les modules locaux
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from threat_engine import Watchdog
from notifier import add_to_batch

class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
        }
        if isinstance(record.msg, dict):
            log_record.update(record.msg)
        else:
            log_record["message"] = record.getMessage()
        return json.dumps(log_record)

logger = logging.getLogger("CyberWolf_Collector")
logger.setLevel(logging.INFO)

# Utilisation d'un chemin absolu ou relatif au projet pour le JSONL
log_file_path = "logs/formatted_logs.jsonl"
os.makedirs("logs", exist_ok=True)

handler = RotatingFileHandler(log_file_path, maxBytes=5000000, backupCount=3)
handler.setFormatter(JSONFormatter())
logger.addHandler(handler)

wdog = Watchdog()

def analyze_and_log(event_data):
    """Analyse un événement avec le Watchdog et l'enregistre."""
    # Log dans le fichier JSONL
    logger.info(event_data)
    
    # Analyse de sécurité
    raw_text = event_data.get("raw_log", "") or event_data.get("action", "")
    if raw_text:
        alerts = wdog.analyze(raw_text)
        for a in alerts:
            # On pourrait ici aussi insérer en DB, mais on va au moins notifier
            print(f"\033[91m[!] ALERTE COLLECTEUR : {a.attack_type}\033[0m")
            add_to_batch(a.attack_type, a.severity, f"[Collector] {a.description}")

def collect_web_logs(filepath, logger):
    """Surveille un fichier de log web et extrait l'IP et la méthode HTTP."""
    log_pattern = re.compile(r'^(?P<ip>\d+\.\d+\.\d+\.\d+).*?"(?P<method>[A-Z]+)')

    try:
        with open(filepath, 'r') as file:
            file.seek(0, os.SEEK_END)
            print(f"[*] Analyse des logs web en cours : {filepath}...")
            
            while True:
                line = file.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                
                match = log_pattern.search(line)
                if match:
                    web_event = {
                        "log_type": "web",
                        "source_ip": match.group("ip"),
                        "method": match.group("method"),
                        "raw_log": line.strip()
                    }
                    analyze_and_log(web_event)
                    
    except FileNotFoundError:
        print(f"[!] Erreur : Impossible de trouver le fichier log à {filepath}")

def detect_web_log_file():
    """Scanne les chemins par défaut pour les logs Apache et Nginx."""
    common_log_paths = [
        "/var/log/nginx/access.log",
        "/var/log/apache2/access.log", 
        "/var/log/httpd/access_log"
    ]
    
    print("[*] Recherche de logs de serveurs web actifs...")
    for path in common_log_paths:
        if os.path.exists(path) and os.access(path, os.R_OK):
            print(f"[+] Log détecté : {path}")
            return path
    return None

def collect_port_logs(port, logger):
    """Écoute sur un port spécifique et logue les tentatives de connexion."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind(('0.0.0.0', port))
        server_socket.listen(5)
        print(f"[*] Écoute des connexions non autorisées sur le port {port}...")
        
        while True:
            client_socket, client_address = server_socket.accept()
            source_ip, source_port = client_address
            
            port_event = {
                "log_type": "port",
                "source_ip": source_ip,
                "target_port": port,
                "action": f"Tentative de connexion sur port {port}"
            }
            
            analyze_and_log(port_event)
            client_socket.close()
            
    except PermissionError:
        print(f"[!] Erreur : Privilèges root requis pour écouter sur le port {port}.")

if __name__ == "__main__":
    print("[*] Initialisation du collecteur CyberWolf...")
    WEB_LOG_FILE = detect_web_log_file()
    PORT_TO_MONITOR = 2222
    
    if WEB_LOG_FILE:
        threading.Thread(target=collect_web_logs, args=(WEB_LOG_FILE, logger), daemon=True).start()
    
    threading.Thread(target=collect_port_logs, args=(PORT_TO_MONITOR, logger), daemon=True).start()
    
    try:
        print("[*] Collecteur actif. Ctrl+C pour arrêter.")
        while True:
            time.sleep(1) 
    except KeyboardInterrupt:
        print("\n[!] Arrêt des collecteurs...")
