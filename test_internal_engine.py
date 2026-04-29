import sys
import os
import sqlite3
import time

# On s'assure de pouvoir importer les modules du projet
sys.path.append(os.getcwd())
sys.path.append(os.path.join(os.getcwd(), 'modules'))

from modules.threat_engine import Watchdog

DB_PATH = "database/siem.db"

def test_detection():
    print("=============================================")
    print("   CyberWolf ENGINE - SUITE DE TEST INTÉGRALE    ")
    print("=============================================")
    
    # Initialisation du moteur avec des seuils bas pour le test
    wdog = Watchdog(brute_threshold=3, port_threshold=5, ddos_threshold=10, cred_threshold=3)
    
    # 1. Attaques basées sur des signatures (Déclenchement immédiat)
    test_signatures = [
        ("SQL INJECTION", "UNION SELECT NULL, username, password FROM users --"),
        ("SCANNER RÉSEAU", "Reconnaissance via nmap -sC -sV localhost"),
        ("ACCÈS SENSIBLE", "Tentative de lecture de /etc/shadow"),
        ("RANSOMWARE", "Alerte : Fichier chiffré détecté .locked"),
        ("SIGNATURE DDOS", "ALERTE SYSTÈME : INBOUND_FLOOD détecté"),
        ("CREDENTIAL STUFFING", "LOGIN_ATTEMPT_MANY_ACCOUNTS source=10.0.0.1"),
        ("ESCALADE PRIVILÈGES", "CRITICAL: useradd uid=0 detected"),
    ]
    
    # 2. Attaques basées sur des seuils (Nécessitent plusieurs répétitions)
    test_thresholds = [
        ("BRUTE FORCE", "LOGIN_FAILED for user admin from 1.1.1.1", 4),
        ("PORT SCANNING", "CONNECTION_ATTEMPT: source=2.2.2.2 port=", 6), # Le port sera ajouté dynamiquement
    ]
    
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL;")
    cursor = conn.cursor()
    
    def log_alert(a):
        print(f"    [!] DÉTECTÉ : {a.attack_type} ({a.severity}) -> {a.description}")
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("INSERT INTO logs (timestamp, event, attack_type) VALUES (?, ?, ?)", 
                       (timestamp, f"[TEST-INT] {a.description}", a.attack_type))
        cursor.execute("INSERT INTO alerts (message, severity, attack_type) VALUES (?, ?, ?)", 
                       (f"TEST: {a.description}", a.severity, a.attack_type))

    # Exécution des tests de signature
    for label, payload in test_signatures:
        print(f"\n[*] Test : {label}")
        alerts = wdog.analyze(payload)
        if alerts:
            for a in alerts: log_alert(a)
        else:
            print("    [-] Échec de la détection.")

    # Exécution des tests de seuil
    for label, payload, count in test_thresholds:
        print(f"\n[*] Test : {label} ({count} itérations)")
        found = False
        for i in range(count):
            current_payload = payload + str(80 + i) if "port=" in payload else payload
            alerts = wdog.analyze(current_payload)
            if alerts:
                for a in alerts:
                    log_alert(a)
                    found = True
        if not found:
            print("    [-] Échec de la détection de seuil.")
            
    conn.commit()
    conn.close()
    print("\n" + "="*45)
    print("   TEST TERMINÉ - VÉRIFIEZ LE DASHBOARD   ")
    print("="*45)

if __name__ == "__main__":
    test_detection()
