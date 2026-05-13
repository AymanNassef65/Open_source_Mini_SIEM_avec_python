import time
import random
import os

# Chemin vers le fichier de logs
LOG_FILE = "logs/auth.log"

def generate_complex_log():
    """Génère diverses lignes d'attaque pour les 8 détecteurs"""
    ip_source = f"192.168.1.{random.randint(10, 250)}"
    external_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.12.34"
    
    scenarios = [
        # Injection SQL
        f"ERROR SQL_QUERY_FAILED: source_ip={external_ip} input='OR 1=1--'",
        f"WARNING SQL_QUERY: source_ip={external_ip} pattern='UNION SELECT NULL,username,password FROM users'",
        
        # Brute Force (ligne unique)
        f"LOGIN_FAILED for user admin from source_ip={external_ip}",
        
        # Scan de Ports
        f"CONNECTION_ATTEMPT: source_ip={external_ip} target_port={random.randint(20, 1024)} status=REFUSED",
        
        # Accès Refusé
        f"ACCESS_DENIED: user=guest source_ip={ip_source} resource=/etc/shadow",
        f"HTTP 403 Forbidden: client {ip_source} access to /wp-admin/config.php",
        
        # DDoS
        f"INBOUND_FLOOD: source_ip={external_ip} packets=10000 size=64KB",
        
        # Ransomware
        f"FILE_ENCRYPTED: path=/home/user/data_{random.randint(1,10)}.docx.locked extension=.crypt",
        f"MASSIVE FILE MODIFICATION detected in /var/www/html/uploads",
        
        # Credential Stuffing
        f"LOGIN_ATTEMPT_MANY_ACCOUNTS: source_ip={external_ip} status=failed",
        
        # Escalade de Privilèges
        f"sudo: user {ip_source} not in sudoers ; COMMAND=/usr/bin/apt-get install nmap",
        f"Privilege Escalation attempt: useradd uid=0 detected",

        # XSS Attack
        f"HTTP GET /search?q=<script>alert(document.cookie)</script> from {external_ip}",
        f"WAF ALERT: XSS pattern detected: javascript:eval(String.fromCharCode(97,108,101,114,116)) from {external_ip}",
        f"ACCESS_LOG: {external_ip} GET /comment?text=<img onerror=alert(1) src=x> 200",
    ]
    return random.choice(scenarios)

def run_simulation():
    print("=============================================")
    print("   CyberWolf SIEM - SIMULATEUR D'ATTAQUE AVANCÉ  ")
    print("=============================================")
    print(f"[*] Cible : {os.path.abspath(LOG_FILE)}")
    
    # S'assurer que le dossier des logs existe
    if not os.path.exists('logs'):
        os.makedirs('logs')

    try:
        while True:
            mode = random.random()
            
            # 1. Mode Rafale (20% de chance) - Attaques concentrées (Brute Force, DDoS, Scan)
            if mode < 0.2:
                target_ip = f"{random.randint(1, 255)}.44.55.66"
                attack_type = random.choice(["BRUTE_FORCE", "DDOS", "SCAN"])
                print(f"\033[91m[!] Exécution d'une rafale {attack_type} depuis {target_ip}...\033[0m")
                
                iterations = 20 if attack_type == "DDOS" else 7
                with open(LOG_FILE, "a") as f:
                    for _ in range(iterations):
                        if attack_type == "BRUTE_FORCE":
                            line = f"LOGIN_FAILED for user root from source_ip={target_ip}\n"
                        elif attack_type == "DDOS":
                            line = f"INBOUND_FLOOD: source_ip={target_ip} packets=5000\n"
                        else:
                            line = f"CONNECTION_ATTEMPT: source_ip={target_ip} target_port={random.randint(20, 1000)} status=REFUSED\n"
                        f.write(line)
                    f.flush() # Forcer l'écriture sur le disque
                time.sleep(0.5)

            # 2. Activité Normale (40% de chance) - Logs standards
            elif mode < 0.6:
                normals = [
                    f"INFO: user=youssef login success from 192.168.1.15",
                    f"SYSTEM: service sshd status=running",
                    f"INFO: database synchronized successfully",
                    f"DEBUG: periodic cleanup task started"
                ]
                line = random.choice(normals) + "\n"
                with open(LOG_FILE, "a") as f:
                    f.write(line)
                    f.flush()
                print(f"[SIM] Normal : {line.strip()}")

            # 3. Attaques Ciblées Individuelles (40% de chance)
            else:
                line = generate_complex_log() + "\n"
                with open(LOG_FILE, "a") as f:
                    f.write(line)
                    f.flush()
                print(f"\033[93m[SIM] Attaque : {line.strip()[:60]}...\033[0m")

            # Délai aléatoire entre les injections
            time.sleep(random.uniform(2, 5))
            
    except KeyboardInterrupt:
        print("\n[*] Simulateur arrêté par l'utilisateur.")

if __name__ == "__main__":
    run_simulation()