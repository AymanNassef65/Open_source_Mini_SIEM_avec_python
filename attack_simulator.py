import time
import random
import os

# المسار الخاص بملف الـ Logs
LOG_FILE = "logs/auth.log"

def generate_complex_log():
    """توليد أسطر هجومية متنوعة للـ 8 كواشف"""
    ip_source = f"192.168.1.{random.randint(10, 250)}"
    external_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.12.34"
    
    scenarios = [
        # SQL Injection
        f"ERROR SQL_QUERY_FAILED: source_ip={external_ip} input='OR 1=1--'",
        f"WARNING SQL_QUERY: source_ip={external_ip} pattern='UNION SELECT NULL,username,password FROM users'",
        
        # Brute Force (سطر منفرد)
        f"LOGIN_FAILED for user admin from source_ip={external_ip}",
        
        # Port Scanning
        f"CONNECTION_ATTEMPT: source_ip={external_ip} target_port={random.randint(20, 1024)} status=REFUSED",
        
        # Access Denied
        f"ACCESS_DENIED: user=guest source_ip={ip_source} resource=/etc/shadow",
        f"HTTP 403 Forbidden: client {ip_source} access to /wp-admin/config.php",
        
        # DDoS
        f"INBOUND_FLOOD: source_ip={external_ip} packets=10000 size=64KB",
        
        # Ransomware
        f"FILE_ENCRYPTED: path=/home/user/data_{random.randint(1,10)}.docx.locked extension=.crypt",
        f"MASSIVE FILE MODIFICATION detected in /var/www/html/uploads",
        
        # Credential Stuffing
        f"LOGIN_ATTEMPT_MANY_ACCOUNTS: source_ip={external_ip} status=failed",
        
        # Privilege Escalation
        f"sudo: user {ip_source} not in sudoers ; COMMAND=/usr/bin/apt-get install nmap",
        f"Privilege Escalation attempt: useradd uid=0 detected"
    ]
    return random.choice(scenarios)

def run_simulation():
    print("=============================================")
    print("    CGDSTE3 SIEM - ADVANCED ATTACK SIMULATOR   ")
    print("=============================================")
    print(f"[*] Target: {os.path.abspath(LOG_FILE)}")
    
    # التأكد من وجود مجلد الـ logs
    if not os.path.exists('logs'):
        os.makedirs('logs')

    try:
        while True:
            mode = random.random()
            
            # 1. Burst Mode (20% chance) - هجمات مركزة (Brute Force, DDoS, Scan)
            if mode < 0.2:
                target_ip = f"{random.randint(1, 255)}.44.55.66"
                attack_type = random.choice(["BRUTE_FORCE", "DDOS", "SCAN"])
                print(f"\033[91m[!] Executing {attack_type} burst from {target_ip}...\033[0m")
                
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
                    f.flush() # دفع البيانات للملف فوراً (Windows Fix)
                time.sleep(0.5)

            # 2. Normal Activity (40% chance) - سجلات عادية
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
                print(f"[SIM] Normal: {line.strip()}")

            # 3. Single Targeted Attacks (40% chance) - هجمات منفردة
            else:
                line = generate_complex_log() + "\n"
                with open(LOG_FILE, "a") as f:
                    f.write(line)
                    f.flush()
                print(f"\033[93m[SIM] Attack: {line.strip()[:60]}...\033[0m")

            # وقت عشوائي بين الحقن
            time.sleep(random.uniform(2, 5))
            
    except KeyboardInterrupt:
        print("\n[*] Simulator Stopped by user.")

if __name__ == "__main__":
    run_simulation()