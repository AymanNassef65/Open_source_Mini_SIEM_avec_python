import subprocess
import time
import os

def start_siem():
    print("🚀 Nexus SIEM - Linux Launcher (Kali Edition)")
    
    # Chemin vers ton environnement virtuel
    # On suppose que tu as créé ton venv avec 'python3 -m venv venv'
    python_venv = "./venv/bin/python3"
    
    if not os.path.exists(python_venv):
        print("[!] Erreur : Environnement virtuel './venv' introuvable.")
        print("[*] Lance d'abord : python3 -m venv venv && source venv/bin/activate && pip install flask scapy watchdog")
        return

    # Liste des commandes à lancer
    # 'qterminal' est le terminal par défaut de Kali (XFCE), change-le en 'gnome-terminal' ou 'konsole' si besoin.
    terminal_cmd = "qterminal" 

    commands = [
        {"name": "DASHBOARD", "cmd": f"{python_venv} app.py"},
        {"name": "ENGINE", "cmd": f"{python_venv} main.py --mode realtime"},
        {"name": "SIMULATOR", "cmd": f"{python_venv} attack_simulator.py"},
    ]

    print("[*] Démarrage des modules standards...")
    for item in commands:
        print(f"    > Lancement de {item['name']}...")
        # Commande pour ouvrir un nouvel onglet/fenêtre qterminal et exécuter la commande
        subprocess.Popen([terminal_cmd, "-e", f"bash -c '{item['cmd']}; exec bash'"])
        time.sleep(1.5)

    # Cas particulier : Nexus_Sentinel (besoin de SUDO pour le sniffing réseau)
    print("[*] Déploiement de l'agent SENTINEL (Sudo requis pour Scapy)...")
    sentinel_cmd = f"sudo {python_venv} modules/RealTime_System_Monitor.py"
    subprocess.Popen([terminal_cmd, "-e", f"bash -c '{sentinel_cmd}; exec bash'"])

    print("\n✅ TOUS LES SYSTÈMES SONT OPÉRATIONNELS")
    print("🔗 Dashboard : http://127.0.0.1:5000")
    print("⚠️  Vérifie la fenêtre Sentinel pour saisir ton mot de passe sudo si nécessaire.")

if __name__ == "__main__":
    start_siem()