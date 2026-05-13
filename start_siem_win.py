import subprocess
import time
import os

def start_siem():
    # Définir le chemin de Python dans le venv (pour Windows)
    python_path = os.path.join("venv", "Scripts", "python.exe")
    
    # S'assurer que le venv existe, sinon utiliser le Python système
    if not os.path.exists(python_path):
        print("[!] Warning: venv not found. Using system python.")
        python_path = "python"

    print("🚀 Initializing CyberWolf SIEM System...")
    print("========================================")

    # 1. Réinitialisation de la base de données (important pour commencer proprement)
    print("[*] Rebuilding Database...")
    subprocess.run([python_path, "init_db.py"])

    # Fonction d'aide pour ouvrir une nouvelle fenêtre CMD et exécuter un script
    def launch(name, script_path, args=None):
        print(f"[*] Launching {name}...")
        cmd = [python_path, script_path]
        if args: cmd.extend(args)
        # L'utilisation de start cmd /k garde la fenêtre ouverte pour voir les logs
        subprocess.Popen(f'start "{name}" cmd /k "{python_path} {script_path} {" ".join(args or [])}"', shell=True)

    # 2. Lancement du Dashboard
    launch("SIEM Dashboard", "app.py")
    time.sleep(2)

    # 3. Lancement du moteur principal (Engine)
    launch("SIEM Engine", "main.py")

    # 4. Lancement de l'agent de terrain (CyberWolf Sentinel - HIDS/NIDS)
    # Note : cela nécessite généralement des privilèges Admin pour les permissions réseau
    launch("CyberWolf Agent", "modules/RealTime_System_Monitor.py")

    # 5. Lancement du simulateur (Simulator)
    launch("Attack Simulator", "attack_simulator.py")

    print("\n✅ SYSTEM ONLINE: CGDSTE3 SIEM is now fully operational.")
    print("🔗 Access Dashboard at: http://127.0.0.1:5000")
    print("⌨️  Press Ctrl+C in any window to stop a specific module.")

if __name__ == "__main__":
    try:
        start_siem()
    except KeyboardInterrupt:
        print("\n[!] Shutdown sequence initiated.")