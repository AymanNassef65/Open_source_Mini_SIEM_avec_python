import sys
import os

sys.path.append(os.getcwd())

import main
from modules.threat_engine import Watchdog

def start_monitor():
    # Définir l'utilisateur en dur pour contourner terminal_auth lors des tests
    main.CURRENT_USER_ID = 1
    main.DB_PATH = "database/user_1/siem.db"
    main.CURRENT_USER_EMAIL = "aymannassif65@gmail.com"
    
    # Simuler l'initialisation de la base de données
    from init_db import create_user_db
    create_user_db(1)
    
    wdog = Watchdog(brute_threshold=3, port_threshold=15, ddos_threshold=20, cred_threshold=3)
    
    # Exécuter monitor_realtime tout en interceptant l'interruption clavier (Ctrl+C)
    try:
        main.monitor_realtime(wdog)
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    start_monitor()
