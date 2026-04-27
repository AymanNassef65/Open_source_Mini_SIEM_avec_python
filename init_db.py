import sqlite3
import os

DB_PATH = "database/siem.db"

def initialize():
    # Créer le dossier database s'il n'existe pas
    if not os.path.exists('database'):
        os.makedirs('database')
        
    # Supprimer l'ancienne DB pour repartir à zéro (Fresh Start)
    if os.path.exists(DB_PATH):
        try:
            os.remove(DB_PATH)
            print("[*] Ancienne base de données supprimée.")
        except PermissionError:
            print("[!] Erreur : Ferme app.py ou main.py avant de réinitialiser la DB !")
            return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # 1. Table LOGS : Historique complet de tout ce qui passe
    cursor.execute("""
    CREATE TABLE logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        event TEXT,
        attack_type TEXT
    )""")

    # 2. Table ALERTS : Uniquement les détections critiques pour le Dashboard
    # Ajout de 'attack_type' ici aussi pour faciliter les graphiques
    cursor.execute('''CREATE TABLE IF NOT EXISTS alerts 
                  (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                   message TEXT, 
                   severity TEXT, 
                   attack_type TEXT)''')

    conn.commit()
    conn.close()
    print("[+] Succès ! Base de données reconstruite avec toutes les colonnes.")

if __name__ == "__main__":
    initialize()