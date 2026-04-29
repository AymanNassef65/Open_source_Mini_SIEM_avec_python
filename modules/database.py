import sqlite3

DB_PATH = "database/siem.db"

def connect_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn

def init_db():
    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event TEXT,
            attack_type TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT,
            severity TEXT
        )
    """)

    conn.commit()
    conn.close()

def insert_log(timestamp, event, attack_type="Normal"):
    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO logs (timestamp, event, attack_type)
        VALUES (?, ?, ?)
    """, (timestamp, event, attack_type))

    conn.commit()
    conn.close()

def insert_alert(message, severity, attack_type="Unknown"):
    conn = connect_db()
    cursor = conn.cursor()
    # On s'assure d'insérer les 3 valeurs
    cursor.execute("INSERT INTO alerts (message, severity, attack_type) VALUES (?, ?, ?)", 
                   (message, severity, attack_type))
    conn.commit()
    conn.close()
