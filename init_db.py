import sqlite3
import os

USERS_DB = "database/users.db"


def init_users_db():
    """Create the shared users.db (auth only)."""
    os.makedirs("database", exist_ok=True)
    conn = sqlite3.connect(USERS_DB)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("""CREATE TABLE IF NOT EXISTS users (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        email     TEXT UNIQUE NOT NULL,
        password  TEXT NOT NULL,
        is_admin  INTEGER DEFAULT 0
    )""")
    conn.commit()
    conn.close()
    print("[+] users.db ready.")


def create_user_db(user_id):
    """Create a private siem.db for a specific user."""
    user_dir = f"database/user_{user_id}"
    os.makedirs(user_dir, exist_ok=True)
    db_path = f"{user_dir}/siem.db"
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("""CREATE TABLE IF NOT EXISTS logs (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp   TEXT,
        event       TEXT,
        attack_type TEXT
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS alerts (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        message     TEXT,
        severity    TEXT,
        attack_type TEXT,
        source_ip   TEXT,
        timestamp   TEXT
    )""")
    conn.commit()
    conn.close()
    print(f"[+] database/user_{user_id}/siem.db ready.")


def initialize():
    """Full reset: wipe everything and rebuild."""
    # Remove old monolithic DB if it exists
    if os.path.exists("database/siem.db"):
        try:
            os.remove("database/siem.db")
            print("[*] Old siem.db removed.")
        except PermissionError:
            print("[!] Close app.py/main.py first!")
            return

    # Remove old users.db
    if os.path.exists(USERS_DB):
        try:
            os.remove(USERS_DB)
            print("[*] Old users.db removed.")
        except PermissionError:
            print("[!] Close app.py/main.py first!")
            return

    # Remove all user DBs
    for name in os.listdir("database") if os.path.exists("database") else []:
        path = os.path.join("database", name)
        if os.path.isdir(path) and name.startswith("user_"):
            db_file = os.path.join(path, "siem.db")
            if os.path.exists(db_file):
                os.remove(db_file)
            try:
                os.rmdir(path)
            except OSError:
                pass
            print(f"[*] Removed {path}")

    init_users_db()
    print("[+] Database reset complete. Register a new account to start.")


if __name__ == "__main__":
    initialize()