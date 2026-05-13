import sqlite3
import os

USERS_DB = "database/users.db"


def connect_users_db():
    """Connect to the shared auth database."""
    os.makedirs("database", exist_ok=True)
    conn = sqlite3.connect(USERS_DB, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def connect_user_db(user_id):
    """Connect to a specific user's private siem.db."""
    db_path = f"database/user_{user_id}/siem.db"
    if not os.path.exists(db_path):
        from init_db import create_user_db
        create_user_db(user_id)
    conn = sqlite3.connect(db_path, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def insert_log(user_id, timestamp, event, attack_type="Normal"):
    conn = connect_user_db(user_id)
    conn.execute(
        "INSERT INTO logs (timestamp, event, attack_type) VALUES (?, ?, ?)",
        (timestamp, event, attack_type))
    conn.commit()
    conn.close()


def insert_alert(user_id, message, severity, attack_type="Unknown", source_ip=None):
    conn = connect_user_db(user_id)
    conn.execute(
        "INSERT INTO alerts (message, severity, attack_type, source_ip, timestamp) VALUES (?, ?, ?, ?, ?)",
        (message, severity, attack_type, source_ip,
         __import__('datetime').datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()
