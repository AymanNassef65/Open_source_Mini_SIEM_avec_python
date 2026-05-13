import smtplib
import requests
import time
import threading
import json
import os
import sqlite3
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# --- Configuration ---
CONFIG_PATH = "config.json"
USERS_DB = "database/users.db"


def load_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'r') as f:
            return json.load(f)
    return {}


config = load_config().get("notifications", {})
TELEGRAM_TOKEN  = config.get("telegram", {}).get("token")
CHAT_ID         = config.get("telegram", {}).get("chat_id")
EMAIL_SENDER    = config.get("email", {}).get("sender")
EMAIL_PASSWORD  = config.get("email", {}).get("password")
BATCH_INTERVAL  = config.get("batch_interval", 60)
NOTIF_ENABLED   = config.get("enabled", False)


def get_dynamic_receiver():
    """
    Fetch all user emails from the shared users.db.
    Returns a list of emails for batch notification.
    Falls back to config.json if DB is unavailable.
    """
    try:
        conn = sqlite3.connect(USERS_DB)
        conn.execute("PRAGMA journal_mode=WAL;")
        cur = conn.cursor()
        cur.execute("SELECT email FROM users ORDER BY id ASC")
        rows = cur.fetchall()
        conn.close()
        if rows:
            return [r[0] for r in rows if r[0]]
    except Exception:
        pass
    # Fallback to static config value
    fallback = config.get("email", {}).get("receiver")
    return [fallback] if fallback else []


alert_queue = []
queue_lock  = threading.Lock()


def send_batch_now():
    """Regroupe les alertes et les envoie périodiquement."""
    global alert_queue

    if not NOTIF_ENABLED:
        return

    while True:
        time.sleep(BATCH_INTERVAL)

        with queue_lock:
            if not alert_queue:
                continue
            current_batch = list(alert_queue)
            alert_queue   = []

        count        = len(current_batch)
        summary_text = (f"🚨 *RAPPORT CYBERWOLF* 🚨\n"
                        f"{count} événements de sécurité identifiés durant la dernière minute :\n\n")
        email_body   = (f"CYBERWOLF SIEM - RAPPORT DE SYNTHÈSE\n"
                        f"Total d'événements : {count}\n" + "-" * 30 + "\n")

        for i, a in enumerate(current_batch, 1):
            line          = f"{i}. [{a['severity']}] {a['type']} : {a['desc']}\n"
            summary_text += f"• {line}"
            email_body   += line

        # ── Envoi Telegram ──
        if config.get("telegram", {}).get("enabled"):
            try:
                t_url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
                requests.post(t_url, data={
                    "chat_id": CHAT_ID,
                    "text": summary_text,
                    "parse_mode": "Markdown"
                }, timeout=10)
            except Exception:
                print("[-] Erreur lors de l'envoi du batch Telegram")

        # ── Envoi Email (to all registered users) ──
        if config.get("email", {}).get("enabled"):
            receivers = get_dynamic_receiver()
            if not receivers:
                print("[-] Aucun email destinataire configuré, notification ignorée.")
                continue
            for email_receiver in receivers:
                try:
                    msg             = MIMEMultipart()
                    msg['From']     = EMAIL_SENDER
                    msg['To']       = email_receiver
                    msg['Subject']  = f"🚨 [CyberWolf] Résumé de Sécurité : {count} événements"
                    msg.attach(MIMEText(email_body, 'plain'))

                    with smtplib.SMTP('smtp.gmail.com', 587) as server:
                        server.starttls()
                        server.login(EMAIL_SENDER, EMAIL_PASSWORD)
                        server.send_message(msg)

                    print(f"[+] Email Batch sent to {email_receiver}")

                except Exception as e:
                    print(f"[-] Erreur Email détaillée : {e}")


# Lancement du thread de gestion du batch en arrière-plan
if NOTIF_ENABLED:
    threading.Thread(target=send_batch_now, daemon=True).start()


def add_to_batch(attack_type, severity, description):
    """Ajoute une alerte à la file d'attente pour le prochain envoi groupé."""
    if not NOTIF_ENABLED:
        return

    with queue_lock:
        alert_queue.append({
            'type':     attack_type,
            'severity': severity,
            'desc':     description,
            'time':     time.strftime('%H:%M:%S')
        })
    print(f"[+] Alerte ajoutée au batch : {attack_type}")
