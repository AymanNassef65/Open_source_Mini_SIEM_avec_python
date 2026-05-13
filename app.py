from flask import Flask, render_template, jsonify, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from collections import defaultdict
import sqlite3
import json, os, re

app = Flask(__name__)
app.secret_key = os.environ.get("CYBERWOLF_SECRET", "cyberwolf-siem-secret-key-2024")

USERS_DB = "database/users.db"

# ── DB helpers ──────────────────────────────────────────────────────────────

def get_auth_db():
    """Se connecte à la base de données partagée des utilisateurs."""
    os.makedirs("database", exist_ok=True)
    conn = sqlite3.connect(USERS_DB)
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn

def get_user_data_db(user_id=None):
    """Se connecte à la base de données siem.db privée d'un utilisateur spécifique."""
    target_id = user_id or session.get("user_id")
    if not target_id:
        return None
    db_path = f"database/user_{target_id}/siem.db"
    if not os.path.exists(db_path):
        from init_db import create_user_db
        create_user_db(target_id)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn

def ensure_users_table():
    conn = get_auth_db()
    conn.execute("""CREATE TABLE IF NOT EXISTS users (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        email     TEXT UNIQUE NOT NULL,
        password  TEXT NOT NULL,
        is_admin  INTEGER DEFAULT 0)""")
    conn.commit()
    conn.close()

def get_current_user():
    if "user_id" not in session:
        return None
    conn = get_auth_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, is_admin FROM users WHERE id=?", (session["user_id"],))
    user = cursor.fetchone()
    conn.close()
    return user

def login_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        if not get_current_user():
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return decorated

@app.before_request
def log_all_requests():
    """Intercepteur pour enregistrer toutes les requêtes HTTP entrantes pour détection par le Watchdog."""
    # Construire une ligne de journal brute pour le SIEM
    ip = request.remote_addr or "127.0.0.1"
    method = request.method
    path = request.path
    query = request.query_string.decode('utf-8')
    
    # Inclure les données de formulaire pour POST/PUT afin que les SQLi soient visibles par le Watchdog
    body = ""
    if method in ["POST", "PUT"] and request.form:
        body = " body=" + str(dict(request.form))
        
    full_url = f"{path}?{query}" if query else path
    
    # Nous l'enregistrons directement dans le fichier auth.log partagé surveillé par main.py/log_collector
    log_line = f"HTTP {method} {full_url}{body} from {ip}\n"
    
    os.makedirs("logs", exist_ok=True)
    with open("logs/auth.log", "a") as f:
        f.write(log_line)

def admin_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return redirect(url_for("login"))
        if not user[2]:
            return jsonify({"error": "Admin access required"}), 403
        return func(*args, **kwargs)
    return decorated

def _update_config_email(email):
    config_path = "config.json"
    try:
        config = json.load(open(config_path)) if os.path.exists(config_path) else {}
        config.setdefault("notifications", {}).setdefault("email", {})["receiver"] = email
        json.dump(config, open(config_path, "w"), indent=2)
    except Exception as error:
        print(f"[!] config.json update failed: {error}")

# ── Routes d'authentification ────────────────────────────────────────────────

@app.route("/login", methods=["GET","POST"])
def login():
    ensure_users_table()
    if get_current_user():
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        conn = get_auth_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id,password FROM users WHERE email=?", (email,))
        user = cursor.fetchone()
        conn.close()
        if user and check_password_hash(user[1], password):
            session["user_id"] = user[0]
            return redirect(url_for("dashboard"))
        flash("Invalid credentials. Access denied.", "error")
    return render_template("login.html", setup_mode=False)

@app.route("/setup", methods=["GET","POST"])
def setup():
    ensure_users_table()
    # Si déjà connecté, permettre la mise à jour du compte
    if get_current_user():
        pass
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        confirm = request.form.get("confirm","")
        if not email or not password:
            flash("Email and password required.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        elif len(password) < 8:
            flash("Password must be ≥ 8 characters.", "error")
        else:
            hashed = generate_password_hash(password)
            try:
                conn = get_auth_db()
                cursor = conn.cursor()
                # Vérifier s'il s'agit du premier utilisateur → le rendre administrateur
                cursor.execute("SELECT COUNT(*) FROM users")
                user_count = cursor.fetchone()[0]
                is_admin = 1 if user_count == 0 else 0

                logged_user = get_current_user()
                if logged_user:
                    # Mettre à jour le compte existant
                    conn.execute("UPDATE users SET email=?,password=? WHERE id=?",
                                 (email, hashed, session["user_id"]))
                else:
                    # Créer un nouveau compte
                    conn.execute("INSERT INTO users(email,password,is_admin) VALUES(?,?,?)",
                                 (email, hashed, is_admin))
                conn.commit()

                # Obtenir l'ID de l'utilisateur
                cursor.execute("SELECT id FROM users WHERE email=?", (email,))
                row = cursor.fetchone()
                conn.close()
                if row:
                    new_user_id = row[0]
                    session["user_id"] = new_user_id
                    # Créer la base de données privée de l'utilisateur
                    from init_db import create_user_db
                    create_user_db(new_user_id)

                _update_config_email(email)
                role = "Admin" if is_admin else "Operator"
                flash(f"Account created ({role}). Welcome.", "success")
                return redirect(url_for("dashboard"))
            except sqlite3.IntegrityError:
                flash("Email already registered.", "error")
    return render_template("login.html", setup_mode=True)

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out securely.", "success")
    return redirect(url_for("login"))

# ── Tableau de bord ──────────────────────────────────────────────────────────

@app.route("/")
@login_required
def dashboard():
    user = get_current_user()
    return render_template("dashboard.html", user_email=user[1], is_admin=user[2])

# ── Admin : lister les utilisateurs ──────────────────────────────────────────

@app.route("/api/users")
@admin_required
def api_users():
    """Admin uniquement : lister tous les utilisateurs enregistrés."""
    conn = get_auth_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, is_admin FROM users ORDER BY id")
    rows = cursor.fetchall()
    conn.close()
    return jsonify({"users": [{"id": row[0], "email": row[1], "is_admin": row[2]} for row in rows]})

@app.route("/api/users/<int:target_user_id>/clear", methods=["POST"])
@admin_required
def admin_clear_user_logs(target_user_id):
    """Admin uniquement : effacer les journaux et alertes d'un utilisateur spécifique."""
    db_path = f"database/user_{target_user_id}/siem.db"
    if not os.path.exists(db_path):
        return jsonify({"status": "error", "message": "User DB not found"}), 404
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM logs")
    cursor.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})

@app.route("/api/users/<int:target_user_id>", methods=["DELETE"])
@admin_required
def admin_delete_user(target_user_id):
    """Admin uniquement : supprimer un utilisateur et sa base de données."""
    current_user = get_current_user()
    if current_user[0] == target_user_id:
        return jsonify({"status": "error", "message": "Cannot delete yourself"}), 400
    conn = get_auth_db()
    conn.execute("DELETE FROM users WHERE id=? AND is_admin=0", (target_user_id,))
    conn.commit()
    conn.close()
    # Supprimer la BD de l'utilisateur
    import shutil
    user_dir = f"database/user_{target_user_id}"
    if os.path.exists(user_dir):
        shutil.rmtree(user_dir, ignore_errors=True)
    return jsonify({"status": "success"})

# ── Core data API ─────────────────────────────────────────────────────────────

@app.route("/api/dashboard")
@login_required
def api_dashboard():
    """Point d'accès unique renvoyant toutes les données du tableau de bord pour l'utilisateur connecté."""
    try:
        conn = get_user_data_db()
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM logs")
        log_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM alerts")
        alert_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity='Critical'")
        critical_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity='High'")
        high_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM logs WHERE attack_type='Brute Force'")
        brute_force_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM logs WHERE attack_type='Access Denied'")
        access_denied_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE attack_type='DDoS Attempt'")
        ddos_count = cursor.fetchone()[0]

        try:
            cursor.execute("SELECT id,message,severity,attack_type,source_ip,timestamp FROM alerts ORDER BY id DESC LIMIT 200")
        except Exception:
            cursor.execute("SELECT id,message,severity,attack_type,NULL,NULL FROM alerts ORDER BY id DESC LIMIT 200")
        alerts = cursor.fetchall()

        cursor.execute("SELECT timestamp,event,attack_type FROM logs ORDER BY id DESC LIMIT 300")
        all_logs = cursor.fetchall()

        cursor.execute("SELECT attack_type,COUNT(*) FROM alerts GROUP BY attack_type")
        event_stats = cursor.fetchall()

        cursor.execute("SELECT severity,COUNT(*) FROM alerts GROUP BY severity")
        severity_stats = cursor.fetchall()

        # Chronologie horaire
        cursor.execute("SELECT timestamp FROM logs ORDER BY id DESC LIMIT 500")
        timestamp_rows = cursor.fetchall()
        hourly_counts = defaultdict(int)
        for (timestamp_val,) in timestamp_rows:
            if timestamp_val:
                match = re.search(r'(\d{2}):\d{2}:\d{2}', timestamp_val)
                if match:
                    hourly_counts[int(match.group(1))] += 1
        timeline = [{"hour": f"{hour:02d}:00", "count": hourly_counts.get(hour, 0)} for hour in range(24)]

        # IPs principales
        try:
            cursor.execute("SELECT source_ip,COUNT(*) FROM alerts WHERE source_ip IS NOT NULL GROUP BY source_ip ORDER BY COUNT(*) DESC LIMIT 10")
            top_ips = cursor.fetchall()
        except Exception:
            top_ips = []

        conn.close()
        return jsonify({
            "log_count": log_count, "alert_count": alert_count,
            "critical": critical_count, "high": high_count,
            "failed_logins": brute_force_count, "access_denied": access_denied_count,
            "ddos_count": ddos_count,
            "alerts": alerts, "all_logs": all_logs,
            "event_stats": event_stats, "severity_stats": severity_stats,
            "timeline": timeline, "top_ips": top_ips
        })
    except Exception as error:
        return jsonify({"error": str(error)}), 500

@app.route("/api/data")
@login_required
def api_data():
    try:
        conn = get_user_data_db()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM logs")
        log_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM alerts")
        alert_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity='Critical'")
        critical_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity='High'")
        high_count = cursor.fetchone()[0]
        try:
            cursor.execute("SELECT id,message,severity,attack_type,source_ip,timestamp FROM alerts ORDER BY id DESC LIMIT 200")
        except Exception:
            cursor.execute("SELECT id,message,severity,attack_type,NULL,NULL FROM alerts ORDER BY id DESC LIMIT 200")
        alerts = cursor.fetchall()
        cursor.execute("SELECT timestamp,event,attack_type FROM logs ORDER BY id DESC LIMIT 500")
        all_logs = cursor.fetchall()
        cursor.execute("SELECT COUNT(*) FROM logs WHERE attack_type='Brute Force'")
        brute_force_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM logs WHERE attack_type='Access Denied'")
        access_denied_count = cursor.fetchone()[0]
        cursor.execute("SELECT attack_type,COUNT(*) FROM alerts GROUP BY attack_type")
        event_stats = cursor.fetchall()
        conn.close()
        return jsonify({
            "log_count": log_count, "alert_count": alert_count,
            "critical": critical_count, "high": high_count,
            "alerts": alerts, "all_logs": all_logs,
            "failed_logins": brute_force_count, "access_denied": access_denied_count,
            "event_stats": event_stats
        })
    except Exception as error:
        return jsonify({"error": str(error)}), 500

@app.route("/api/top_ips")
@login_required
def api_top_ips():
    """Renvoie les 10 principales IPs sources par nombre d'alertes."""
    try:
        conn = get_user_data_db()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT source_ip, COUNT(*) as cnt FROM alerts WHERE source_ip IS NOT NULL GROUP BY source_ip ORDER BY cnt DESC LIMIT 10")
            rows = cursor.fetchall()
        except Exception:
            rows = []
        conn.close()
        return jsonify({"top_ips": rows})
    except Exception as error:
        return jsonify({"error": str(error)}), 500

@app.route("/api/timeline")
@login_required
def api_timeline():
    """Événements groupés par heure de la journée à partir des 500 derniers journaux."""
    try:
        conn = get_user_data_db()
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp, attack_type FROM logs ORDER BY id DESC LIMIT 500")
        rows = cursor.fetchall()
        conn.close()
        hourly_counts = defaultdict(int)
        for timestamp_val, attack_type in rows:
            if not timestamp_val:
                continue
            match = re.search(r'(\d{2}):\d{2}:\d{2}', timestamp_val)
            if match:
                hour = int(match.group(1))
                hourly_counts[hour] += 1
        result = [{"hour": f"{hour:02d}:00", "count": hourly_counts.get(hour, 0)} for hour in range(24)]
        return jsonify({"timeline": result})
    except Exception as error:
        return jsonify({"error": str(error)}), 500

@app.route("/api/severity_stats")
@login_required
def api_severity_stats():
    try:
        conn = get_user_data_db()
        cursor = conn.cursor()
        cursor.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
        rows = cursor.fetchall()
        conn.close()
        return jsonify({"severity_stats": rows})
    except Exception as error:
        return jsonify({"error": str(error)}), 500

@app.route("/api/clear_logs", methods=["POST"])
@login_required
def clear_logs():
    """Effacer uniquement les journaux et alertes de l'utilisateur connecté."""
    try:
        conn = get_user_data_db()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM logs")
        cursor.execute("DELETE FROM alerts")
        conn.commit()
        conn.close()
        return jsonify({"status": "success"})
    except Exception as error:
        return jsonify({"status": "error", "message": str(error)}), 500

@app.route("/api/update_email", methods=["POST"])
@login_required
def update_email():
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    if not email or "@" not in email:
        return jsonify({"status": "error", "message": "Invalid email"}), 400
    try:
        current_user = get_current_user()
        conn = get_auth_db()
        conn.execute("UPDATE users SET email=? WHERE id=?", (email, current_user[0]))
        conn.commit()
        conn.close()
        _update_config_email(email)
        return jsonify({"status": "success", "email": email})
    except sqlite3.IntegrityError:
        return jsonify({"status": "error", "message": "Email already in use"}), 409
    except Exception as error:
        return jsonify({"status": "error", "message": str(error)}), 500

if __name__ == "__main__":
    ensure_users_table()
    app.run(debug=True, port=5000)