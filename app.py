from flask import Flask, render_template, jsonify
import sqlite3 as s3
import os

app = Flask(__name__)

DB_PATH = "database/siem.db"

# دالة مساعدة باش نجيبو البيانات كاملة من القاعدة
def get_data_from_db():
    conn = s3.connect(DB_PATH)
    curseur = conn.cursor()

    # 1. Total Logs
    curseur.execute("SELECT COUNT(*) FROM logs")
    log_count = curseur.fetchone()[0]

    # 2. Total Alerts
    curseur.execute("SELECT COUNT(*) FROM alerts")
    alert_count = curseur.fetchone()[0]

    # 3. Alerts للجدول الصغير (مع العمود الرابع attack_type)
    curseur.execute("SELECT id, message, severity, attack_type FROM alerts ORDER BY id DESC LIMIT 10")
    alerts = curseur.fetchall()

    # 4. الأرشيف الكامل
    curseur.execute("SELECT timestamp, event, attack_type FROM logs ORDER BY id DESC LIMIT 200")
    all_logs = curseur.fetchall()

    # 5. الإحصائيات السريعة
    curseur.execute("SELECT COUNT(*) FROM logs WHERE attack_type='Brute Force'")
    failed_logins = curseur.fetchone()[0]

    curseur.execute("SELECT COUNT(*) FROM logs WHERE attack_type='Access Denied'")
    access_denied = curseur.fetchone()[0]

    # 6. إحصائيات المبيان (Chart)
    curseur.execute("SELECT attack_type, COUNT(*) FROM alerts GROUP BY attack_type")
    event_stats = curseur.fetchall()

    conn.close()
    return log_count, alert_count, alerts, all_logs, failed_logins, access_denied, event_stats

@app.route("/api/data")
def api_data():
    try:
        # هنا كنستعملو الدالة المساعدة باش نعمرو المتغيرات
        log_count, alert_count, alerts, all_logs, failed_logins, access_denied, event_stats = get_data_from_db()
        
        return jsonify({
            "log_count": log_count,
            "alert_count": alert_count,
            "alerts": alerts,
            "all_logs": all_logs,       
            "failed_logins": failed_logins,
            "access_denied": access_denied,
            "event_stats": event_stats
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/")
def dashboard():
    return render_template("dashboard.html")

@app.route("/api/clear_logs", methods=["POST"])
def clear_logs():
    try:
        conn = s3.connect(DB_PATH)
        curseur = conn.cursor()
        curseur.execute("DELETE FROM logs")
        curseur.execute("DELETE FROM alerts")
        conn.commit()
        conn.close()

        if os.path.exists("logs/auth.log"):
            with open("logs/auth.log", "w") as f:
                f.truncate(0)

        return jsonify({"status": "success", "message": "System reset successful"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, port=5000)