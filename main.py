"""
CyberWolf SIEM - main.py
Terminal UI with login/register before SIEM starts.
Each user gets their own database.
"""

import os, sys, time, random, sqlite3, getpass
from colorama import init as colorama_init, Fore, Style
colorama_init(autoreset=False)
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from modules.threat_engine import Watchdog
from modules.notifier import add_to_batch

# ── Colors (using colorama — human readable) ─────────────────────────────────
RED     = Fore.LIGHTRED_EX
YELLOW  = Fore.LIGHTYELLOW_EX
GREEN   = Fore.LIGHTGREEN_EX
CYAN    = Fore.LIGHTCYAN_EX
BLUE    = Fore.LIGHTBLUE_EX
MAGENTA = Fore.LIGHTMAGENTA_EX
WHITE   = Fore.WHITE
DIM     = Style.DIM
BOLD    = Style.BRIGHT
RESET   = Style.RESET_ALL

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

# ── DB helpers ────────────────────────────────────────────────────────────────
USERS_DB = "database/users.db"
LOG_FILE = "logs/auth.log"
last_alerts_cache = {}
COOLDOWN = 20

# These get set after login
CURRENT_USER_ID = None
DB_PATH = None

def connect_users_db():
    os.makedirs("database", exist_ok=True)
    conn = sqlite3.connect(USERS_DB)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0)""")
    conn.commit()
    return conn

def connect_user_data_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn

def insert_log(timestamp, event, attack_type):
    try:
        conn = connect_user_data_db()
        conn.execute("INSERT INTO logs(timestamp,event,attack_type) VALUES(?,?,?)",
                     (timestamp, event, attack_type))
        conn.commit(); conn.close()
    except Exception as error:
        print(f"{RED}[-] Log DB: {error}{RESET}")

def insert_alert(message, severity, attack_type, source_ip=None):
    try:
        add_to_batch(attack_type, severity, message)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = connect_user_data_db()
        try:
            conn.execute(
                "INSERT INTO alerts(message,severity,attack_type,source_ip,timestamp) VALUES(?,?,?,?,?)",
                (message, severity, attack_type, source_ip, timestamp))
        except Exception:
            conn.execute(
                "INSERT INTO alerts(message,severity,attack_type) VALUES(?,?,?)",
                (message, severity, attack_type))
        conn.commit(); conn.close()
    except Exception as error:
        print(f"{RED}[-] Alert DB: {error}{RESET}")

# ── Banner ─────────────────────────────────────────────────────────────────────
BANNER = f"""
{CYAN}{BOLD}
  ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██╗    ██╗ ██████╗ ██╗     ███████╗
 ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██║    ██║██╔═══██╗██║     ██╔════╝
 ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║ █╗ ██║██║   ██║██║     █████╗
 ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║███╗██║██║   ██║██║     ██╔══╝
 ╚██████╗   ██║   ██████╔╝███████╗██║  ██║╚███╔███╔╝╚██████╔╝███████╗██║
  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝  ╚═════╝ ╚══════╝╚═╝
{RESET}{DIM}                   S I E M  ·  S E C U R I T Y  ·  P L A T F O R M{RESET}
{CYAN}{'═'*75}{RESET}"""

# ── Terminal Auth ─────────────────────────────────────────────────────────────
def terminal_auth():
    """Login or register before SIEM starts. Returns (user_id, email, is_admin)."""
    global CURRENT_USER_ID, DB_PATH
    while True:
        clear_screen()
        print(BANNER)
        print(f"\n{WHITE}{BOLD}  AUTHENTICATION REQUIRED{RESET}\n")
        print(f"  {GREEN}[1]{RESET}  Login to existing account")
        print(f"  {CYAN}[2]{RESET}  Register new account")
        print(f"  {RED}[Q]{RESET}  Quit\n")
        print(f"{CYAN}{'─'*75}{RESET}")
        choice = input(f"\n  {WHITE}{BOLD}⟶  Choice: {RESET}").strip().upper()

        if choice == "Q":
            print(f"\n{CYAN}  Goodbye.{RESET}\n"); sys.exit(0)
        elif choice == "1":
            result = do_login()
            if result: return result
        elif choice == "2":
            result = do_register()
            if result: return result
        else:
            print(f"\n  {RED}Invalid choice.{RESET}"); time.sleep(1)

def do_login():
    global CURRENT_USER_ID, DB_PATH
    print(f"\n  {CYAN}── LOGIN ──{RESET}\n")
    email = input(f"  {WHITE}Email: {RESET}").strip().lower()
    password = getpass.getpass(f"  {WHITE}Password: {RESET}")
    conn = connect_users_db(); cursor = conn.cursor()
    cursor.execute("SELECT id,password,is_admin FROM users WHERE email=?", (email,))
    row = cursor.fetchone(); conn.close()
    if row and check_password_hash(row[1], password):
        CURRENT_USER_ID = row[0]
        DB_PATH = f"database/user_{row[0]}/siem.db"
        from init_db import create_user_db
        create_user_db(row[0])
        role = "Admin" if row[2] else "Operator"
        print(f"\n  {GREEN}✔ Welcome back, {email} ({role}){RESET}")
        time.sleep(1.5)
        return (row[0], email, row[2])
    else:
        print(f"\n  {RED}✘ Invalid credentials.{RESET}")
        time.sleep(2)
        return None

def do_register():
    global CURRENT_USER_ID, DB_PATH
    print(f"\n  {CYAN}── REGISTER ──{RESET}\n")
    email = input(f"  {WHITE}Email: {RESET}").strip().lower()
    if not email or "@" not in email:
        print(f"\n  {RED}Invalid email.{RESET}"); time.sleep(1.5); return None
    password = getpass.getpass(f"  {WHITE}Password (min 8 chars): {RESET}")
    if len(password) < 8:
        print(f"\n  {RED}Password too short.{RESET}"); time.sleep(1.5); return None
    confirm = getpass.getpass(f"  {WHITE}Confirm password: {RESET}")
    if password != confirm:
        print(f"\n  {RED}Passwords don't match.{RESET}"); time.sleep(1.5); return None
    try:
        conn = connect_users_db(); cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        is_admin = 1 if cursor.fetchone()[0] == 0 else 0
        hashed = generate_password_hash(password)
        conn.execute("INSERT INTO users(email,password,is_admin) VALUES(?,?,?)",
                     (email, hashed, is_admin))
        conn.commit()
        cursor.execute("SELECT id FROM users WHERE email=?", (email,))
        user_id = cursor.fetchone()[0]; conn.close()
        CURRENT_USER_ID = user_id
        DB_PATH = f"database/user_{user_id}/siem.db"
        from init_db import create_user_db
        create_user_db(user_id)
        role = "Admin" if is_admin else "Operator"
        print(f"\n  {GREEN}✔ Account created ({role}). Welcome, {email}!{RESET}")
        time.sleep(1.5)
        return (user_id, email, is_admin)
    except sqlite3.IntegrityError:
        print(f"\n  {RED}Email already registered.{RESET}"); time.sleep(1.5); return None

# ── Attack catalogue ──────────────────────────────────────────────────────────
def random_ip():
    return f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(10,99)}.{random.randint(1,254)}"

ATTACKS = {
    1: {"name":"SQL Injection","icon":"💉","severity":"Critical","color":RED,
        "mitre":"T1190 · Initial Access",
        "description":"Malicious SQL payload injected into a web form or URL parameter.\nGoal: extract database contents, bypass authentication, drop tables.",
        "payload": lambda: f"SQL_QUERY_FAILED: source_ip={random_ip()} input='UNION SELECT NULL,username,password FROM users--'",
        "action":"🔴 Block source IP · Enable WAF · Audit DB queries · Patch endpoints"},
    2: {"name":"Brute Force","icon":"🔑","severity":"High","color":YELLOW,
        "mitre":"T1110 · Credential Access",
        "description":"Repeated authentication failures from a single IP address.\nGoal: guess credentials to gain unauthorised access.",
        "payload": lambda ip: f"LOGIN_FAILED for user admin from source_ip={ip}",
        "burst":6,"use_fixed_ip":True,
        "action":"🔒 Lock account · Enforce MFA · Rate-limit auth · Blocklist IP"},
    3: {"name":"Port Scanning","icon":"📡","severity":"Medium","color":BLUE,
        "mitre":"T1046 · Discovery",
        "description":"Systematic probing of ports to map exposed services.\nGoal: identify attack surface before exploitation.",
        "payload": lambda ip: f"CONNECTION_ATTEMPT: source_ip={ip} target_port={random.randint(20,65535)} status=REFUSED",
        "burst":20,"use_fixed_ip":True,
        "action":"🛡 Enable IDS · Close unnecessary ports · Block scanner IP"},
    4: {"name":"Access Denied","icon":"🚫","severity":"Medium","color":MAGENTA,
        "mitre":"T1078 · Defense Evasion",
        "description":"Unauthorised attempt to access a restricted or sensitive resource.\nGoal: reach files, admin panels, or config outside allowed scope.",
        "payload": lambda: f"ACCESS_DENIED: user=guest source_ip={random_ip()} resource=/etc/shadow",
        "action":"📋 Review ACLs · Verify privileges · Check insider threat · Audit logs"},
    5: {"name":"DDoS Attempt","icon":"🌊","severity":"Critical","color":RED,
        "mitre":"T1499 · Impact",
        "description":"Volumetric flood of packets from a single or distributed source.\nGoal: exhaust bandwidth or CPU to cause service outage.",
        "payload": lambda: f"INBOUND_FLOOD: source_ip={random_ip()} packets={random.randint(5000,50000)} size=64KB",
        "burst":1,
        "action":"⚡ Rate-limit · Activate mitigation · Contact ISP · Monitor BW"},
    6: {"name":"Ransomware","icon":"🔐","severity":"Critical","color":RED,
        "mitre":"T1486 · Impact",
        "description":"Mass file encryption or shadow-copy deletion detected.\nGoal: encrypt victim data and demand ransom payment.",
        "payload": lambda: f"FILE_ENCRYPTED: path=/home/user/data_{random.randint(1,999)}.docx.locked extension=.crypt",
        "action":"🚨 ISOLATE NOW · Snapshot disks · Notify IR team · Check backups"},
    7: {"name":"Credential Stuffing","icon":"👥","severity":"High","color":YELLOW,
        "mitre":"T1110.004 · Credential Access",
        "description":"Bulk login attempts across many different accounts from one IP.\nGoal: validate breached credential lists against live systems.",
        "payload": lambda: f"LOGIN_ATTEMPT_MANY_ACCOUNTS: source_ip={random_ip()} status=failed",
        "action":"🔁 Force reset · Enable CAPTCHA · Monitor credential leaks · Rate-limit"},
    8: {"name":"Privilege Escalation","icon":"⬆️","severity":"Critical","color":RED,
        "mitre":"T1068 · Privilege Escalation",
        "description":"Attempt to gain root or admin rights from a low-privilege account.\nGoal: obtain full system control to persist and move laterally.",
        "payload": lambda: f"sudo: user hacker not in sudoers ; COMMAND=/usr/bin/su root",
        "action":"🔑 Revoke privs · Audit sudo logs · Patch kernel · Review user roles"},
    9: {"name":"XSS Attack","icon":"💻","severity":"High","color":YELLOW,
        "mitre":"T1189 · Initial Access",
        "description":"Cross-site scripting payload detected in HTTP request parameter.\nGoal: steal cookies/session tokens or deface web applications.",
        "payload": lambda: f"HTTP GET /search?q=<script>alert(document.cookie)</script> from {random_ip()}",
        "action":"🛡 Sanitize inputs · Set CSP headers · Enable WAF XSS rules · Audit code"},
    10:{"name":"Full Siege (All Attacks)","icon":"💣","severity":"Critical","color":RED,
        "mitre":"Multiple TTPs",
        "description":"Launches all 9 attack types in rapid succession.\nSimulates a coordinated Advanced Persistent Threat (APT) campaign.",
        "payload":None,
        "action":"🚨 Full incident response · Isolate systems · Escalate to CISO"},
}

# ── Terminal helpers ───────────────────────────────────────────────────────────
def draw_box(title, lines, color=CYAN, width=71):
    print(f"\n{color}╔{'═'*(width-2)}╗")
    label = f"  {title}  "
    padding = width - 2 - len(label)
    print(f"║{label}{'─'*padding}║")
    print(f"╠{'═'*(width-2)}╣{RESET}")
    for line in lines:
        text = str(line)
        for sub_line in text.split("\n"):
            sub_line = sub_line[:width-4]
            print(f"{color}║{RESET}  {WHITE}{sub_line:<{width-4}}{color}║{RESET}")
    print(f"{color}╚{'═'*(width-2)}╝{RESET}")

def spinner(message, seconds=1.5):
    chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    end_time = time.time() + seconds; index = 0
    while time.time() < end_time:
        print(f"\r{CYAN}{chars[index%len(chars)]}{RESET} {message}   ", end="", flush=True)
        time.sleep(0.08); index += 1
    print(f"\r{GREEN}✔{RESET} {message} — {GREEN}Done{RESET}   ")

def severity_badge(severity):
    colors = {"Critical": RED, "High": YELLOW, "Medium": BLUE, "Low": GREEN}
    color = colors.get(severity, WHITE)
    return f"{color}[{severity}]{RESET}"

def progress_bar(label, total=30, color=CYAN):
    sys.stdout.write(f"  {label} {color}[")
    for i in range(total):
        time.sleep(0.03); sys.stdout.write("█"); sys.stdout.flush()
    sys.stdout.write(f"]{RESET}\n")

# ── Show main menu ────────────────────────────────────────────────────────────
def show_menu(user_email):
    clear_screen(); print(BANNER)
    print(f"  {DIM}Logged in as: {GREEN}{user_email}{RESET}\n")
    print(f"  {WHITE}{BOLD}  ATTACK SIMULATION MENU{RESET}  {DIM}(1-10 · M to monitor · Q to quit){RESET}\n")
    rows = [
        (1, "SQL Injection","Critical",RED),(2, "Brute Force","High",YELLOW),
        (3, "Port Scanning","Medium",BLUE),(4, "Access Denied","Medium",MAGENTA),
        (5, "DDoS Attempt","Critical",RED),(6, "Ransomware","Critical",RED),
        (7, "Credential Stuffing","High",YELLOW),(8, "Privilege Escalation","Critical",RED),
        (9, "XSS Attack","High",YELLOW),(10,"Full Siege (All)","Critical",RED),
    ]
    print(f"  {DIM}┌──────┬──────────────────────────────────┬─────────────┐{RESET}")
    print(f"  {DIM}│  #   │  Attack Type                     │  Severity   │{RESET}")
    print(f"  {DIM}├──────┼──────────────────────────────────┼─────────────┤{RESET}")
    for number, name, severity, color in rows:
        num_col = f"  [{color}{BOLD}{number:>2}{RESET}]"
        name_col = f"  {WHITE}{name:<34}{RESET}"
        sev_col = f"{color}{severity:<13}{RESET}"
        print(f"  {DIM}│{RESET}{num_col} {DIM}│{RESET}{name_col}{DIM}│{RESET}  {sev_col}{DIM}│{RESET}")
    print(f"  {DIM}└──────┴──────────────────────────────────┴─────────────┘{RESET}")
    print(f"\n  {GREEN}[M]{RESET}  Start Real-Time Log Monitor")
    print(f"  {RED}[Q]{RESET}  Quit")
    print(f"\n{CYAN}{'─'*75}{RESET}")
    return input(f"\n  {WHITE}{BOLD}⟶  Your choice: {RESET}").strip().upper()

# ── Run a single attack ───────────────────────────────────────────────────────
def run_attack(attack_id, watchdog):
    attack = ATTACKS.get(attack_id)
    if not attack: return
    if attack_id == 10: run_full_siege(watchdog); return
    clear_screen(); print(BANNER)
    draw_box(f"  {attack['icon']}  ATTACK #{attack_id} — {attack['name']}  ",
        [f"{'Severity':<18} {severity_badge(attack['severity'])}",
         f"{'MITRE ATT&CK':<18} {CYAN}{attack['mitre']}{RESET}","",
         f"{'Description':<18}",attack["description"],"",
         f"{'Recommended':<18}",attack["action"]], color=attack["color"])
    burst = attack.get("burst", 1); source_ip = random_ip()
    print(f"\n  {DIM}Injecting {burst} log line(s) into {LOG_FILE} …{RESET}\n")
    os.makedirs("logs", exist_ok=True); detected = []
    progress_bar(f"Injecting {burst} event(s)", total=burst, color=attack["color"])
    use_fixed = attack.get("use_fixed_ip", False)
    for i in range(burst):
        line = (attack["payload"](source_ip) if use_fixed else attack["payload"]()) + "\n"
        with open(LOG_FILE, "a") as log_file: log_file.write(line)
        alerts = watchdog.analyze(line)
        for alert in alerts:
            detected.append(alert)
            now = datetime.now(); timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
            cache_key = f"{alert.attack_type}_{alert.source_ip}"
            last_time = last_alerts_cache.get(cache_key)
            if last_time is None or (now - last_time).total_seconds() > COOLDOWN:
                last_alerts_cache[cache_key] = now
                insert_alert(f"{alert.description} at {now.strftime('%H:%M:%S')}",
                            alert.severity, alert.attack_type, source_ip=alert.source_ip)
                insert_log(timestamp, alert.description, alert.attack_type)
            else:
                insert_log(timestamp, f"[DUP] {alert.description}", alert.attack_type)
        time.sleep(0.05)
    print()
    if detected:
        print(f"  {GREEN}{BOLD}✔ DETECTED — {len(detected)} alert(s) fired:{RESET}\n")
        seen_types = set()
        for alert in detected:
            if alert.attack_type not in seen_types:
                seen_types.add(alert.attack_type)
                sev_color = {"Critical":RED,"High":YELLOW,"Medium":BLUE,"Low":GREEN}.get(alert.severity, WHITE)
                print(f"    {sev_color}▶ {alert.attack_type:<25} [{alert.severity}]{RESET}")
                print(f"      {DIM}{alert.description[:65]}{RESET}")
                if alert.source_ip: print(f"      {CYAN}Source IP:{RESET} {alert.source_ip}")
                print()
        print(f"  {GREEN}Dashboard updated — check http://127.0.0.1:5000{RESET}")
    else:
        print(f"  {YELLOW}⚠  No alerts fired (threshold not reached). Try 'Full Siege'.{RESET}")
    print(f"\n{CYAN}{'─'*75}{RESET}")
    input(f"\n  {DIM}Press ENTER to return to menu…{RESET}")

# ── Full siege ────────────────────────────────────────────────────────────────
def run_full_siege(watchdog):
    clear_screen(); print(BANNER)
    draw_box("  💣  FULL SIEGE — APT SIMULATION  ",
        ["Severity       CRITICAL","MITRE ATT&CK   Multiple TTPs — Coordinated Campaign","",
         "Launching all 9 attack types in rapid succession.",
         "This simulates an Advanced Persistent Threat (APT) campaign.","",
         "Monitor: http://127.0.0.1:5000"], color=RED)
    print(); os.makedirs("logs", exist_ok=True)
    for attack_num in range(1, 10):
        attack = ATTACKS[attack_num]; burst = attack.get("burst", 1)
        use_fixed = attack.get("use_fixed_ip", False); siege_ip = random_ip()
        sys.stdout.write(f"  {attack['color']}{attack['icon']}  {attack['name']:<26}{RESET} "); sys.stdout.flush()
        for _ in range(burst):
            line = (attack["payload"](siege_ip) if use_fixed else attack["payload"]()) + "\n"
            with open(LOG_FILE, "a") as log_file: log_file.write(line)
            alerts = watchdog.analyze(line)
            for alert in alerts:
                now = datetime.now(); timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
                cache_key = f"{alert.attack_type}_{alert.source_ip}"
                last_time = last_alerts_cache.get(cache_key)
                if last_time is None or (now - last_time).total_seconds() > COOLDOWN:
                    last_alerts_cache[cache_key] = now
                    insert_alert(f"{alert.description} at {now.strftime('%H:%M:%S')}",
                                alert.severity, alert.attack_type, source_ip=alert.source_ip)
                    insert_log(timestamp, alert.description, alert.attack_type)
            time.sleep(0.02)
        print(f"{GREEN}✔ Done{RESET}"); time.sleep(0.3)
    print(f"\n  {GREEN}{BOLD}Siege complete — all events sent to dashboard.{RESET}")
    print(f"  {CYAN}Check alerts at http://127.0.0.1:5000{RESET}")
    print(f"\n{CYAN}{'─'*75}{RESET}")
    input(f"\n  {DIM}Press ENTER to return to menu…{RESET}")

# ── Real-time monitor ─────────────────────────────────────────────────────────
def monitor_realtime(watchdog):
    clear_screen(); print(BANNER)
    print(f"\n  {GREEN}{BOLD}[MONITOR]{RESET} Watching: {CYAN}{os.path.abspath(LOG_FILE)}{RESET}")
    print(f"  {DIM}Press Ctrl+C to stop and return to menu{RESET}\n")
    print(f"{CYAN}{'═'*75}{RESET}")
    os.makedirs("logs", exist_ok=True)
    if not os.path.exists(LOG_FILE): open(LOG_FILE, "a").close()
    with open(LOG_FILE, "r") as log_handle:
        log_handle.seek(0, os.SEEK_END); last_position = log_handle.tell()
        try:
            while True:
                current_size = os.path.getsize(LOG_FILE)
                if current_size < last_position:
                    print(f"\n  {YELLOW}[!] Log reset detected — repositioning…{RESET}")
                    log_handle.seek(0); last_position = 0
                line = log_handle.readline()
                if not line: last_position = log_handle.tell(); time.sleep(0.5); continue
                last_position = log_handle.tell(); now = datetime.now()
                timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
                time_short = now.strftime("%H:%M:%S")
                alerts = watchdog.analyze(line)
                if alerts:
                    for alert in alerts:
                        sev_color = {"Critical":RED,"High":YELLOW,"Medium":BLUE,"Low":GREEN}.get(alert.severity, WHITE)
                        print(f"  {sev_color}▶ [{time_short}] {alert.attack_type:<22} [{alert.severity}]{RESET}")
                        print(f"    {DIM}{alert.description[:70]}{RESET}")
                        if alert.source_ip: print(f"    {CYAN}IP:{RESET} {alert.source_ip}")
                        cache_key = f"{alert.attack_type}_{alert.source_ip}"
                        last_time = last_alerts_cache.get(cache_key)
                        if last_time is None or (now - last_time).total_seconds() > COOLDOWN:
                            last_alerts_cache[cache_key] = now
                            insert_alert(f"{alert.description} at {time_short}",
                                        alert.severity, alert.attack_type, source_ip=alert.source_ip)
                        insert_log(timestamp, alert.description, alert.attack_type)
                else:
                    print(f"  {DIM}  [{time_short}] {line.strip()[:70]}{RESET}")
                    insert_log(timestamp, line.strip(), "Normal")
        except KeyboardInterrupt:
            print(f"\n\n  {YELLOW}[*] Monitor stopped.{RESET}")
            print(watchdog.summary()); time.sleep(1.5)

# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # colorama handles Windows color support automatically
    colorama_init()

    # Auth first
    user_id, user_email, is_admin = terminal_auth()
    watchdog = Watchdog(brute_threshold=3, port_threshold=15, ddos_threshold=20, cred_threshold=3)

    while True:
        choice = show_menu(user_email)
        if choice == "Q":
            clear_screen()
            print(f"\n{CYAN}  CyberWolf SIEM — Session ended. Stay secure.{RESET}\n")
            break
        elif choice == "M":
            monitor_realtime(watchdog)
        elif choice.isdigit() and 1 <= int(choice) <= 10:
            run_attack(int(choice), watchdog)
        else:
            print(f"\n  {RED}Invalid choice. Enter 1-10, M, or Q.{RESET}"); time.sleep(1.2)