"""
modules/watchdog.py
====================
8 détecteurs intégrés. Silencieux par défaut —
c'est main.py qui gère l'affichage et la DB.

Usage dans main.py (inchangé) :
    wdog = Watchdog()
    alerts = wdog.analyze(line)   # → list[Alert]
    for a in alerts:
        insert_log(...)
        insert_alert(...)
"""

import re
import threading
from collections import defaultdict
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Optional


# ─────────────────────────────────────────────
#  Alert
# ─────────────────────────────────────────────

@dataclass
class Alert:
    attack_type: str
    severity: str               # Low | Medium | High | Critical
    source_ip: Optional[str]
    description: str
    raw_line: str
    timestamp: str = field(
        default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )


# ─────────────────────────────────────────────
#  IP extraction (multi-format)
# ─────────────────────────────────────────────

_IP_PATTERNS = [
    re.compile(r"source[_\s]ip\s*=\s*(?P<ip>\d{1,3}(?:\.\d{1,3}){3})", re.I),
    re.compile(r"SRC=(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"),
    re.compile(r"from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})", re.I),
    re.compile(r"rhost=(?P<ip>\d{1,3}(?:\.\d{1,3}){3})", re.I),
    re.compile(r"client\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})", re.I),
    re.compile(r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"),   # fallback
]

def _extract_ip(line: str) -> Optional[str]:
    for pat in _IP_PATTERNS:
        m = pat.search(line)
        if m:
            return m.group("ip")
    return None


# ─────────────────────────────────────────────
#  Base detector
# ─────────────────────────────────────────────

class BaseDetector:
    name     = "Base"
    severity = "Low"

    def analyze(self, line: str) -> Optional[Alert]:
        raise NotImplementedError

    def _alert(self, line: str, description: str, severity: str = None) -> Alert:
        return Alert(
            attack_type=self.name,
            severity=severity or self.severity,
            source_ip=_extract_ip(line),
            description=description,
            raw_line=line.strip(),
        )


# ─────────────────────────────────────────────
#  1. SQL Injection
# ─────────────────────────────────────────────

class SQLInjectionDetector(BaseDetector):
    name     = "SQL Injection"
    severity = "Critical"

    PATTERNS = [
        (re.compile(r"SQL_QUERY_FAILED", re.I),                                   "Query failure"),
        (re.compile(r"\bUNION\b.{0,30}\bSELECT\b", re.I),                        "UNION SELECT"),
        (re.compile(r"\bSELECT\b.{0,30}\bFROM\b", re.I),                         "SELECT FROM"),
        (re.compile(r"(--|#|/\*).{0,30}(DROP|ALTER|TRUNCATE)", re.I),             "Comment + DDL"),
        (re.compile(r"'\s*(OR|AND)\s*'?\d+'?\s*=\s*'?\d+'?", re.I),              "OR/AND tautology"),
        (re.compile(r"\bOR\b\s+1\s*=\s*1", re.I),                                "OR 1=1"),
        (re.compile(r"(SLEEP|BENCHMARK|WAITFOR)\s*\(", re.I),                     "Time-based blind"),
        (re.compile(r"(?:SELECT|WHERE|FROM|AND|OR)\b.*?0x[0-9a-f]{4,}", re.I),   "Hex encoding"),
        (re.compile(r"INFORMATION_SCHEMA|SYS\.TABLES|PG_TABLES", re.I),           "Schema enum"),
        (re.compile(r"LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE", re.I),           "File read/write"),
    ]

    def analyze(self, line: str) -> Optional[Alert]:
        matched = [lbl for pat, lbl in self.PATTERNS if pat.search(line)]
        if not matched:
            return None
        sev = "Critical" if len(matched) >= 2 else "High"
        return self._alert(line, f"SQL injection : {', '.join(matched)}", sev)


# ─────────────────────────────────────────────
#  2. Brute Force
# ─────────────────────────────────────────────

class BruteForceDetector(BaseDetector):
    name     = "Brute Force"
    severity = "High"

    PATTERNS = [
        re.compile(r"LOGIN_FAILED", re.I),
        re.compile(r"Failed password for .+ from", re.I),
        re.compile(r"Invalid user .+ from", re.I),
        re.compile(r"authentication failure.+rhost=", re.I),
        re.compile(r"\d{1,3}(?:\.\d{1,3}){3}.+\s401\s", re.I),
    ]

    def __init__(self, threshold: int = 5, window: int = 60, cooldown: int = 30):
        self.threshold = threshold
        self.window    = window
        self.cooldown  = cooldown
        self._attempts: dict[str, list[datetime]] = defaultdict(list)
        self._last_alert: dict[str, datetime]     = {}
        self._lock = threading.Lock()

    def analyze(self, line: str) -> Optional[Alert]:
        if not any(p.search(line) for p in self.PATTERNS):
            return None

        ip  = _extract_ip(line) or "unknown"
        now = datetime.now()

        with self._lock:
            cutoff = now - timedelta(seconds=self.window)
            self._attempts[ip] = [t for t in self._attempts[ip] if t > cutoff]
            self._attempts[ip].append(now)
            count = len(self._attempts[ip])

            if count < self.threshold:
                return None
            last = self._last_alert.get(ip)
            if last and (now - last).total_seconds() < self.cooldown:
                return None
            self._last_alert[ip] = now

        sev = "Critical" if count >= self.threshold * 3 else "High"
        return self._alert(
            line,
            f"{count} échecs d'auth depuis {ip} en {self.window}s",
            sev,
        )


# ─────────────────────────────────────────────
#  3. Port Scanning
# ─────────────────────────────────────────────

class PortScanDetector(BaseDetector):
    name     = "Port Scanning"
    severity = "Medium"

    IPTABLES_RE = re.compile(r"SRC=(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*DPT=(?P<port>\d+)", re.I)
    CONN_RE     = re.compile(r"CONNECTION_ATTEMPT|SCAN", re.I)
    SCANNER_RE  = re.compile(r"(nmap|masscan|zmap|nikto|zgrab)", re.I)

    def __init__(self, port_threshold: int = 15, window: int = 10, cooldown: int = 20):
        self.port_threshold = port_threshold
        self.window         = window
        self.cooldown       = cooldown
        self._seen: dict[str, dict[str, datetime]] = defaultdict(dict)
        self._last_alert: dict[str, datetime]      = {}
        self._lock = threading.Lock()

    def analyze(self, line: str) -> Optional[Alert]:
        if self.SCANNER_RE.search(line):
            return self._alert(line, "Signature de scanner réseau détectée", "High")

        ip, port = None, None
        m = self.IPTABLES_RE.search(line)
        if m:
            ip, port = m.group("ip"), m.group("port")
        elif self.CONN_RE.search(line):
            ip = _extract_ip(line)
            pm = re.search(r":(\d+)", line)
            port = pm.group(1) if pm else "?"

        if not ip:
            return None

        now = datetime.now()
        with self._lock:
            cutoff = now - timedelta(seconds=self.window)
            self._seen[ip] = {p: t for p, t in self._seen[ip].items() if t > cutoff}
            if port:
                self._seen[ip][port] = now
            unique = len(self._seen[ip])

            if unique < self.port_threshold:
                return None
            last = self._last_alert.get(ip)
            if last and (now - last).total_seconds() < self.cooldown:
                return None
            self._last_alert[ip] = now

        sev = "Critical" if unique >= self.port_threshold * 2 else "Medium"
        return self._alert(line, f"{unique} ports sondés par {ip} en {self.window}s", sev)


# ─────────────────────────────────────────────
#  4. Access Denied
# ─────────────────────────────────────────────

class AccessDeniedDetector(BaseDetector):
    name     = "Access Denied"
    severity = "Medium"

    DENIED_PATTERNS = [
        re.compile(r"ACCESS_DENIED", re.I),
        re.compile(r"Permission denied", re.I),
        re.compile(r"HTTP/\d\.\d\"\s+403\b", re.I),
        re.compile(r"(unauthorized|forbidden).{0,30}(resource|path|file)", re.I),
    ]
    SENSITIVE_RE = re.compile(
        r"(/etc/(passwd|shadow|sudoers)|/root/|\.ssh/|"
        r"/admin|/wp-admin|\.env|/config)", re.I
    )

    def analyze(self, line: str) -> Optional[Alert]:
        is_denied = any(p.search(line) for p in self.DENIED_PATTERNS)
        hit_sensitive = self.SENSITIVE_RE.search(line)
        
        if not is_denied and not hit_sensitive:
            return None
            
        if is_denied and hit_sensitive:
            sev = "Critical"
            desc = f"Accès REFUSÉ à une ressource sensible : {hit_sensitive.group(0)}"
        elif hit_sensitive:
            sev = "High"
            desc = f"Accès/Référence à une ressource sensible : {hit_sensitive.group(0)}"
        else:
            sev = "Medium"
            desc = "Accès refusé détecté"
            
        return self._alert(line, desc, sev)


# ─────────────────────────────────────────────
#  5. DDoS
# ─────────────────────────────────────────────

class DDoSDetector(BaseDetector):
    name     = "DDoS Attempt"
    severity = "Critical"

    FLOOD_RE = re.compile(r"INBOUND_FLOOD", re.I)

    def __init__(self, rate_threshold: int = 100, window: int = 5, cooldown: int = 60):
        self.rate_threshold = rate_threshold
        self.window         = window
        self.cooldown       = cooldown
        self._hits: dict[str, list[datetime]] = defaultdict(list)
        self._last_alert: dict[str, datetime] = {}
        self._lock = threading.Lock()

    def analyze(self, line: str) -> Optional[Alert]:
        if self.FLOOD_RE.search(line):
            return self._alert(line, "Signature INBOUND_FLOOD détectée")

        ip = _extract_ip(line)
        if not ip:
            return None

        now = datetime.now()
        with self._lock:
            cutoff = now - timedelta(seconds=self.window)
            self._hits[ip] = [t for t in self._hits[ip] if t > cutoff]
            self._hits[ip].append(now)
            count = len(self._hits[ip])

            if count < self.rate_threshold:
                return None
            last = self._last_alert.get(ip)
            if last and (now - last).total_seconds() < self.cooldown:
                return None
            self._last_alert[ip] = now

        return self._alert(line, f"Taux anormal : {count} hits de {ip} en {self.window}s")


# ─────────────────────────────────────────────
#  6. Ransomware
# ─────────────────────────────────────────────

class RansomwareDetector(BaseDetector):
    name     = "Ransomware"
    severity = "Critical"

    PATTERNS = [
        (re.compile(r"FILE_ENCRYPTED|MASSIVE FILE MODIFICATION", re.I), "Chiffrement massif"),
        (re.compile(r"\.(locked|encrypted|enc|crypt|wncry|cerber)\b", re.I), "Extension suspecte"),
        (re.compile(r"vssadmin.*(delete|resize).*(shadow|copies)", re.I),    "Shadow copy supprimée"),
        (re.compile(r"(bcdedit|wbadmin).*(off|delete)", re.I),              "Recovery désactivé"),
        (re.compile(r"README.*DECRYPT|HOW_TO_DECRYPT|RANSOM_NOTE", re.I),   "Note de rançon"),
    ]

    def analyze(self, line: str) -> Optional[Alert]:
        for pat, label in self.PATTERNS:
            if pat.search(line):
                return self._alert(line, f"Indicateur ransomware : {label}")
        return None


# ─────────────────────────────────────────────
#  7. Credential Stuffing
# ─────────────────────────────────────────────

class CredentialStuffingDetector(BaseDetector):
    name     = "Credential Stuffing"
    severity = "High"

    DIRECT_RE  = re.compile(r"LOGIN_ATTEMPT_MANY_ACCOUNTS", re.I)
    ATTEMPT_RE = re.compile(r"(login|auth|signin).{0,30}(attempt|failed|error)", re.I)
    USER_RE    = re.compile(r"(user|username|account)[=:\s]+(\S+)", re.I)

    def __init__(self, account_threshold: int = 10, window: int = 60, cooldown: int = 30):
        self.account_threshold = account_threshold
        self.window            = window
        self.cooldown          = cooldown
        self._accounts: dict[str, dict[str, datetime]] = defaultdict(dict)
        self._last_alert: dict[str, datetime]          = {}
        self._lock = threading.Lock()

    def analyze(self, line: str) -> Optional[Alert]:
        if self.DIRECT_RE.search(line):
            return self._alert(line, "Credential stuffing détecté (signature directe)")

        if not self.ATTEMPT_RE.search(line):
            return None

        ip = _extract_ip(line)
        if not ip:
            return None

        user_m   = self.USER_RE.search(line)
        username = user_m.group(2) if user_m else line[:30]
        now      = datetime.now()

        with self._lock:
            cutoff = now - timedelta(seconds=self.window)
            self._accounts[ip] = {
                u: t for u, t in self._accounts[ip].items() if t > cutoff
            }
            self._accounts[ip][username] = now
            unique = len(self._accounts[ip])

            if unique < self.account_threshold:
                return None
            last = self._last_alert.get(ip)
            if last and (now - last).total_seconds() < self.cooldown:
                return None
            self._last_alert[ip] = now

        sev = "Critical" if unique >= self.account_threshold * 2 else "High"
        return self._alert(line, f"{unique} comptes différents testés depuis {ip}", sev)


# ─────────────────────────────────────────────
#  8. Privilege Escalation
# ─────────────────────────────────────────────

class PrivilegeEscalationDetector(BaseDetector):
    name     = "Privilege Escalation"
    severity = "Critical"

    PATTERNS = [
        (re.compile(r"sudo.*not in sudoers|useradd.*?uid=0", re.I),
         "Signature directe", "Critical"),
        (re.compile(r"sudo.*(command not allowed|not in sudoers|incorrect password)", re.I),
         "Commande sudo refusée", "High"),
        (re.compile(r"su\[.*\].*FAILED", re.I),
         "Échec su", "Medium"),
        (re.compile(r"(chmod|chown)\s+(u\+s|4[0-7]{3}|777)", re.I),
         "SUID / world-writable", "High"),
        (re.compile(r"(open|write).{0,30}/(etc/(passwd|shadow|sudoers))", re.I),
         "Accès fichier sensible", "Critical"),
        (re.compile(r"(dirty[_-]?cow|dirtypipe|polkit|pkexec|CVE-202[0-9]-\d+)", re.I),
         "Exploit kernel connu", "Critical"),
        (re.compile(r"\bld_preload\b|\bld_library_path\b", re.I),
         "Hijack linker dynamique", "High"),
        (re.compile(r"(useradd|usermod|groupadd).{0,80}(sudo|wheel|admin)", re.I),
         "Ajout à groupe privilégié", "Critical"),
        (re.compile(r"passwd\s+root", re.I),
         "Changement mot de passe root", "Critical"),
    ]

    def analyze(self, line: str) -> Optional[Alert]:
        for pat, label, sev in self.PATTERNS:
            if pat.search(line):
                return self._alert(line, f"Escalade de privilèges : {label}", sev)
        return None


# ─────────────────────────────────────────────
#  9. XSS (Cross-Site Scripting)
# ─────────────────────────────────────────────

class XSSDetector(BaseDetector):
    name     = "XSS Attack"
    severity = "High"

    PATTERNS = [
        re.compile(r"<script.*?>", re.I),
        re.compile(r"javascript:", re.I),
        re.compile(r"onerror\s*=", re.I),
        re.compile(r"onload\s*=", re.I),
        re.compile(r"alert\s*\(", re.I),
        re.compile(r"String\.fromCharCode", re.I),
        re.compile(r"eval\s*\(", re.I),
        re.compile(r"document\.cookie", re.I),
    ]

    def analyze(self, line: str) -> Optional[Alert]:
        matched = [p.pattern for p in self.PATTERNS if p.search(line)]
        if not matched:
            return None
        return self._alert(line, f"Tentative XSS détectée : {', '.join(matched)}")

# ─────────────────────────────────────────────
#  Watchdog — orchestrateur principal
# ─────────────────────────────────────────────

class Watchdog:
    """
    Passe chaque ligne à travers les 9 détecteurs.
    Silencieux par défaut : pas de print, pas d'accès DB.
    C'est main.py qui décide quoi faire avec les alertes retournées.
    """

    def __init__(
        self,
        brute_threshold:   int = 5,
        brute_window:      int = 60,
        port_threshold:    int = 15,
        port_window:       int = 10,
        ddos_threshold:    int = 100,
        cred_threshold:    int = 10,
    ):
        self.detectors: list[BaseDetector] = [
            SQLInjectionDetector(),
            BruteForceDetector(brute_threshold, brute_window),
            PortScanDetector(port_threshold, port_window),
            AccessDeniedDetector(),
            DDoSDetector(ddos_threshold),
            RansomwareDetector(),
            CredentialStuffingDetector(cred_threshold),
            PrivilegeEscalationDetector(),
            XSSDetector(),
        ]
        self.alert_history: list[Alert] = []
        self._lock = threading.Lock()

    def analyze(self, line: str) -> list[Alert]:
        """
        Analyse une ligne de log.
        Retourne la liste des alertes détectées (peut être vide).
        Ne print rien, ne touche pas à la DB.
        """
        found: list[Alert] = []
        for detector in self.detectors:
            try:
                alert = detector.analyze(line)
                if alert:
                    found.append(alert)
                    with self._lock:
                        self.alert_history.append(alert)
            except Exception as exc:
                # On log l'erreur sans crasher
                print(f"[Watchdog] Erreur détecteur {detector.name}: {exc}")
        return found

    def analyze_batch(self, lines: list[str]) -> list[Alert]:
        """Analyse une liste de lignes d'un coup."""
        results: list[Alert] = []
        for line in lines:
            results.extend(self.analyze(line))
        return results

    def summary(self) -> str:
        """Retourne un résumé texte des alertes de la session (pour main.py)."""
        from collections import Counter
        with self._lock:
            counts = Counter(a.attack_type for a in self.alert_history)
            total  = len(self.alert_history)

        lines = ["── Watchdog Summary ──"]
        for name, count in counts.most_common():
            lines.append(f"  {name:<25} {count} alerte(s)")
        lines.append(f"  {'TOTAL':<25} {total}")
        return "\n".join(lines)