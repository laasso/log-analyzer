#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, re, gzip, socket, sys
from dotenv import load_dotenv
from glob import glob
from datetime import datetime, timedelta
from ipaddress import ip_address, ip_network
from collections import Counter
from email.message import EmailMessage

load_dotenv()

MAIL_TO      = os.getenv("MAIL_TO", "root@localhost").split(",")
MAIL_FROM    = os.getenv("MAIL_FROM", f"root@{socket.gethostname()}")
MAIL_SUBJECT = os.getenv("MAIL_SUBJECT", "[logwatch] Informe de ataques")
USE_SENDMAIL = os.getenv("USE_SENDMAIL", "true").lower() == "true"
SMTP_HOST    = os.getenv("SMTP_HOST")
SMTP_PORT    = int(os.getenv("SMTP_PORT", 587))
SMTP_USER    = os.getenv("SMTP_USER")
SMTP_PASS    = os.getenv("SMTP_PASS")

NET_PREFIX  = int(os.getenv("NET_PREFIX", 16))
SERVICES    = [s.strip() for s in os.getenv("SERVICES", "Servidor Web,Servidor SSH,Servidor SMTP").split(",")]
WEB_LOG_PATHS  = [p.strip() for p in os.getenv("WEB_LOG_PATHS", "/var/log/nginx/access.log*,/var/log/apache2/access.log*").split(",")]
SSH_LOG_PATHS  = [p.strip() for p in os.getenv("SSH_LOG_PATHS", "/var/log/auth.log*,/var/log/secure*").split(",")]
SMTP_LOG_PATHS = [p.strip() for p in os.getenv("SMTP_LOG_PATHS", "/var/log/mail.log*,/var/log/maillog*").split(",")]

# ========= Helpers ==========
def open_log(p): return gzip.open(p, "rt", errors="ignore") if p.endswith(".gz") else open(p, "r", errors="ignore")
def collect(globs): 
    files = []
    for g in globs: files += glob(g)
    return sorted(set(files))
def is_private(ip):
    try: return ip_address(ip).is_private
    except: return True

# ========= Parsers ==========
def parse_web(line):
    m = re.search(r'(?:(?<=^)|(?<=\brealip=))(?P<ip>(?:\d{1,3}\.){3}\d{1,3})', line)
    if not m: return None, False
    ip = m.group("ip")
    sm = re.search(r'"\w+\s+([^"]+?)\s+HTTP/[^"]+"\s+(\d{3})\s', line)
    if not sm: return ip, False
    url, status = sm.group(1), int(sm.group(2))
    suspicious = [r"/wp-login", r"/xmlrpc", r"/\.git", r"\.\./", r"/etc/passwd", r"select", r"<script", r"cmd="]
    is_attack = status in {400,401,403,404,405,444,500,501,502,503}
    if not is_attack:
        for r_ in suspicious:
            if re.search(r_, url, re.I):
                is_attack = True
                break
    return ip, is_attack

def parse_ssh(line):
    if not re.search(r"(Failed password|Invalid user|BREAK-IN)", line):
        return None, False
    m = re.search(r'from\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3})', line)
    return (m.group("ip"), True) if m else (None, False)

def parse_smtp(line):
    if not re.search(r"(authentication failed|NOQUEUE: reject|lost connection)", line):
        return None, False
    m = re.search(r'\[(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\]', line)
    return (m.group("ip"), True) if m else (None, False)

# ========= Análisis ==========
def analyze():
    attacks = {"Servidor Web": Counter(), "Servidor SSH": Counter(), "Servidor SMTP": Counter()}
    since = datetime.now() - timedelta(days=1)

    for svc in SERVICES:
        if svc == "Servidor Web": paths, parser = WEB_LOG_PATHS, parse_web
        elif svc == "Servidor SSH": paths, parser = SSH_LOG_PATHS, parse_ssh
        elif svc == "Servidor SMTP": paths, parser = SMTP_LOG_PATHS, parse_smtp
        else: continue

        for p in collect(paths):
            try:
                if datetime.fromtimestamp(os.path.getmtime(p)) < since:
                    continue
                with open_log(p) as fh:
                    for line in fh:
                        match = re.match(r'([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})', line)
                        if match:
                            try:
                                ts = datetime.strptime(match.group(1), "%b %d %H:%M:%S").replace(year=datetime.now().year)
                                if ts < since: continue
                            except Exception: pass
                        ip, ok = parser(line)
                        if ok and ip and not is_private(ip):
                            attacks[svc][ip] += 1
            except Exception as e:
                print(f"[WARN] No se pudo leer {p}: {e}", file=sys.stderr)
    return attacks

# ========= Resumen ==========
def summarize(attacks):
    total = Counter()
    for c in attacks.values(): total.update(c)
    nets = Counter()
    for ip, n in total.items():
        try:
            net = ip_network(f"{ip}/{NET_PREFIX}", strict=False).network_address
            nets[f"{net}/{NET_PREFIX}"] += n
        except: pass
    return total, nets

# ========= HTML Report ==========
def report_html(attacks, total, nets):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hostname = socket.gethostname()

    def table(title, data):
        if not data: return ""
        rows = "".join(f"<tr><td>{ip}</td><td>{count}</td></tr>" for ip, count in data)
        return f"""
        <h3>{title}</h3>
        <table>
          <tr><th>Origen</th><th>Intentos</th></tr>
          {rows}
        </table>
        """

    svc_tables = ""
    for svc, ctr in attacks.items():
        if sum(ctr.values()) == 0: continue
        svc_tables += table(f"🛡️ {svc} ({sum(ctr.values())} ataques)", ctr.most_common(5))

    total_table = table("🌍 IPs más activas (Global)", total.most_common(10))
    net_table   = table("🌐 Redes más activas", nets.most_common(5))

    html = f"""
    <html>
    <head>
    <meta charset="utf-8">
    <style>
      body {{
        font-family: 'Segoe UI', Roboto, sans-serif;
        background-color: #f5f6fa;
        color: #2f3640;
        margin: 0; padding: 20px;
      }}
      h2 {{
        background: #273c75; color: white;
        padding: 10px; border-radius: 8px;
      }}
      h3 {{ color: #192a56; margin-top: 20px; }}
      table {{
        width: 100%; border-collapse: collapse;
        margin-top: 8px; background: white; border-radius: 8px;
        box-shadow: 0 2px 5px rgba(0,0,0,0.1);
      }}
      th, td {{
        padding: 8px 10px; text-align: left;
        border-bottom: 1px solid #eee;
      }}
      th {{ background: #40739e; color: white; }}
      tr:hover {{ background: #f1f2f6; }}
      footer {{
        text-align: center; color: #888; font-size: 12px; margin-top: 20px;
      }}
    </style>
    </head>
    <body>
      <h2>📊 Informe de Ataques — {hostname}</h2>
      <p><strong>🕒 Últimas 24 horas:</strong> {now}</p>
      {svc_tables}
      {total_table}
      {net_table}
      <footer>Generado automáticamente por Logwatch Python</footer>
    </body>
    </html>
    """
    return html

# ========= Envío correo ==========
def send_mail(subject, html_body):
    msg = EmailMessage()
    msg["From"] = MAIL_FROM
    msg["To"] = ", ".join(MAIL_TO)
    msg["Subject"] = subject
    msg.set_content("Tu cliente de correo no soporta HTML.")
    msg.add_alternative(html_body, subtype="html")

    if USE_SENDMAIL and os.path.exists("/usr/sbin/sendmail"):
        import subprocess
        subprocess.Popen(["/usr/sbin/sendmail", "-t", "-oi"], stdin=subprocess.PIPE).communicate(msg.as_bytes())
    else:
        import smtplib
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as s:
            try: s.starttls()
            except Exception: pass
            if SMTP_USER and SMTP_PASS: s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)

# ========= MAIN ==========
if __name__ == "__main__":
    attacks = analyze()
    total, nets = summarize(attacks)
    html = report_html(attacks, total, nets)
    send_mail(MAIL_SUBJECT, html)

