#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import gzip
import socket
import sys
import time
import json
import requests
from pathlib import Path
from glob import glob
from dotenv import load_dotenv
from datetime import datetime, timedelta
from ipaddress import ip_address, ip_network
from collections import Counter
from email.message import EmailMessage


# ---------------------------------------------------------
# CARGAR CONFIG
# ---------------------------------------------------------

load_dotenv()

MAIL_TO      = os.getenv("MAIL_TO", "").split(",")
MAIL_FROM    = os.getenv("MAIL_FROM")
MAIL_SUBJECT = os.getenv("MAIL_SUBJECT", "Informe de actividad 24h")
USE_SENDMAIL = os.getenv("USE_SENDMAIL", "false").lower() == "true"
SMTP_HOST    = os.getenv("SMTP_HOST")
SMTP_PORT    = int(os.getenv("SMTP_PORT", 587))
SMTP_USER    = os.getenv("SMTP_USER")
SMTP_PASS    = os.getenv("SMTP_PASS")

NET_PREFIX     = int(os.getenv("NET_PREFIX", 16))
SERVICES       = [s.strip() for s in os.getenv("SERVICES").split(",")]
WEB_LOG_PATHS  = [p.strip() for p in os.getenv("WEB_LOG_PATHS").split(",")]
SSH_LOG_PATHS  = [p.strip() for p in os.getenv("SSH_LOG_PATHS").split(",")]

CACHE_FILE = Path("./ip-cache.json")
CACHE_TTL  = 7 * 24 * 3600


# ---------------------------------------------------------
# UTILIDADES
# ---------------------------------------------------------

def collect(globs):
    files = []
    for g in globs:
        files.extend(glob(g))
    return sorted(set(files))

def open_log(path):
    return gzip.open(path, "rt", errors="ignore") if path.endswith(".gz") else open(path, "r", errors="ignore")

def is_private(ip):
    try:
        return ip_address(ip).is_private
    except:
        return True


# ---------------------------------------------------------
# PARSEO TIMESTAMP
# ---------------------------------------------------------

# NGINX: [11/Nov/2025:15:21:56 +0000]
def parse_ts_nginx(line):
    m = re.search(r'\[(\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2})', line)
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), "%d/%b/%Y:%H:%M:%S")
    except:
        return None


# SSH: ISO-8601 o syslog
def parse_ts_ssh(line):
    # ISO8601
    m1 = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line)
    if m1:
        try:
            return datetime.fromisoformat(m1.group(1))
        except:
            pass

    # syslog clásico
    m2 = re.match(r"^([A-Z][a-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})", line)
    if m2:
        try:
            return datetime.strptime(m2.group(1), "%b %d %H:%M:%S").replace(year=datetime.now().year)
        except:
            pass

    return None


# ---------------------------------------------------------
# EXTRACCIÓN DE IP
# ---------------------------------------------------------

def extract_ip_web(line):
    m = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
    return m.group(1) if m else None

def extract_ip_ssh(line):
    # “from IP”
    m = re.search(r"from\s+(\d+\.\d+\.\d+\.\d+)", line)
    if m:
        return m.group(1)
    # "[IP]"
    m = re.search(r"\[(\d+\.\d+\.\d+\.\d+)\]", line)
    if m:
        return m.group(1)
    return None


# ---------------------------------------------------------
# ANÁLISIS ÚLTIMAS 24H
# ---------------------------------------------------------

def analyze():
    since = datetime.now() - timedelta(hours=24)
    counts = {"Servidor Web": Counter(), "Servidor SSH": Counter()}

    for svc in SERVICES:
        if svc == "Servidor Web":
            paths = WEB_LOG_PATHS
            parse_ts = parse_ts_nginx
            extract_ip = extract_ip_web

        elif svc == "Servidor SSH":
            paths = SSH_LOG_PATHS
            parse_ts = parse_ts_ssh
            extract_ip = extract_ip_ssh

        else:
            continue

        for path in collect(paths):
            try:
                with open_log(path) as f:
                    for line in f:
                        ts = parse_ts(line)
                        if not ts or ts < since:
                            continue

                        ip = extract_ip(line)
                        if not ip:
                            continue   # ignorar eventos sin IP real

                        if not is_private(ip):
                            counts[svc][ip] += 1

            except Exception as e:
                print(f"[WARN] No se pudo leer {path}: {e}", file=sys.stderr)

    return counts


# ---------------------------------------------------------
# SUMARIOS
# ---------------------------------------------------------

def summarize(counts):
    total = Counter()
    for ctr in counts.values():
        total.update(ctr)

    nets = Counter()
    for ip, n in total.items():
        try:
            net = ip_network(f"{ip}/{NET_PREFIX}", strict=False).network_address
            nets[f"{net}/{NET_PREFIX}"] += n
        except:
            pass

    return total, nets


# ---------------------------------------------------------
# GEOLOCALIZACIÓN
# ---------------------------------------------------------

def load_cache():
    if not CACHE_FILE.exists():
        return {}
    try:
        return json.loads(CACHE_FILE.read_text())
    except:
        return {}

def save_cache(cache):
    try:
        CACHE_FILE.write_text(json.dumps(cache))
    except:
        pass

def geolocate_ips(ip_counter):
    cache = load_cache()
    now = time.time()
    out = {}

    for ip in ip_counter:
        cached = cache.get(ip)
        if cached and now - cached.get("ts", 0) < CACHE_TTL:
            out[ip] = cached
            continue

        try:
            r = requests.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,message,country,city,isp"},
                timeout=5
            )
            data = r.json()
            if data.get("status") == "success":
                info = {
                    "country": data.get("country"),
                    "city": data.get("city"),
                    "isp": data.get("isp"),
                    "ts": now
                }
                cache[ip] = info
                out[ip] = info

        except:
            pass

    save_cache(cache)
    return out


# ---------------------------------------------------------
# INFORME HTML BONITO
# ---------------------------------------------------------

def build_report_html(counts, total, nets, geo):

    hostname = socket.gethostname()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def format_ip_row(ip, n):
        info = geo.get(ip, {})
        country = info.get("country", "")
        city = info.get("city", "")
        isp = info.get("isp", "")
        location = f"{country} - {city}" if country or city else ""
        isp_text = isp if isp else ""
        extra = ""
        if location:
            extra += f"<div style='font-size:12px;color:#555;'>{location}</div>"
        if isp_text:
            extra += f"<div style='font-size:12px;color:#888;'>{isp_text}</div>"
        return f"""
        <tr>
            <td style="padding:8px;border-bottom:1px solid #ddd;">
                <strong>{ip}</strong>{extra}
            </td>
            <td style="padding:8px;text-align:right;border-bottom:1px solid #ddd;">{n}</td>
        </tr>
        """

    html = f"""
    <html>
    <meta charset="UTF-8">
    <style>
    body {{
        font-family: Arial, sans-serif;
        background:#f0f2f5;
        padding:20px;
    }}
    h1 {{
        background:#34495e;
        color:white;
        padding:15px;
        border-radius:5px;
        text-align:center;
    }}
    h2 {{
        color:#2c3e50;
        margin-top:30px;
        border-left:5px solid #2980b9;
        padding-left:10px;
    }}
    table {{
        width:100%;
        border-collapse:collapse;
        background:white;
        border-radius:6px;
        overflow:hidden;
        box-shadow:0 2px 4px rgba(0,0,0,0.1);
        margin-bottom:25px;
    }}
    th {{
        background:#2980b9;
        color:white;
        padding:10px;
        text-align:left;
    }}
    td {{
        padding:10px;
    }}
    </style>

    <h1>Informe de actividad - {hostname}</h1>
    <p><strong>Periodo:</strong> Últimas 24 horas</p>
    <p><strong>Generado:</strong> {now}</p>

    <h2>Resumen por servicio</h2>
    <table>
        <tr><th>Servicio</th><th>Total</th></tr>
    """

    for svc, ctr in counts.items():
        html += f"<tr><td>{svc}</td><td style='text-align:right'>{sum(ctr.values())}</td></tr>"

    html += "</table>"

    for svc, ctr in counts.items():
        if not ctr:
            continue
        html += f"<h2>Detalle por IP → {svc}</h2><table><tr><th>IP</th><th>Solicitudes</th></tr>"
        for ip, n in ctr.most_common():
            html += format_ip_row(ip, n)
        html += "</table>"

    html += "<h2>IPs más activas (global)</h2><table><tr><th>IP</th><th>Solicitudes</th></tr>"
    for ip, n in total.most_common(20):
        html += format_ip_row(ip, n)
    html += "</table>"

    html += "<h2>Redes más activas</h2><table><tr><th>Red</th><th>Solicitudes</th></tr>"
    for net, n in nets.most_common(20):
        html += f"<tr><td>{net}</td><td style='text-align:right'>{n}</td></tr>"
    html += "</table>"

    html += "<p style='text-align:center;font-size:12px;color:#777'>Informe generado automáticamente</p>"

    html += "</html>"
    return html


# ---------------------------------------------------------
# EMAIL
# ---------------------------------------------------------

def send_mail(subject, html_body):
    msg = EmailMessage()
    msg["From"] = MAIL_FROM
    msg["To"] = ", ".join(MAIL_TO)
    msg["Subject"] = subject
    msg.set_content("Tu cliente no soporta HTML.")
    msg.add_alternative(html_body, subtype="html")

    if USE_SENDMAIL and os.path.exists("/usr/sbin/sendmail"):
        import subprocess
        subprocess.Popen(["/usr/sbin/sendmail", "-t", "-oi"], stdin=subprocess.PIPE).communicate(msg.as_bytes())
        return

    import smtplib
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
        try:
            s.starttls()
        except:
            pass
        if SMTP_USER and SMTP_PASS:
            s.login(SMTP_USER, SMTP_PASS)
        s.send_message(msg)


# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------

if __name__ == "__main__":
    counts = analyze()
    total, nets = summarize(counts)
    geo = geolocate_ips(total)
    html = build_report_html(counts, total, nets, geo)
    send_mail(MAIL_SUBJECT, html)

