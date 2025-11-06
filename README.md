# log-analyzer

Script de análisis de logs que genera un informe HTML con los intentos de ataque
web/SSH/SMTP detectados durante las últimas 24 h y lo envía por correo.

## Requisitos

- Python 3.9+
- Dependencias base: `python-dotenv`.
- Dependencias opcionales para el mapa de ataques SSH:
  - `requests`
  - `folium`

Instalación rápida:

```bash
pip install python-dotenv requests folium
```

## Variables de entorno

Las siguientes variables permiten personalizar el comportamiento:

| Variable | Descripción | Valor por defecto |
| --- | --- | --- |
| `MAIL_TO` | Destinatarios separados por coma | `root@localhost` |
| `MAIL_FROM` | Remitente del informe | `root@<hostname>` |
| `MAIL_SUBJECT` | Asunto del correo | `[logwatch] Informe de ataques` |
| `USE_SENDMAIL` | Usa `/usr/sbin/sendmail` si está disponible | `true` |
| `SMTP_HOST`/`SMTP_PORT`/`SMTP_USER`/`SMTP_PASS` | Configuración SMTP alternativa | – |
| `SERVICES` | Servicios a analizar (coma) | `Servidor Web,Servidor SSH,Servidor SMTP` |
| `WEB_LOG_PATHS` | Rutas de logs web (globs) | `/var/log/nginx/access.log*,/var/log/apache2/access.log*` |
| `SSH_LOG_PATHS` | Rutas de logs SSH (globs) | `/var/log/auth.log*,/var/log/secure*` |
| `SMTP_LOG_PATHS` | Rutas de logs SMTP (globs) | `/var/log/mail.log*,/var/log/maillog*` |
| `NET_PREFIX` | Prefijo de red para el resumen agregado | `16` |
| `SSH_MAP_ENABLED` | Generar mapa con orígenes de ataques SSH | `true` |
| `SSH_MAP_FILE` | Ruta del fichero HTML del mapa adjunto | `ssh-attack-map.html` |
| `SSH_MAP_CACHE` | Ruta del fichero de caché de geolocalización | `~/.cache/log-analyzer/ip-geolocation.json` |
| `SSH_MAP_CACHE_MAX_AGE` | Validez (seg.) de entradas en caché | `604800` |

> 💡 El mapa interactivo se genera únicamente si hay datos de ataques SSH y se
> dispone de las librerías opcionales. La geolocalización se realiza a través
> de la API pública `ip-api.com`, almacenando resultados en caché para evitar
> consultas repetidas.

## Ejecución

```bash
python main.py
```

El script producirá un informe HTML enviado por correo y adjuntará el mapa
`ssh-attack-map.html` con los orígenes de los ataques SSH más recientes.
