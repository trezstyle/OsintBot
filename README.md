# 🤖 Cyber-Volt SOC Master Bot v3.0

A full-featured SOC (Security Operations Center) platform inside Telegram.  
Designed for cybersecurity analysts, penetration testers, and system administrators.

## 📋 Commands

### BotFather Menu (button to the left of the input field)

| Command | Description |
|---------|-------------|
| `/start` | 🤖 Start the bot / greeting |
| `/help` | 📖 Open menu with all functions |
| `/status` | 🖥 System dashboard (CPU/RAM/Disk) |
| `/top` | 📊 Top processes by CPU/RAM |
| `/logs` | 📜 Log analysis (failed/sudo/ssh/attack) |
| `/audit` | 🛡 BSI Compliance Audit |
| `/scan` | 🕸 Network scan (fast / full) |
| `/whois` | 🏢 WHOIS lookup by domain |
| `/recon` | 🌐 Domain / IP reconnaissance |
| `/fim` | 📋 File Integrity Monitor (add/check) |
| `/cve` | 🧠 CVE vulnerability check for package |
| `/hibp` | 🔐 Breach search (email/domain) |
| `/mitre` | 🧬 MITRE ATT&CK technique search |
| `/report` | 📄 Generate PDF report |
| `/alerts` | 🚨 Suricata IDS alerts |

### Inline Menu (via `/help`)

All functions available as clickable buttons in the `/help` menu:

| Category | Buttons |
|----------|---------|
| 🛡 Threat Intel | IP Threat Hunt, Domain Recon |
| 🕸 Network | Fast Scan, Full Scan |
| 📊 Monitoring | System Status, Top Processes, Logs |
| 🔐 Security | BSI Audit, FIM Monitor, CVE, HIBP, MITRE |
| 🚨 Alerts | Suricata Alerts |
| 📄 Reports | PDF Report |

### Auto-Detection

Just send an IP address or domain into the chat — the bot automatically performs a threat hunt!

---

## 🚨 Suricata IDS Integration

The bot includes a built-in **Suricata alert watcher** that runs as a background thread. When Suricata is installed and logging alerts, the bot automatically:

1. **Monitors** `/var/log/suricata/fast.log` every 15 seconds
2. **Buffers** the last 50 alerts in memory
3. **Sends real-time push notifications** for urgent signatures (MALWARE, TROJAN, EXPLOIT, CNC, CVE, SHELLCODE, RCE, etc.)
4. **Auto-runs Threat Hunt** on the source IP of any urgent alert (VirusTotal + AbuseIPDB + GeoIP)
5. **Provides on-demand view** via `/alerts` command or `🚨 Suricata Alerts` button

## How it works
suricata_watcher()         → polls fast.log every 15s
  ↓
New alert detected?        → added to buffer (max 50)
  ↓
Urgent keywords?           → push notification to Telegram
  ↓
Source IP found?           → auto VT + AbuseIPDB + GeoIP lookup
  ↓
Result sent to chat        → full alert with threat intelligence

## 📁 Project Structure

/root/cyber-volt/
├── intel_bot.py          # Main bot (telebot) — English
├── .env                  # Tokens and API keys
├── threat_intel_log.md   # Threat hunt query history
├── fim_hashes.json       # FIM database
├── bot.log               # Bot runtime logs
├── README.md             # This file
└── pdf_reports/          # Generated PDF reports (auto-created)

## 🏗 Production Project Structure

```text
/root/cyber-volt/
├── intel_bot.py                  # Entry point
├── config.py                     # Typed settings and environment loading
├── security.py                   # Authorization and input validation
├── runtime.py                    # Telegram polling loop
├── watchers.py                   # Background auth and Suricata watchers
├── health.py                     # Standalone production healthcheck
├── logging_config.py             # Optional structured rotating logging
├── services/                     # Threat intel, scanner, FIM, system, reporting
├── ui/                           # Telegram handlers and keyboards
├── Dockerfile                    # Production container build
├── Dockerfile.compose            # Compose deployment definition
├── pyproject.toml                # Package metadata
├── env.example                   # Sanitized environment template
└── .github/workflows/            # CI and Docker image workflows
```

## 🚀 Quick Start (Docker)

```bash
cp env.example .env
# Edit .env and set TELEGRAM_TOKEN plus ALLOWED_USERS.
docker build -t cyber-volt-soc-bot:3.0.0 .
docker run --rm --env-file .env \
  -v "$PWD/logs:/app/logs" \
  -v "$PWD/data:/app/data" \
  cyber-volt-soc-bot:3.0.0
```

Compose alternative:

```bash
docker compose -f Dockerfile.compose up -d --build
docker compose -f Dockerfile.compose logs -f
```

## 🔧 Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `TELEGRAM_TOKEN` | ✅ Yes | none | Telegram BotFather token. |
| `VT_API_KEY` | ❌ No | empty | VirusTotal API key for IP reputation. |
| `ABUSE_API_KEY` | ❌ No | empty | AbuseIPDB API key. |
| `HIBP_API_KEY` | ❌ No | empty | Have I Been Pwned API key for email searches. |
| `ALLOWED_USERS` | ✅ Recommended | empty | Comma-separated Telegram user IDs allowed to use the bot. |
| `ALLOWED_CHATS` | ❌ No | empty | Comma-separated Telegram chat IDs allowed to use the bot. |
| `FIM_ALLOWED_PREFIXES` | ✅ Recommended | `/etc,/root/cyber-volt` | Comma-separated paths allowed for FIM monitoring. |
| `PID_FILE` | ❌ No | `bot.pid` | PID file used by runtime guard and healthcheck. |
| `BOT_LOG_FILE` | ❌ No | `bot.log` | Bot runtime log path. |
| `LOG_FILE` | ❌ No | `threat_intel_log.md` | Threat intel query history path. |
| `FIM_FILE` | ❌ No | `fim_hashes.json` | FIM hash database path. |
| `REPORT_FILE` | ❌ No | `/tmp/cyber_volt_report.pdf` | Generated report path. |
| `AUTH_LOG_FILE` | ❌ No | `/var/log/auth.log` | Auth log path for failed login analysis. |
| `SURICATA_FAST_LOG_FILE` | ❌ No | `/var/log/suricata/fast.log` | Suricata fast log path. |
| `SSHD_CONFIG_FILE` | ❌ No | `/etc/ssh/sshd_config` | SSH daemon config path for audit checks. |
| `NMAP_PATH` | ❌ No | `/usr/bin/nmap` | nmap binary path. |
| `ROOT_PATH` | ❌ No | `/` | Filesystem root used for disk checks. |
| `LOG_ENABLED` | ❌ No | `true` | Enable or disable configured logging. |
| `LOG_LEVEL` | ❌ No | `INFO` | Python logging level. |
| `LOG_FORMAT` | ❌ No | `text` | Use `json` for structured logs. |
| `LOG_MAX_BYTES` | ❌ No | `10485760` | Rotating log file max size. |
| `LOG_BACKUP_COUNT` | ❌ No | `3` | Number of rotated log backups. |

## 🔒 Security Recommendations

- Keep `.env` out of git and rotate `TELEGRAM_TOKEN` if it is ever exposed.
- Always set `ALLOWED_USERS` or `ALLOWED_CHATS`; otherwise the bot can be open to anyone who finds it.
- Run the container as the bundled non-root `cybervolt` user and mount host logs read-only.
- Keep `FIM_ALLOWED_PREFIXES` narrow and avoid broad writable paths.
- Use least-privilege API keys and monitor provider quotas.
- Review scanner usage before enabling broad network scans in production environments.

## 🏭 Production Deployment

- Build from `Dockerfile` and deploy with `Dockerfile.compose` or your orchestrator.
- Mount `/app/logs` and `/app/data` to persistent volumes.
- Mount host logs such as `/var/log/auth.log` and `/var/log/suricata` read-only when those integrations are needed.
- Use Docker restart policy `unless-stopped` or an equivalent supervisor.
- Run `python3 health.py` or the Docker `HEALTHCHECK` to verify process and Telegram API connectivity.
- Use `LOG_FORMAT=json` when shipping logs to a central collector.

## 🧪 CI/CD

Badges placeholder:

```markdown
[![CI](https://github.com/OWNER/REPO/actions/workflows/ci.yml/badge.svg)](https://github.com/OWNER/REPO/actions/workflows/ci.yml)
[![Docker](https://github.com/OWNER/REPO/actions/workflows/docker.yml/badge.svg)](https://github.com/OWNER/REPO/actions/workflows/docker.yml)
```

The CI workflow runs dependency installation, `flake8`, `pylint`, `bandit`, and Python compile checks on Python 3.12. The Docker workflow builds the image on pushes to `main` and can push to GitHub Container Registry.

## 🔐 API Keys

| Key | Service | Required | Cost |
|-----|---------|----------|------|
| `TELEGRAM_TOKEN` | [@BotFather](https://t.me/BotFather) | ✅ Yes | Free |
| `VT_API_KEY` | [VirusTotal](https://www.virustotal.com/) | ❌ Optional | Free tier available |
| `ABUSE_API_KEY` | [AbuseIPDB](https://www.abuseipdb.com/) | ❌ Optional | Free tier available |

### HIBP (without API key)
Free-tier search works by domain (not by email):
- `user@gmail.com` → searches breaches on `gmail.com`
- `adobe.com` → searches breaches on Adobe
- `name:Adobe` → details of a specific breach

Paid API key (~$3.50/month) enables full email search.

## ⚙️ Features

## 🛡 Threat Intelligence
- **VirusTotal** — IP reputation (malicious/suspicious count)
- **AbuseIPDB** — Abuse confidence score, ISP reputation
- **GeoIP** (ipinfo.io) — City, region, country, ISP
- **WHOIS** — Domain registration data
- **crt.sh** — Subdomain enumeration
- **Brute Force Alerts** — Real-time auth.log monitoring

## 🕸 Network Scanner
- **Fast Scan** — 23 common ports (~5 seconds)
- **Full Scan** — All 65535 TCP ports two-pass (`-Pn -T4`, no ping sweep)

## 📊 System Monitoring
- **System Dashboard** — CPU/RAM/Disk/Load/Network bars
- **Top Processes** — PID, CPU%, MEM%, RSS in clean format
- **Log Analyzer** — Failed logins, sudo events, SSH activity, top attackers

## 🚨 Suricata IDS Alerts
- **Real-time monitoring** — polls `/var/log/suricata/fast.log` every 15 seconds
- **Auto-notifications** — push alerts for MALWARE, TROJAN, EXPLOIT, CNC, CVE, SHELLCODE, RCE
- **Auto Threat Hunt** — when an urgent alert fires, the bot automatically:
  - Runs VirusTotal check on the source IP
  - Runs AbuseIPDB check
  - Runs GeoIP lookup
  - Sends full intelligence report to your Telegram
- **On-demand view** — `/alerts` command shows last 15 alerts
- **Alert buffer** — keeps last 50 alerts in memory

## 🔐 Security Checks
- **BSI IT-Grundschutz Audit** — SSH config, firewall, ports, disk encryption, AppArmor
- **File Integrity Monitor** — SHA256 hash tracking for critical files
- **CVE Check** — NVD (NIST) vulnerability database
- **HIBP Check** — Have I Been Pwned breach search (domain-based, free)
- **MITRE ATT&CK** — Technique lookup by T-ID

## 📄 Reports
- **PDF Report** — System status, top processes, failed logins, compliance audit

## 📝 Logs

- `journalctl -u cyber_volt_bot.service -f` — systemd journal (real-time)
- `/root/cyber-volt/bot.log` — Bot runtime log file
- `/root/cyber-volt/threat_intel_log.md` — Threat hunt query history
- `/var/log/suricata/fast.log` — Suricata IDS alerts (if installed)

## 📜 License

MIT License — free to use, modify, and distribute.
