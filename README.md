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
