# 🔍 CODE REVIEW — Cyber-Volt SOC Bot

## 1. Architecture Overview
- Architecture pattern
  - Single-file procedural Telegram bot with global configuration, global mutable runtime state, background polling threads, synchronous command handlers, and direct integrations to OS commands and public threat-intel APIs.
  - The bot is both the presentation layer, command router, business logic layer, persistence layer, scheduler, and deployment entrypoint.
- Component breakdown
  - Telegram UI: inline keyboards, command handlers, callback handlers, next-step handlers.
  - Threat intelligence: VirusTotal, AbuseIPDB, ipinfo, WHOIS, crt.sh, HIBP, MITRE CTI, NVD CVE API.
  - Host monitoring: psutil status, process listing, auth log analysis, BSI-style audit, Suricata alert watcher.
  - Active scanning: nmap subprocess wrapper for fast and full scans.
  - File integrity monitoring: JSON database at `/root/cyber-volt/fim_hashes.json`.
  - Reporting: ReportLab PDF generation to `/tmp/cyber_volt_report.pdf`.
  - Runtime control: PID file in `/tmp`, custom Telegram polling loop, daemon alert threads.
- Data flow description
  - User sends Telegram message or presses inline button.
  - Handler updates global `ALERT_CHAT_ID`, parses user input, and calls a synchronous local function.
  - Local function may call external HTTP APIs, execute shell commands, read privileged OS files, update JSON state, or generate a PDF.
  - Result is formatted as Markdown and sent back through Telegram.
  - Background threads poll `/var/log/auth.log` and `/var/log/suricata/fast.log`, mutate in-memory buffers, and push alerts to the latest chat that used the bot.

## 2. Bugs Found
FILE:LINE | SEVERITY | DESCRIPTION

- `threat_intel_log.md`:1 | MEDIUM | File requested in project review and documented in README, but it does not exist. `save_to_log()` will create it only after a successful threat-hunt write, so a fresh deployment has missing expected runtime state.
- `intel_bot.py`:2 | LOW | `socket` is imported but unused.
- `intel_bot.py`:31 | HIGH | `telebot.TeleBot(TOKEN)` is created even when `TELEGRAM_TOKEN` is missing; startup will fail later with unclear behavior instead of validating configuration explicitly.
- `intel_bot.py`:42-47 | MEDIUM | `save_to_log()` suppresses all exceptions, hiding missing permissions, disk errors, encoding failures, and broken log paths.
- `intel_bot.py`:122 | MEDIUM | VirusTotal URL interpolates raw `ip` without strict validation in direct step handlers, allowing malformed paths and unreliable API calls.
- `intel_bot.py`:125-126 | MEDIUM | Assumes `data.attributes.last_analysis_stats` exists; malformed or changed API responses produce user-visible exceptions.
- `intel_bot.py`:168-176 | MEDIUM | WHOIS accepts unvalidated arbitrary domain strings and suppresses all failures, making invalid input and dependency failures indistinguishable.
- `intel_bot.py`:180-183 | MEDIUM | crt.sh query is built from unescaped user input and assumes every JSON object contains `common_name`; nonstandard responses can raise `KeyError` or JSON decode errors.
- `intel_bot.py`:209-254 | LOW | Top process command uses `shell=True` even though no dynamic input is required.
- `intel_bot.py`:246 | LOW | Uses Unicode ellipsis in code output while the rest of the project does not consistently define encoding assumptions.
- `intel_bot.py`:301-336 | MEDIUM | Audit labels README claims disk encryption/AppArmor coverage, but implementation does not check either.
- `intel_bot.py`:305 | LOW | Reads `/etc/ssh/sshd_config` without a context manager.
- `intel_bot.py`:307 | LOW | Uses `os.system()` for firewall status instead of `subprocess.run()` with explicit args.
- `intel_bot.py`:310,315,319,328 | LOW | Audit subprocess calls mostly lack timeouts, so a blocked command can hang a bot request.
- `intel_bot.py`:343-362 | MEDIUM | Log analyzer hardcodes `/var/log/auth.log`; this fails on distributions using journald-only auth logs or `/var/log/secure`.
- `intel_bot.py`:369-398 | CRITICAL | `scan_network()` interpolates user-controlled `target` into shell commands, allowing command injection.
- `intel_bot.py`:400-419 | LOW | Nmap parser only recognizes IPv4 and simple host lines; IPv6 and service/version output are poorly handled.
- `intel_bot.py`:421-437 | MEDIUM | `format_scan()` can generate Telegram messages above platform limits for large scans, causing send failures.
- `intel_bot.py`:444-451 | HIGH | FIM database load/save has no context managers, no atomic write, no file locking, and `save_fim()` does not handle JSON write errors.
- `intel_bot.py`:453-480 | HIGH | `/fim add` allows any Telegram user to hash arbitrary server files and directories readable by the bot process.
- `intel_bot.py`:478,516 | HIGH | File hashing reads entire files into memory; large files can exhaust memory.
- `intel_bot.py`:483-520 | MEDIUM | FIM directory mode hashes metadata only, not file contents; content changes can be missed if size and mtime are preserved.
- `intel_bot.py`:527-550 | CRITICAL | `check_cve()` interpolates user-controlled package names into shell commands, allowing command injection.
- `intel_bot.py`:535 | MEDIUM | NVD query is built without URL parameter encoding and has no API key/rate-limit handling.
- `intel_bot.py`:568,586 | MEDIUM | HIBP API key is hardcoded as an empty string instead of reading configuration; feature is misleading and brittle.
- `intel_bot.py`:568,586 | MEDIUM | HIBP URLs interpolate raw user input without URL encoding.
- `intel_bot.py`:580,602 | MEDIUM | HIBP HTML descriptions are forwarded into Telegram Markdown without sanitization; formatting injection and broken rendering are likely.
- `intel_bot.py`:621 | HIGH | MITRE CTI JSON is downloaded on every lookup; this is slow, rate-limit prone, and a single dependency outage breaks the command.
- `intel_bot.py`:624 | LOW | MITRE lookup uses substring matching against the first external reference only; it can return wrong techniques or miss valid ones.
- `intel_bot.py`:639-662 | HIGH | `generate_report()` writes every report to the same predictable `/tmp/cyber_volt_report.pdf`, causing cross-request overwrite and race issues.
- `intel_bot.py`:652,655 | MEDIUM | Report generation subprocess calls lack timeouts.
- `intel_bot.py`:671-714 | MEDIUM | Auth watcher polls and greps the last 20 lines every 30 seconds; high-volume logs can miss attacks between polls.
- `intel_bot.py`:675-693 | LOW | Auth deduplication key is only first 80 chars; distinct lines can collide.
- `intel_bot.py`:702-711 | MEDIUM | `failed_attempts` is mutated by a background thread without a lock.
- `intel_bot.py`:714,781 | HIGH | Background daemon threads start at import time, before `__main__`; importing the module for tests or tooling causes side effects and filesystem polling.
- `intel_bot.py`:720-781 | MEDIUM | Suricata watcher polls the last 20 lines, so bursts over 20 alerts in 15 seconds are silently missed.
- `intel_bot.py`:755-773 | HIGH | Auto threat hunt may call `bot.send_message(ALERT_CHAT_ID, ...)` when `ALERT_CHAT_ID` is `None`; exception is swallowed, hiding broken alert delivery.
- `intel_bot.py`:788-899 | CRITICAL | No authentication/authorization check restricts who can use privileged commands; anyone who can chat with the bot can scan networks, read logs, hash files, and generate host reports.
- `intel_bot.py`:827-829 | MEDIUM | `/scan fast` with no target raises `IndexError` because the filtered argument list can be empty.
- `intel_bot.py`:858,973 | LOW | `bot.reply_to()` / `bot.send_message()` for "Generating PDF report..." omit `parse_mode` while using Markdown markup.
- `intel_bot.py`:883-899 | MEDIUM | Auto-domain detection treats any dotted string as a domain; invalid domains and local paths with dots can trigger external lookups.
- `intel_bot.py`:906-998 | MEDIUM | Callback handler uses a private pyTelegramBotAPI matcher later in the custom loop, increasing upgrade fragility.
- `intel_bot.py`:992 | HIGH | Callback branch references undefined `cmd_hello`; a `h_hello` callback would raise `NameError`.
- `intel_bot.py`:1005-1010 | HIGH | `process_ip_hunt()` does not validate IP octets; values like `999.999.999.999` are accepted.
- `intel_bot.py`:1012-1021 | HIGH | `process_domain_hunt()` routes IPv4-like values without octet validation and sends arbitrary strings to WHOIS/crt.sh.
- `intel_bot.py`:1023-1033 | CRITICAL | Next-step scan handlers send raw Telegram input to command-injection-prone `scan_network()`.
- `intel_bot.py`:1035-1038 | HIGH | `process_fim_add()` accepts arbitrary paths from Telegram without allowlist or size limits.
- `intel_bot.py`:1040-1044 | CRITICAL | `process_cve()` sends raw Telegram input to command-injection-prone `check_cve()`.
- `intel_bot.py`:1068-1082 | HIGH | PID file in world-writable `/tmp` is predictable and vulnerable to symlink/path attacks and stale PID races.
- `intel_bot.py`:1080-1082 | MEDIUM | PID guard removes and rewrites PID file non-atomically after stale PID detection.
- `intel_bot.py`:1130-1200 | HIGH | Custom polling loop reimplements internals instead of using supported polling APIs; next-step handler cleanup semantics are likely broken.
- `intel_bot.py`:1147-1152 | MEDIUM | Next-step handlers are fetched and invoked manually, but not explicitly cleared; prompts may be reprocessed or leak depending on backend behavior.
- `intel_bot.py`:1160,1175 | HIGH | Uses private `_test_message_handler()` API; library upgrades can break routing.
- `README.md`:70-77 | LOW | Project structure documents `threat_intel_log.md` and `pdf_reports/`, but `threat_intel_log.md` is absent and reports are actually generated in `/tmp`.
- `README.md`:107 | LOW | Claims full scan is "two-pass"; code performs a single `nmap -Pn -T4 --open -p-` scan.
- `README.md`:125-127 | MEDIUM | Claims BSI audit checks disk encryption and AppArmor, but code does not.
- `README.md`:132-133 | LOW | PDF report location is not documented accurately.
- `fim_hashes.json`:1-67 | MEDIUM | Stores hashes for sensitive system files in a repo working tree. Hashes are not secrets by themselves, but they reveal monitored targets and host security posture.
- `.gitignore`:9 | LOW | Ignores `fim_hashes.json`, but the file exists in the working tree and may already be tracked; this can create false confidence.

## 3. Security Issues
- API key handling
  - `TELEGRAM_TOKEN`, `VT_API_KEY`, and `ABUSE_API_KEY` are read from `.env`, and `.env` has mode `600` and is ignored by `.gitignore`, which is good.
  - Startup does not fail fast if `TELEGRAM_TOKEN` is missing.
  - HIBP uses `headers={"hibp-api-key": ""}` instead of `HIBP_API_KEY` from environment.
  - API errors often include exception text sent back to Telegram, which may disclose operational details.
- Input validation
  - No central validation for Telegram users, chat IDs, IP addresses, domains, package names, file paths, or scan targets.
  - Auto-detection validates IPv4 octets, but explicit `/recon`, `/whois`, callback, and next-step paths do not.
  - Domains are accepted with a loose dotted-string check.
  - File paths for FIM are unrestricted.
- Command injection risks
  - Critical injection in `scan_network()` via `target` at lines 373 and 383.
  - Critical injection in `check_cve()` via `pkg` at lines 531 and 533.
  - Static shell commands also use `shell=True`; lower risk, but still unnecessary.
- File permission issues
  - `intel_bot.py`, `README.md`, `fim_hashes.json`, and `.gitignore` are `644 root:root`; `.env` is `600 root:root`.
  - Bot log and threat-intel log are hardcoded under `/root/cyber-volt`; permissions are not explicitly controlled at creation.
  - PDF reports and PID file use predictable `/tmp` paths.
  - FIM can read arbitrary files permitted to the bot's OS user and report hashes to Telegram.
- Token exposure
  - No token literal was found in reviewed source files.
  - README correctly lists `.env`, but operational logging and exception echoing should avoid ever printing request headers, API failures with sensitive bodies, or token-bearing URLs.
- subprocess abuse
  - Telegram users can trigger expensive `nmap -p-` scans and shell commands.
  - Long-running commands execute synchronously in the message path, causing denial of service.
  - No allowlist limits scan scope to owned ranges.

## 4. Code Quality Issues
- PEP8 violations
  - Many multiple imports on one line.
  - Many one-line `if`, `with`, `try`, `except`, and handler branches.
  - Broad bare `except` blocks throughout.
  - Line lengths are frequently far above 79/88 chars.
- Missing type hints
  - No functions have type hints.
  - Shared structures such as FIM entries, Suricata alerts, and parsed nmap hosts are untyped dictionaries.
- Bad naming
  - Short names like `m`, `r`, `d`, `w`, `u`, `p`, `t`, `cid`, `cmd`, and `kb` reduce readability in security-sensitive code.
  - `format_audit()` claims BSI compliance but performs a shallow host health check.
- Repeated code (DRY)
  - Command and callback handlers duplicate routing for status, top, audit, logs, scan, FIM, CVE, HIBP, MITRE, report, and alerts.
  - Directory hashing logic is duplicated in `fim_add()` and `fim_check()`.
  - Markdown response formatting and Telegram reply patterns are repeated everywhere.
- SOLID violations
  - Single module and many functions mix UI, business logic, subprocess execution, persistence, network clients, reporting, and background scheduling.
  - Hard to unit test because `bot`, threads, env loading, and paths are initialized at import time.
- Error handling gaps
  - Bare exceptions hide security and operational failures.
  - Many commands return raw exception strings to users.
  - Missing explicit handling for API schema changes, JSON decode failures, Telegram message length limits, file permission errors, and network rate limits.
- Hardcoded values
  - Absolute paths: `/root/cyber-volt/.env`, `bot.log`, `threat_intel_log.md`, `fim_hashes.json`.
  - Runtime paths: `/tmp/cyber_volt_bot.pid`, `/tmp/cyber_volt_report.pdf`.
  - System paths: `/var/log/auth.log`, `/var/log/suricata/fast.log`, `/etc/ssh/sshd_config`.
  - Poll intervals, alert thresholds, ports, API URLs, and nmap flags are hardcoded.

## 5. Race Conditions & Threading
- Thread safety analysis
  - `ALERT_CHAT_ID` is written under `ALERT_LOCK` but read without the lock in background threads.
  - `suricata_alerts` is protected by `suricata_lock` for appends and reads, which is the best-handled shared structure.
  - `failed_attempts` has no lock, but today only the auth watcher mutates it; this is fragile if future handlers expose it.
- Shared state problems
  - `ALERT_CHAT_ID` is global and overwritten by whichever chat last sends a command. Alerts can be sent to the wrong chat.
  - `suricata_alerts` is in-memory only and lost on restart.
  - Telegram next-step handler state is manipulated through internals in the custom polling loop.
- Lock usage issues
  - Locks are used inconsistently.
  - File writes to FIM JSON and threat-intel log are not locked, so concurrent commands can corrupt or interleave writes.
  - PID file handling is not atomic after stale PID cleanup.

## 6. Performance Issues
- File I/O patterns
  - FIM hashes entire files with `.read()`, which does not scale.
  - FIM directory mode walks entire trees synchronously inside a Telegram request.
  - Auth and Suricata watchers repeatedly shell out and reread tail/grep output rather than maintaining file offsets.
  - Threat-intel log appends synchronously and silently drops failures.
- Network request patterns
  - Threat hunt performs VT, AbuseIPDB, and GeoIP sequentially.
  - MITRE CTI downloads a large JSON file on every lookup.
  - No caching for WHOIS, crt.sh, NVD, HIBP, MITRE, or IP reputation.
  - No backoff/rate-limit strategy except coarse Telegram 409/429 polling sleeps.
- Memory usage
  - Large FIM files can be loaded into memory.
  - Large nmap output is captured fully into memory before parsing.
  - Large Telegram responses are assembled as strings without size checks.

## 7. Production Readiness
- Docker readiness
  - Not Docker-ready as-is. The app assumes root-owned absolute paths, Linux host logs, systemd, ufw, nmap, dpkg, ss, grep, awk, and direct access to `/var/log`.
  - Configuration is not injectable beyond API keys.
- VPS deployment
  - It can run on a root-managed VPS, but it needs a dedicated unprivileged service user, systemd unit, least-privilege file permissions, allowlisted Telegram users, and explicit dependency installation.
  - Hardcoded `/root/cyber-volt` prevents portable deployments.
- Logging quality
  - Logs to file and stdout, but no rotation is configured.
  - Many critical exceptions are swallowed.
  - User-visible exceptions can leak internals while internal logs omit stack traces.
- Monitoring
  - No health endpoint, metrics, watchdog heartbeat, queue depth, alert delivery status, or dependency availability checks.
  - Background thread failures are usually hidden.
- CI/CD
  - No requirements file existed before this review.
  - No tests, linting, formatting, type checking, security scanning, Dockerfile, pre-commit, or GitHub Actions workflow.

## 8. Refactoring Plan (prioritized)
1. Add authorization first: enforce allowed Telegram user IDs/chat IDs before every command and callback.
2. Remove command injection: replace shell-string subprocess calls with arg lists; validate scan targets and package names with strict allowlists.
3. Move configuration into a typed settings object: paths, poll intervals, alert thresholds, API keys, allowed users, scan policy, and feature flags.
4. Stop import-time side effects: create `main()`, initialize bot and threads only under `if __name__ == "__main__"`.
5. Replace custom polling internals with supported pyTelegramBotAPI polling or webhook mode.
6. Split the file into modules: `config`, `telegram_handlers`, `threat_intel`, `host_checks`, `scanner`, `fim`, `reporting`, `watchers`.
7. Implement safe persistence: atomic JSON writes, file locks, streaming hashing, explicit permissions, and migration/recovery for corrupt FIM data.
8. Add input models and validators for IPs, domains, package names, paths, and scan targets.
9. Add caching and rate limiting for external APIs, especially MITRE, NVD, WHOIS, crt.sh, and reputation lookups.
10. Add tests for validators, nmap parsing, FIM hashing, command routing, and error cases.
11. Add production packaging: `requirements.txt`, systemd unit, Dockerfile or deployment docs, CI lint/test/security checks.
12. Improve observability: structured logs, stack traces for internal logs, log rotation, health checks, and alert delivery metrics.

## 9. Scores
- Security: 2/10
- Code Quality: 3/10
- Architecture: 3/10
- Production Readiness: 2/10
- Overall Level: Junior

## 10. TODO List
- Critical
  - Add Telegram user/chat allowlisting before any sensitive action.
  - Fix command injection in `scan_network()` and `check_cve()`.
  - Restrict scanning to explicitly authorized targets.
  - Restrict or remove arbitrary FIM path reads from Telegram.
  - Move PID and report files out of predictable shared `/tmp` names or create them securely.
  - Stop starting threads at import time.
- Important
  - Validate `TELEGRAM_TOKEN` and all optional API keys at startup.
  - Replace broad bare `except` blocks with specific exceptions and internal stack logging.
  - Use context managers and atomic writes for logs/FIM data.
  - Stream file hashing instead of reading whole files.
  - Cache MITRE CTI and other expensive external lookups.
  - Split code into testable modules.
  - Add tests, linting, formatting, typing, and CI.
  - Fix README mismatches with actual behavior.
- Nice to have
  - Add Docker/systemd deployment examples.
  - Add configurable paths and thresholds.
  - Add message chunking for long Telegram responses.
  - Add log rotation.
  - Add persistent alert history.
  - Add an async job queue for long scans and reports.
