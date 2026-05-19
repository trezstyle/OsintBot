# Code Review: Cyber-Volt SOC Bot

## Summary

This is a feature-rich Telegram SOC/OSINT bot built with aiogram 3.x. The codebase shows solid architectural intent with separation into `services/`, `ui/`, and root modules. However, it suffers from several production-readiness issues including thread safety gaps, performance bottlenecks, inconsistent async/sync mixing, global mutable state, and security concerns.

**Overall Assessment**: Functional but not production-robust. Needs structural improvements for scalability, maintainability, and reliability.

---

## 1. Critical Bugs & Logical Issues

### 1.1 Event Loop Leak in `notifier.py:15-23`
```python
_loops: dict[int, asyncio.AbstractEventLoop] = {}
```
Threads call `_get_loop()` which creates new event loops and stores them forever. When threads die (e.g., after watcher restart), the loops are never closed, causing file descriptor leaks.

**Fix**: Clean up loop entries when threads exit, or use `asyncio.run()` for one-shot tasks.

### 1.2 Duplicate `_bar()` in `system.py:78` and `system.py:170`
Two identical implementations of a bar-chart function at lines 78 and 170. The second one has a bug (`filled = int(v / 10)` should be `int(v / 100 * n)` like the first).

### 1.3 SQLite Connection State in `database.py:24-29`
```python
_local = threading.local()
def get_db():
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = sqlite3.connect(...)
    return _local.conn
```
Thread-local connections work but: (a) no graceful close on shutdown, (b) thread pool reuse can return stale connections, (c) `check_same_thread=False` disables SQLite's safety net, relying entirely on our own locking.

### 1.4 `fim_save_all()` Non-Atomic Delete + Insert
```python
def fim_save_all(entries):
    db.execute("DELETE FROM fim")
    db.executemany("INSERT INTO fim ...", ...)
    db.commit()
```
If the process crashes between DELETE and INSERT (or during executemany), ALL FIM data is lost. Should use a transaction with proper rollback.

### 1.5 Rate Limiter User ID Collision in `system.py:258`
```python
_nvd_limiter = RateLimiter(max_calls=5, window_seconds=60)
if not _nvd_limiter.is_allowed(0):  # user_id=0
```
Using hardcoded `0` as user_id means all users share the same NVD rate limit bucket. This is intentional but also means user A's CVE checks can block user B's.

### 1.6 `_deploy.py` Hardcoded Path
```python
["bash", "-c", "cd /root/OsintBot && git add ui/handlers.py ..."]
```
Hardcoded to `/root/OsintBot`. Not portable.

### 1.7 `_test_top.py` Hardcoded Path
```python
sys.path.insert(0, "/root/OsintBot")
```
Same issue.

### 1.8 Tests Import Non-Existent Functions
`test_fim.py` imports `load_fim` and `save_fim` from `services.fim`, but these functions don't exist in `fim.py` — they were moved to `database.py` as `fim_load()` and `fim_save_all()`.

---

## 2. Performance Bottlenecks

### 2.1 `auth_log_lines()` Reads Entire File Every Call
Used by `failed_login_count()`, `tail_auth_matches()`, `analyze_logs()`, and `format_compliance()`. For a 500MB auth.log on a busy server, this is ~5-10MB per read × multiple calls per handler.

**Fix**: Use `tail` approach (seek from end) or `mmap` for large files.

### 2.2 `hunt.py` Creates ThreadPool Per Call
```python
def threat_hunt_ip(ip):
    with ThreadPoolExecutor(max_workers=3) as pool:
```
Each invocation creates and tears down a thread pool. This is expensive for frequent calls. Should reuse a module-level pool.

### 2.3 `scanner.py` Module-Level Pool with No Cleanup
```python
_executor = ThreadPoolExecutor(max_workers=2)
```
The pool has no shutdown mechanism. On process exit, pending futures may be lost/warnings emitted.

### 2.4 Busy-Waiting in `job_queue.py:48`
```python
if job is None:
    time.sleep(0.5)
    continue
```
500μs wakeups × 86400s/day = 172,800 unnecessary wakeups/day when idle. Use `threading.Condition` or `queue.Queue`.

### 2.5 Synchronous HTTP in Async Handlers
`check_phone`, `get_whois`, `check_hibp`, etc. all use synchronous `requests` inside async Telegram handlers. This blocks the event loop.

---

## 3. Security Vulnerabilities

### 3.1 UFW Command Injection Surface in `system.py:360`
```python
result = _run_cmd(["ufw", "--force", real_action, real_arg], timeout=10)
```
While `real_action` is validated to `allow|deny|delete`, `real_arg` is user-controlled with minimal validation. Behind admin auth, but still dangerous.

### 3.2 Dashboard Auth is Single Shared Secret
No user-level auth, no session tokens, no HTTPS enforcement, no rate limiting on auth attempts.

### 3.3 Path Traversal via Symlink Race in FIM
```python
def validate_file_path(text, allowed_prefixes=None):
    path = Path(text).resolve()
```
The path is resolved at validation time, but checked at runtime. A symlink can be swapped between validation and use.

### 3.4 Nmap Target Validation Gaps
`validate_hostname` allows domains and IPs. But nmap also accepts URL schemes, CIDR ranges, and ranges like `192.168.1.1-10`. These bypass the simple validators.

### 3.5 Docker Runs as Non-Root but Needs Root-Only Files
The Docker container runs as `cybervolt` user but reads `/var/log/auth.log`, `/etc/ssh/sshd_config`, runs `ufw`, etc. This won't work without `sudo` or capabilities.

---

## 4. Code Smells & Maintainability

### 4.1 Global Mutable State Everywhere
- `ALLOWED_USERS` / `ALLOWED_CHATS` (module-level lists)
- `_bot: Optional[Bot]` global in notifier
- `_jobs: dict` global in job_queue
- `failed_attempts`, `suricata_alerts` module globals in watchers

### 4.2 270-Line `cmd_handler()` Function
The single dispatch function handles ~20+ commands with deeply nested conditionals. Violates Open/Closed principle.

### 4.3 Mixed Sync/Async Architecture
The bot uses `asyncio` for Telegram, but spawns `threading.Thread` for watchers, job queue, scheduler, and metrics. These threads then call `send_message_sync()` which creates event loops to bridge back to async.

### 4.4 `_CMD_TABLE` Pattern
Command configuration is a dict with function references. This works but lacks: type hints for args/results, error handling configuration, permission levels, and input transformation pipelines.

### 4.5 Configuration Loaded at Import Time
`config.py:88`: `settings = load_settings()` runs at module import. This makes testing harder and prevents dynamic reconfiguration.

### 4.6 F-Strings in Logging
```python
log.warning(f"delete_webhook error: {e}")
```
Should use lazy `%s` formatting to avoid paying the formatting cost when log level is not enabled.

---

## 5. Refactored Code

Below are the refactored versions of the most critical files, addressing the key issues above while preserving all functionality.
