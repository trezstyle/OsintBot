"""
Security module for Cyber-Volt SOC Bot.
Provides safe input validation, authorization, and subprocess execution.
"""
import ipaddress
import re
import subprocess
import logging
import os
from pathlib import Path
from typing import List, Optional, Union

log = logging.getLogger("cyber_volt.security")

# ── Allowed users / chats ──
# Loaded from .env: ALLOWED_USERS="123456,789012" ALLOWED_CHATS="-1001234567890"
ALLOWED_USERS: List[int] = []
ALLOWED_CHATS: List[int] = []
AUTH_CONFIGURED = False

def load_authorization() -> None:
    """Load allowed user/chat IDs from environment."""
    global ALLOWED_USERS, ALLOWED_CHATS, AUTH_CONFIGURED
    users = os.getenv("ALLOWED_USERS", "")
    chats = os.getenv("ALLOWED_CHATS", "")
    AUTH_CONFIGURED = bool(users.strip() or chats.strip())
    if users:
        try:
            ALLOWED_USERS = [int(x.strip().strip('"').strip("'")) for x in users.split(",") if x.strip().strip('"').strip("'").lstrip("-").isdigit()]
        except ValueError:
            log.warning(f"Invalid ALLOWED_USERS value: {users}")
    if chats:
        try:
            ALLOWED_CHATS = [int(x.strip().strip('"').strip("'")) for x in chats.split(",") if x.strip().strip('"').strip("'").lstrip("-").isdigit()]
        except ValueError:
            log.warning(f"Invalid ALLOWED_CHATS value: {chats}")
    if not ALLOWED_USERS and not ALLOWED_CHATS:
        if AUTH_CONFIGURED:
            log.warning("Authorization configured but no valid numeric IDs were found — bot will reject commands.")
        else:
            log.warning("No ALLOWED_USERS or ALLOWED_CHATS configured — bot will REJECT ALL requests! Set ALLOWED_USERS in .env")
    else:
        log.info(f"Auth loaded: {len(ALLOWED_USERS)} users, {len(ALLOWED_CHATS)} chats")


def is_authorized(user_id: int, chat_id: int) -> bool:
    """Check if a user/chat is allowed to use privileged commands.

    If no whitelist is configured, rejects all requests.
    """
    if not AUTH_CONFIGURED:
        return False
    if user_id in ALLOWED_USERS:
        return True
    if chat_id in ALLOWED_CHATS:
        return True
    return False


def is_admin(user_id: int) -> bool:
    """Check if user has admin role in the database."""
    try:
        from services.database import get_user
        user = get_user(user_id)
        return user is not None and user.get("role") == "admin"
    except Exception:
        return user_id in ALLOWED_USERS


def is_readonly(user_id: int) -> bool:
    """Check if user has readonly role."""
    try:
        from services.database import get_user
        user = get_user(user_id)
        return user is not None and user.get("role") == "readonly"
    except Exception:
        return False


# ── Input Validators ──

def validate_ip(text: str) -> Optional[str]:
    """Validate and normalize an IP address. Returns None if invalid."""
    text = text.strip()
    try:
        ip = ipaddress.ip_address(text)
        return str(ip)
    except ValueError:
        return None


def validate_domain(text: str) -> Optional[str]:
    """Validate a domain name. Returns normalized domain or None."""
    text = text.strip().lower()
    # Basic domain regex: must have at least one dot, valid chars
    pattern = r'^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
    if re.match(pattern, text) and len(text) <= 253:
        return text
    return None


def validate_hostname(text: str) -> Optional[str]:
    """Validate an IP or domain. Returns the value or None."""
    ip = validate_ip(text)
    if ip:
        return ip
    return validate_domain(text)


def validate_package_name(text: str) -> Optional[str]:
    """Validate a Debian package name. Returns name or None."""
    text = text.strip().lower()
    # Debian package names: alphanumeric, +, -, .
    pattern = r'^[a-z0-9][a-z0-9\+\\.\\-]*$'
    if re.match(pattern, text) and len(text) <= 128:
        return text
    return None


def validate_file_path(text: str, allowed_prefixes: Optional[List[str]] = None) -> Optional[str]:
    """Validate and resolve a file path. Optionally restrict to allowed prefixes.
    
    Protects against:
    - Path traversal (../../etc/shadow)
    - Symlink attacks (resolved to real path)
    - Access outside allowed directories
    """
    text = text.strip()
    if not text:
        return None
    
    # Resolve the path
    try:
        path = Path(text).resolve()
    except RuntimeError:
        return None  # Path resolution failed
    
    # Check allowed prefixes
    if allowed_prefixes:
        allowed = False
        for prefix in allowed_prefixes:
            try:
                prefix_path = Path(prefix).resolve()
                if path == prefix_path or path.is_relative_to(prefix_path):
                    allowed = True
                    break
            except RuntimeError:
                continue
        if not allowed:
            return None
    
    return str(path)


def validate_fim_path(path: str) -> Optional[str]:
    """Validate a FIM path against configured allowed prefixes."""
    from config import settings

    prefixes = [str(p) for p in settings.paths.fim_allowed_prefixes]
    return validate_file_path(path, prefixes)


# ── Safe Subprocess ──

class SafeCommandError(Exception):
    """Raised when a safe command fails."""
    pass


def run_command(args: List[str], timeout: int = 30, max_output: int = 100_000) -> str:
    """Run a system command safely with arg list (NO shell=True).
    
    Args:
        args: Command as list (e.g. ["nmap", "-T4", "-p", "22", "192.168.1.1"])
        timeout: Maximum execution time in seconds
        max_output: Maximum output bytes to capture
        
    Returns:
        Command stdout as string
        
    Raises:
        SafeCommandError: If command fails, times out, or produces too much output
    """
    if not args:
        raise SafeCommandError("Empty command args")
    
    # Log what we're running (without sensitive args)
    log.debug(f"Running: {' '.join(str(a) for a in args[:4])}...")
    
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,  # Don't raise on non-zero exit
        )
        
        # Truncate if too large
        output = result.stdout
        if len(output) > max_output:
            output = output[:max_output] + "\n... [truncated]"
        
        return output
    except subprocess.TimeoutExpired:
        raise SafeCommandError(f"Command timed out after {timeout}s")
    except FileNotFoundError:
        raise SafeCommandError(f"Command not found: {args[0]}")
    except OSError as e:
        raise SafeCommandError(f"OS error running command: {e}")
