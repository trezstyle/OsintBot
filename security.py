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

ALLOWED_USERS: List[int] = []
ALLOWED_CHATS: List[int] = []
AUTH_CONFIGURED = False


def load_authorization() -> None:
    global ALLOWED_USERS, ALLOWED_CHATS, AUTH_CONFIGURED
    users = os.getenv("ALLOWED_USERS", "")
    chats = os.getenv("ALLOWED_CHATS", "")
    AUTH_CONFIGURED = bool(users.strip() or chats.strip())
    if users:
        try:
            ALLOWED_USERS = [
                int(x.strip().strip('"').strip("'"))
                for x in users.split(",")
                if x.strip().strip('"').strip("'").lstrip("-").isdigit()
            ]
        except ValueError:
            log.warning("Invalid ALLOWED_USERS value: %s", users)
    if chats:
        try:
            ALLOWED_CHATS = [
                int(x.strip().strip('"').strip("'"))
                for x in chats.split(",")
                if x.strip().strip('"').strip("'").lstrip("-").isdigit()
            ]
        except ValueError:
            log.warning("Invalid ALLOWED_CHATS value: %s", chats)
    if not ALLOWED_USERS and not ALLOWED_CHATS:
        if AUTH_CONFIGURED:
            log.warning("Authorization configured but no valid numeric IDs were found")
        else:
            log.warning("No ALLOWED_USERS or ALLOWED_CHATS configured")
    else:
        log.info("Auth loaded: %d users, %d chats", len(ALLOWED_USERS), len(ALLOWED_CHATS))


def is_authorized(user_id: int, chat_id: int) -> bool:
    if not AUTH_CONFIGURED:
        return False
    if user_id in ALLOWED_USERS:
        return True
    if chat_id in ALLOWED_CHATS:
        return True
    return False


def is_admin(user_id: int) -> bool:
    try:
        from services.database import get_user
        user = get_user(user_id)
        return user is not None and user.get("role") == "admin"
    except Exception:
        return user_id in ALLOWED_USERS


def is_readonly(user_id: int) -> bool:
    try:
        from services.database import get_user
        user = get_user(user_id)
        return user is not None and user.get("role") == "readonly"
    except Exception:
        return False


_DOMAIN_PATTERN = re.compile(r'^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$')
_PACKAGE_PATTERN = re.compile(r'^[a-z0-9][a-z0-9\+\\.\\-]*$')


def validate_ip(text: str) -> Optional[str]:
    text = text.strip()
    try:
        ip = ipaddress.ip_address(text)
        return str(ip)
    except ValueError:
        return None


def validate_domain(text: str) -> Optional[str]:
    text = text.strip().lower()
    if _DOMAIN_PATTERN.match(text) and len(text) <= 253:
        return text
    return None


def validate_hostname(text: str) -> Optional[str]:
    ip = validate_ip(text)
    if ip:
        return ip
    return validate_domain(text)


def validate_package_name(text: str) -> Optional[str]:
    text = text.strip().lower()
    if _PACKAGE_PATTERN.match(text) and len(text) <= 128:
        return text
    return None


def validate_file_path(text: str, allowed_prefixes: Optional[List[str]] = None) -> Optional[str]:
    text = text.strip()
    if not text:
        return None

    try:
        path = Path(text).resolve()
    except (RuntimeError, OSError):
        return None

    if allowed_prefixes:
        allowed = False
        for prefix in allowed_prefixes:
            try:
                prefix_path = Path(prefix).resolve()
                if path == prefix_path or path.is_relative_to(prefix_path):
                    allowed = True
                    break
            except (RuntimeError, OSError):
                continue
        if not allowed:
            return None

    return str(path)


def validate_fim_path(path: str) -> Optional[str]:
    from config import settings
    prefixes = [str(p) for p in settings.paths.fim_allowed_prefixes]
    return validate_file_path(path, prefixes)


class SafeCommandError(Exception):
    pass


def run_command(args: List[str], timeout: int = 30, max_output: int = 100_000) -> str:
    if not args:
        raise SafeCommandError("Empty command args")

    log.debug("Running: %s ...", " ".join(str(a) for a in args[:4]))

    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

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
