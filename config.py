from dataclasses import dataclass
from pathlib import Path
import os

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
ENV_FILE = BASE_DIR / ".env"
load_dotenv(ENV_FILE)


def _require_env(name: str) -> str:
    val = os.getenv(name, "").strip()
    if not val:
        raise RuntimeError(f"{name} is required in .env")
    return val


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        return int(raw)
    except ValueError:
        return default


def _csv_paths(name: str, default: str) -> tuple[Path, ...]:
    raw = os.getenv(name, default)
    return tuple(Path(p.strip()) for p in raw.split(",") if p.strip())


@dataclass(frozen=True)
class PathSettings:
    base_dir: Path
    env_file: Path
    pid_file: Path
    bot_log_file: Path
    threat_intel_log_file: Path
    fim_file: Path
    report_file: Path
    auth_log_file: Path
    suricata_fast_log_file: Path
    sshd_config_file: Path
    nmap_path: Path
    root_path: Path
    fim_allowed_prefixes: tuple[Path, ...]


@dataclass(frozen=True)
class ApiSettings:
    telegram_token: str
    vt_api_key: str = ""
    abuse_api_key: str = ""
    hibp_api_key: str = ""
    sentry_dsn: str = ""
    webhook_url: str = ""
    webhook_port: int = 8443
    metrics_port: int = 9099
    locale: str = "en"


@dataclass(frozen=True)
class Settings:
    paths: PathSettings
    api: ApiSettings
    unauthorized_text: str = ""


def load_settings() -> Settings:
    token = _require_env("TELEGRAM_TOKEN")

    paths = PathSettings(
        base_dir=BASE_DIR,
        env_file=ENV_FILE,
        pid_file=Path(_env("PID_FILE", str(BASE_DIR / "bot.pid"))),
        bot_log_file=Path(_env("BOT_LOG_FILE", str(BASE_DIR / "bot.log"))),
        threat_intel_log_file=Path(_env("LOG_FILE", str(BASE_DIR / "threat_intel_log.md"))),
        fim_file=Path(_env("FIM_FILE", str(BASE_DIR / "fim_hashes.json"))),
        report_file=Path(_env("REPORT_FILE", "/tmp/cyber_volt_report.pdf")),
        auth_log_file=Path(_env("AUTH_LOG_FILE", "/var/log/auth.log")),
        suricata_fast_log_file=Path(_env("SURICATA_FAST_LOG_FILE", "/var/log/suricata/fast.log")),
        sshd_config_file=Path(_env("SSHD_CONFIG_FILE", "/etc/ssh/sshd_config")),
        nmap_path=Path(_env("NMAP_PATH", "/usr/bin/nmap")),
        root_path=Path(_env("ROOT_PATH", "/")),
        fim_allowed_prefixes=_csv_paths("FIM_ALLOWED_PREFIXES", "/etc,/root/cyber-volt"),
    )
    api = ApiSettings(
        telegram_token=token,
        vt_api_key=_env("VT_API_KEY"),
        abuse_api_key=_env("ABUSE_API_KEY"),
        hibp_api_key=_env("HIBP_API_KEY"),
        sentry_dsn=_env("SENTRY_DSN"),
        webhook_url=_env("WEBHOOK_URL"),
        webhook_port=_env_int("WEBHOOK_PORT", 8443),
        metrics_port=_env_int("METRICS_PORT", 9099),
        locale=_env("LOCALE", "en"),
    )
    return Settings(paths=paths, api=api)


settings = load_settings()
