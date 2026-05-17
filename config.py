"""Configuration for Cyber-Volt SOC Bot."""
from dataclasses import dataclass
from pathlib import Path
import os
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
ENV_FILE = BASE_DIR / ".env"
load_dotenv(ENV_FILE)


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


@dataclass(frozen=True)
class Settings:
    paths: PathSettings
    api: ApiSettings
    unauthorized_text: str = "❌ Unauthorized. Contact bot admin to add your ID to ALLOWED_USERS."


def _csv_paths(name: str, default: str) -> tuple[Path, ...]:
    raw = os.getenv(name, default)
    return tuple(Path(p.strip()) for p in raw.split(",") if p.strip())


def load_settings() -> Settings:
    token = os.getenv("TELEGRAM_TOKEN", "").strip()
    if not token:
        raise RuntimeError("TELEGRAM_TOKEN is required in .env")

    paths = PathSettings(
        base_dir=BASE_DIR,
        env_file=ENV_FILE,
        pid_file=Path(os.getenv("PID_FILE", BASE_DIR / "bot.pid")),
        bot_log_file=Path(os.getenv("BOT_LOG_FILE", BASE_DIR / "bot.log")),
        threat_intel_log_file=Path(os.getenv("LOG_FILE", BASE_DIR / "threat_intel_log.md")),
        fim_file=Path(os.getenv("FIM_FILE", BASE_DIR / "fim_hashes.json")),
        report_file=Path(os.getenv("REPORT_FILE", "/tmp/cyber_volt_report.pdf")),
        auth_log_file=Path(os.getenv("AUTH_LOG_FILE", "/var/log/auth.log")),
        suricata_fast_log_file=Path(os.getenv("SURICATA_FAST_LOG_FILE", "/var/log/suricata/fast.log")),
        sshd_config_file=Path(os.getenv("SSHD_CONFIG_FILE", "/etc/ssh/sshd_config")),
        nmap_path=Path(os.getenv("NMAP_PATH", "/usr/bin/nmap")),
        root_path=Path(os.getenv("ROOT_PATH", "/")),
        fim_allowed_prefixes=_csv_paths("FIM_ALLOWED_PREFIXES", "/etc,/root/cyber-volt"),
    )
    api = ApiSettings(
        telegram_token=token,
        vt_api_key=os.getenv("VT_API_KEY", ""),
        abuse_api_key=os.getenv("ABUSE_API_KEY", ""),
        hibp_api_key=os.getenv("HIBP_API_KEY", ""),
    )
    return Settings(paths=paths, api=api)


settings = load_settings()
