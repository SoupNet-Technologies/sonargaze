"""Key storage: keyring first, then environment, then a 0600 env file.

Lookup order is api_key argument, SONARGAZE_API_KEY, SHODAN_API_KEY, the OS
keyring, then .env in the working directory or ~/.config/sonargaze/.env.
"""

from __future__ import annotations

import contextlib
import os
import stat
from pathlib import Path

ENV_VARS = ("SONARGAZE_API_KEY", "SHODAN_API_KEY")
KEYRING_SERVICE = "sonargaze"
KEYRING_USER = "shodan-api-key"
MASK = "\u2022" * 8


class ConfigError(Exception):
    """No usable API key could be found."""


def config_dir() -> Path:
    """Per-user config directory, honouring XDG on Linux."""
    override = os.environ.get("SONARGAZE_CONFIG_DIR")
    if override:
        return Path(override).expanduser()
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".config"
    return base / "sonargaze"


def env_file_candidates(cwd: Path | None = None) -> list[Path]:
    return [Path(cwd or Path.cwd()) / ".env", config_dir() / ".env"]


def parse_env_file(path: Path) -> dict[str, str]:
    """Minimal ``KEY=VALUE`` reader: ``#`` comments, optional quotes, no magic."""
    values: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return values
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export ") :]
        name, _, raw = line.partition("=")
        name = name.strip()
        value = raw.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if name:
            values[name] = value
    return values


def _keyring_get() -> str | None:
    try:
        import keyring
    except Exception:
        return None
    try:
        return keyring.get_password(KEYRING_SERVICE, KEYRING_USER)
    except Exception:
        return None


def _keyring_set(api_key: str) -> bool:
    try:
        import keyring
    except Exception:
        return False
    try:
        keyring.set_password(KEYRING_SERVICE, KEYRING_USER, api_key)
        return True
    except Exception:
        return False


def _keyring_delete() -> bool:
    try:
        import keyring
    except Exception:
        return False
    try:
        keyring.delete_password(KEYRING_SERVICE, KEYRING_USER)
        return True
    except Exception:
        return False


def find_api_key(api_key: str | None = None, *, cwd: Path | None = None) -> str | None:
    """Return the first API key we can find, or ``None``."""
    # explicit beats environment beats stored key
    if api_key and api_key.strip():
        return api_key.strip()
    for name in ENV_VARS:
        value = os.environ.get(name)
        if value and value.strip():
            return value.strip()
    stored = _keyring_get()
    if stored and stored.strip():
        return stored.strip()
    for path in env_file_candidates(cwd):
        values = parse_env_file(path)
        for name in ENV_VARS:
            value = values.get(name)
            if value and value.strip():
                return value.strip()
    return None


def require_api_key(api_key: str | None = None, *, cwd: Path | None = None) -> str:
    key = find_api_key(api_key, cwd=cwd)
    if not key:
        raise ConfigError(
            "No Shodan API key found. Run `sonargaze key set` (reads stdin), "
            "or export SHODAN_API_KEY, or put SHODAN_API_KEY=... in "
            f"{env_file_candidates(cwd)[-1]}."
        )
    return key


def save_api_key(api_key: str, *, prefer_keyring: bool = True) -> str:
    """Store the key in the OS keyring when possible, else a 0600 env file.

    Returns a short human description of where it went.
    """
    api_key = (api_key or "").strip()
    if not api_key:
        raise ConfigError("refusing to save an empty API key")
    if prefer_keyring and _keyring_set(api_key):
        return f"OS keyring ({KEYRING_SERVICE})"
    path = config_dir() / ".env"
    path.parent.mkdir(parents=True, exist_ok=True)
    remaining: dict[str, str] = {}
    if path.exists():
        for name, value in parse_env_file(path).items():
            if name not in ENV_VARS:
                remaining[name] = value
    lines = ["# sonargaze: local secrets, never commit this file"]
    lines += [f"{name}={value}" for name, value in remaining.items()]
    lines.append(f"SHODAN_API_KEY={api_key}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with contextlib.suppress(OSError):
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return str(path)


def clear_api_key() -> list[str]:
    """Best-effort removal from keyring and env file. Returns what was cleared."""
    cleared: list[str] = []
    if _keyring_delete():
        cleared.append(f"OS keyring ({KEYRING_SERVICE})")
    path = config_dir() / ".env"
    if path.exists():
        try:
            kept = [
                f"{name}={value}"
                for name, value in parse_env_file(path).items()
                if name not in ENV_VARS
            ]
            path.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
            cleared.append(str(path))
        except OSError:
            pass
    return cleared


def mask_key(api_key: str | None) -> str:
    """Never show a key; show that one exists and how long it is."""
    if not api_key:
        return "not configured"
    tail = api_key[-4:] if len(api_key) >= 12 else ""
    return f"{MASK}{tail} ({len(api_key)} chars)"
