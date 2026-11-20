"""NoteItUp configuration.

The app secret key lives in a local `.env` file, never in code. On first run a
random key is generated and written there.
"""
import os
import secrets
from pathlib import Path

from dotenv import load_dotenv, set_key

BASE_DIR = Path(__file__).resolve().parent
ENV_FILE = BASE_DIR / ".env"


def ensure_secret_key() -> str:
    load_dotenv(ENV_FILE)
    key = os.environ.get("SECRET_KEY")
    if not key:
        key = secrets.token_hex(32)
        ENV_FILE.touch(exist_ok=True)
        try:
            os.chmod(ENV_FILE, 0o600)
        except OSError:
            pass
        set_key(str(ENV_FILE), "SECRET_KEY", key)
        os.environ["SECRET_KEY"] = key
    return key


class Config:
    DATABASE = str(BASE_DIR / "noteitup.db")
    STORAGE_DIR = str(BASE_DIR / "storage")
    HOST = os.environ.get("HOST", "127.0.0.1")  # localhost only by default
    PORT = int(os.environ.get("PORT", "5000"))

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    # Browsers differ on Secure cookies over plain http://localhost, so this is opt-in.
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "0") == "1"
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2 MB per request
