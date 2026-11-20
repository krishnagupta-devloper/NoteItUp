"""Login password hashing, CSRF protection, rate limiting and auth guards."""
import hashlib
import hmac
import os
import secrets
import threading
import time
from collections import defaultdict, deque
from functools import wraps

from flask import abort, g, jsonify, redirect, request, session, url_for

from models import get_db

# ---- password hashing --------------------------------------------------------
# Argon2 when argon2-cffi is installed (recommended); salted scrypt otherwise.
try:
    from argon2 import PasswordHasher
    from argon2.exceptions import InvalidHashError, VerificationError

    _argon = PasswordHasher()
except ImportError:  # pragma: no cover - depends on the environment
    _argon = None

_SCRYPT = dict(n=2**14, r=8, p=1, dklen=32)
_dummy_hash = None


def hash_password(password: str) -> str:
    if _argon:
        return _argon.hash(password)
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, **_SCRYPT)
    return f"scrypt${salt.hex()}${digest.hex()}"


def verify_password(stored: str, password: str) -> bool:
    if stored.startswith("$argon2"):
        if not _argon:
            return False
        try:
            return _argon.verify(stored, password)
        except (VerificationError, InvalidHashError):
            return False
    if stored.startswith("scrypt$"):
        _, salt_hex, digest_hex = stored.split("$")
        digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), **_SCRYPT)
        return hmac.compare_digest(digest, bytes.fromhex(digest_hex))
    return False


def burn_hash_time(password: str) -> None:
    """Spend the same time as a real check so unknown user IDs aren't detectable."""
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = hash_password("not-a-real-password")
    verify_password(_dummy_hash, password)


# ---- CSRF ----------------------------------------------------------------------
def csrf_token() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def check_csrf() -> None:
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    expected = session.get("csrf")
    sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
    if not expected or not hmac.compare_digest(sent.encode(), expected.encode()):
        abort(400, description="Security check failed. Reload the page and try again.")


# ---- rate limiting (in memory, per process) -----------------------------------
class RateLimiter:
    def __init__(self):
        self._fails = defaultdict(deque)
        self._lock = threading.Lock()

    def wait_time(self, key: str, limit: int, window: int) -> int:
        """Seconds left to wait if `key` already failed `limit` times in `window`."""
        now = time.time()
        with self._lock:
            q = self._fails[key]
            while q and now - q[0] > window:
                q.popleft()
            return int(window - (now - q[0])) + 1 if len(q) >= limit else 0

    def fail(self, key: str) -> None:
        with self._lock:
            self._fails[key].append(time.time())

    def clear(self, key: str) -> None:
        with self._lock:
            self._fails.pop(key, None)

    def reset_all(self) -> None:
        with self._lock:
            self._fails.clear()


limiter = RateLimiter()


def wait_text(seconds: int) -> str:
    minutes = max(1, round(seconds / 60))
    return f"{minutes} minute" + ("" if minutes == 1 else "s")


# ---- current user + guards ----------------------------------------------------
def load_user() -> None:
    """Attach the signed-in user to `g`, enforcing the user's inactivity timeout."""
    g.user = None
    uid = session.get("uid")
    if not uid:
        return
    row = get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if row is None:
        session.clear()
        return
    limit = row["idle_minutes"] * 60
    if limit and time.time() - session.get("last_seen", 0) > limit:
        session.clear()
        return
    g.user = row
    session["last_seen"] = time.time()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)

    return wrapped


def api_guard():
    """before_request hook for every /api blueprint."""
    if g.user is None:
        return jsonify(error="Your session ended. Sign in again."), 401
    return None
