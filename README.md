# NoteItUp

A cozy, liquid-glass notes app that runs on your own computer (`localhost`). Write `.md` or `.txt`
notes, organise them in tabs, pin the important ones, keep to-do lists in **Tasks**, and lock private
notes with AES-256-GCM encryption. Several people can share one device, each with a private account.

## Run it

Python 3.10 or newer.

**Windows (PowerShell)**
```
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

**macOS / Linux**
```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open <http://127.0.0.1:5000>, create an account, and start writing.
The first run creates a `.env` file with a random `SECRET_KEY` and a `noteitup.db` database.
The server listens on `127.0.0.1` only, so other devices on your network can't reach it.

## Using it

| Do this | How |
| --- | --- |
| Switch notes | Scroll, drag, click a side card, use the arrow buttons, or press the Left/Right arrow keys on the card strip |
| New note | **New note**, pick `.md` or `.txt` |
| Lock a note | **Lock** (or Ctrl+L), set a lock password. It is encrypted and saved as `Name.md.locked` |
| Open a locked note | Enter the lock password. It is decrypted in memory only |
| Remove a lock | Unlock the note, then **Remove lock permanently** |
| To-do lists | **Tasks** in the sidebar: lists, progress ring, up next |
| Shortcuts | Ctrl+S save, Ctrl+B bold, Ctrl+I italic, Ctrl+U underline, Ctrl+L lock |
| Themes | Settings: Cozy, Light, Dark, Midnight, plus accent colour, font, size, auto-logout |

> **A forgotten lock password cannot be recovered.** The key is derived from it and never stored.

## How the security works

* Login passwords: Argon2 (falls back to salted scrypt if `argon2-cffi` isn't installed). Never stored in plain text.
* Lock key: scrypt (N=2^15, r=8, p=1) with a random 16-byte salt per file.
* Encryption: AES-256-GCM, fresh random 12-byte nonce on every save. File layout is `salt + nonce + ciphertext + tag`.
  A wrong password and a tampered file fail the same way and reveal nothing.
* Locking writes the `.locked` file, reads it back and verifies it decrypts, and only then deletes the plain file.
* Lock passwords and keys are never written to disk. While a locked note is open, the password lives in a
  JavaScript variable in the page, and is dropped when you switch notes, lock again or close the tab.
* Sessions use HttpOnly, SameSite cookies. Every state-changing request needs a CSRF token.
* Login and unlock attempts are rate limited (5 failures per 5 minutes).
* Every query and file path is scoped to the signed-in user. Notes are saved via temp file + atomic replace.
* Responses are sent with `Cache-Control: no-store` and a strict Content-Security-Policy.

## Files

```
app.py            app factory + run
config.py         settings, .env secret key
models.py         SQLite schema
security.py       password hashing, CSRF, rate limiter, guards
crypto_utils.py   all encryption code (the only place that touches keys)
routes/           auth.py, notes.py (notes, tabs, lock), tasks.py, settings.py
templates/        login, register, terms, app
static/           css/app.css, js/app.js, js/auth.js, img/ (your app icon)
storage/<user>/   the real .md / .txt / .locked files
tests/            python -m unittest discover -s tests
```

## Tests

```
python -m unittest discover -s tests
```

Covers encryption (round trip, wrong password, every flipped byte detected), the lock/unlock flow,
CSRF, rate limits, user isolation, tabs, tasks and settings.

## Notes and limits

* `.txt` notes can't store bold, italic or underline. The UI says so. Use `.md` for formatting.
* Deleting a tab keeps its notes (they stay under All notes).
* The development server is fine for personal localhost use. Don't expose it to the internet.
* Back up the `storage/` folder and `noteitup.db` together.
