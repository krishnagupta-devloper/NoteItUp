"""All note encryption lives here.

Locked file format (one file):  salt (16) + nonce (12) + ciphertext + GCM tag (16)

* Key: scrypt(lock password, random per-file salt) -> 32 bytes
* Cipher: AES-256-GCM with a fresh random nonce every time a file is encrypted
* The GCM tag authenticates the data, so a wrong password and a tampered file
  both fail the same way, and nothing is revealed.

Keys and passwords are never written anywhere; they exist only for the duration
of a call.
"""
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
KEY_LEN = 32
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1


class DecryptionError(Exception):
    """Wrong password, or the locked file was changed or is damaged."""


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password.encode("utf-8"))


def encrypt(password: str, plaintext: bytes) -> bytes:
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    ciphertext_and_tag = AESGCM(derive_key(password, salt)).encrypt(nonce, plaintext, None)
    return salt + nonce + ciphertext_and_tag


def decrypt(password: str, blob: bytes) -> bytes:
    if len(blob) < SALT_LEN + NONCE_LEN + TAG_LEN:
        raise DecryptionError("Locked file is too short to be valid.")
    salt = blob[:SALT_LEN]
    nonce = blob[SALT_LEN:SALT_LEN + NONCE_LEN]
    ciphertext_and_tag = blob[SALT_LEN + NONCE_LEN:]
    try:
        return AESGCM(derive_key(password, salt)).decrypt(nonce, ciphertext_and_tag, None)
    except InvalidTag as exc:
        raise DecryptionError("Wrong password, or the file was modified.") from exc
