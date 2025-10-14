# mfa_demo.py
# MFA: Password + TOTP + Backup Codes (tanpa library eksternal)
import base64
import hmac
import hashlib
import os
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# =========================
# Util: Password Hashing
# =========================
def hash_password(password: str, salt: Optional[bytes] = None, *, rounds: int = 150_000) -> Tuple[bytes, bytes]:
    """
    Hash password dengan PBKDF2-HMAC-SHA256.
    Return: (salt, hash)
    """
    if salt is None:
        salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds, dklen=32)
    return salt, pwd_hash

def verify_password(password: str, salt: bytes, expected_hash: bytes, *, rounds: int = 150_000) -> bool:
    _, pwd_hash = hash_password(password, salt, rounds=rounds)
    # constant-time compare
    return hmac.compare_digest(pwd_hash, expected_hash)

# =========================
# Util: HOTP / TOTP
# =========================
def _int_to_bytes(i: int) -> bytes:
    return i.to_bytes(8, byteorder="big")

def hotp(secret_b32: str, counter: int, digits: int = 6, algo: str = "sha1") -> str:
    """
    HOTP: RFC 4226. secret adalah Base32 (tanpa spasi), counter 64-bit.
    """
    key = base64.b32decode(secret_b32.upper().replace(" ", ""))
    msg = _int_to_bytes(counter)
    if algo.lower() != "sha1":
        raise ValueError("Demo ini hanya SHA1 untuk kesederhanaan")
    mac = hmac.new(key, msg, hashlib.sha1).digest()
    # dynamic truncation
    offset = mac[-1] & 0x0F
    code_int = ((mac[offset] & 0x7F) << 24) | (mac[offset+1] << 16) | (mac[offset+2] << 8) | mac[offset+3]
    code = code_int % (10 ** digits)
    return str(code).zfill(digits)

def totp(secret_b32: str, timestamp: Optional[int] = None, step: int = 30, t0: int = 0, digits: int = 6) -> str:
    """
    TOTP: RFC 6238 (berbasis HOTP). Default SHA1, 6 digit, 30s step.
    """
    if timestamp is None:
        timestamp = int(time.time())
    counter = int((timestamp - t0) // step)
    return hotp(secret_b32, counter, digits=digits, algo="sha1")

def verify_totp(secret_b32: str, code: str, window: int = 1, step: int = 30, digits: int = 6) -> bool:
    """
    Verifikasi TOTP dengan toleransi 'window' step (untuk drift waktu).
    window=1 berarti cek step saat ini, sebelumnya, dan sesudahnya.
    """
    now = int(time.time())
    # izinkan +/- window
    for w in range(-window, window + 1):
        candidate = totp(secret_b32, timestamp=now + (w * step), step=step, digits=digits)
        if hmac.compare_digest(candidate, str(code).zfill(digits)):
            return True
    return False

# =========================
# Backup Codes
# =========================
def generate_backup_code(n_chars: int = 10) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # tanpa karakter mudah tertukar (I,1,O,0)
    return "".join(alphabet[ord(os.urandom(1)) % len(alphabet)] for _ in range(n_chars))

def hash_backup_code(code: str) -> str:
    # Simpel: SHA256 hex (di dunia nyata bisa tambah salt/pepper terpisah)
    return hashlib.sha256(code.encode("utf-8")).hexdigest()

# =========================
# User Store & MFA Logic
# =========================
@dataclass
class UserRecord:
    username: str
    pwd_salt: bytes
    pwd_hash: bytes
    totp_secret_b32: str
    backup_hashes: List[str] = field(default_factory=list)
    failed_attempts: int = 0
    lock_until_epoch: int = 0

class InMemoryUserStore:
    def __init__(self):
        self.users: Dict[str, UserRecord] = {}

    def create_user(self, username: str, password: str, *, totp_secret_b32: Optional[str] = None, backup_count: int = 5) -> Tuple[UserRecord, List[str]]:
        if username in self.users:
            raise ValueError("Username sudah ada")
        salt, pwd_hash = hash_password(password)
        if totp_secret_b32 is None:
            # secret TOTP 20 bytes, Base32 (kompatibel Google Authenticator/Aegis/Authenticator App)
            secret = base64.b32encode(os.urandom(20)).decode("utf-8").replace("=", "")
        else:
            secret = totp_secret_b32.replace(" ", "")
        # generate backup codes (disimpan hash; plain dibalikan untuk dicatat user)
        backup_plain = [generate_backup_code() for _ in range(backup_count)]
        backup_hashes = [hash_backup_code(b) for b in backup_plain]
        rec = UserRecord(username=username, pwd_salt=salt, pwd_hash=pwd_hash,
                         totp_secret_b32=secret, backup_hashes=backup_hashes)
        self.users[username] = rec
        return rec, backup_plain

    def get(self, username: str) -> Optional[UserRecord]:
        return self.users.get(username)

# =========================
# MFA Flow
# =========================
class MFAService:
    def __init__(self, store: InMemoryUserStore):
        self.store = store
        # kebijakan sederhana
        self.max_failed = 5
        self.lock_seconds = 5 * 60  # kunci 5 menit

    def _is_locked(self, user: UserRecord) -> bool:
        return time.time() < user.lock_until_epoch

    def _register_failure(self, user: UserRecord):
        user.failed_attempts += 1
        if user.failed_attempts >= self.max_failed:
            user.lock_until_epoch = int(time.time()) + self.lock_seconds
            user.failed_attempts = 0  # reset counter setelah lock

    def _register_success(self, user: UserRecord):
        user.failed_attempts = 0
        user.lock_until_epoch = 0

    def primary_auth(self, username: str, password: str) -> Tuple[bool, str]:
        user = self.store.get(username)
        if not user:
            return False, "User tidak ditemukan"
        if self._is_locked(user):
            sisa = int(user.lock_until_epoch - time.time())
            return False, f"Akun terkunci. Coba lagi dalam {sisa} detik."
        if verify_password(password, user.pwd_salt, user.pwd_hash):
            # jangan reset success di sini; final success setelah MFA
            return True, "Password benar. Lanjut MFA (TOTP/backup code)."
        else:
            self._register_failure(user)
            return False, "Password salah."

    def verify_totp_step(self, username: str, totp_code: str) -> Tuple[bool, str]:
        user = self.store.get(username)
        if not user:
            return False, "User tidak ditemukan"
        if self._is_locked(user):
            sisa = int(user.lock_until_epoch - time.time())
            return False, f"Akun terkunci. Coba lagi dalam {sisa} detik."
        ok = verify_totp(user.totp_secret_b32, totp_code, window=1, step=30, digits=6)
        if ok:
            self._register_success(user)
            return True, "MFA TOTP sukses. Login BERHASIL."
        else:
            self._register_failure(user)
            return False, "Kode TOTP salah atau kedaluwarsa."

    def verify_backup_code_step(self, username: str, backup_code_plain: str) -> Tuple[bool, str]:
        user = self.store.get(username)
        if not user:
            return False, "User tidak ditemukan"
        if self._is_locked(user):
            sisa = int(user.lock_until_epoch - time.time())
            return False, f"Akun terkunci. Coba lagi dalam {sisa} detik."
        hashed = hash_backup_code(backup_code_plain)
        if hashed in user.backup_hashes:
            # one-time use
            user.backup_hashes.remove(hashed)
            self._register_success(user)
            return True, "MFA via backup code sukses. Login BERHASIL."
        else:
            self._register_failure(user)
            return False, "Backup code tidak valid/terpakai."

# =========================
# Demo CLI
# =========================
def demo():
    print("=== DEMO MFA (Password + TOTP + Backup Codes) ===")
    store = InMemoryUserStore()
    svc = MFAService(store)

    # 1) Registrasi user baru
    rec, backups = store.create_user("andi", "PasswordKuat!2025", backup_count=3)
    print(f"[REGISTRASI] username=andi")
    print(f"  TOTP SECRET (Base32): {rec.totp_secret_b32}")
    print("  Simpan secret ini di Authenticator App (manual entry).")
    print(f"  Backup codes (SIMPAN RAPIH; sekali pakai): {', '.join(backups)}\n")

    # 2) Login: langkah 1 - password
    ok, msg = svc.primary_auth("andi", "PasswordKuat!2025")
    print(f"[LOGIN STEP 1] {msg}")
    if not ok:
        return

    # 3) Contoh menghasilkan TOTP saat ini (di server untuk tujuan demo/tes),
    #    di dunia nyata, code ini dihasilkan di perangkat user (Authenticator App).
    now_totp = totp(rec.totp_secret_b32)
    print(f"  (DEBUG DEMO) TOTP saat ini (6 digit): {now_totp}")

    # 4) Login: langkah 2a - verifikasi TOTP
    ok2, msg2 = svc.verify_totp_step("andi", now_totp)
    print(f"[LOGIN STEP 2 - TOTP] {msg2}")

    # 5) Contoh: jika TOTP gagal, user dapat memakai backup code
    #    (kita pakai salah satu yang sudah digenerate).
    if not ok2:
        print("Mencoba pakai backup code ...")
        ok3, msg3 = svc.verify_backup_code_step("andi", backups[0])
        print(f"[LOGIN STEP 2 - BACKUP] {msg3}")

if __name__ == "__main__":
    demo()
