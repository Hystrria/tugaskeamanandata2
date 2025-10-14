import os
import io
import json
import base64
from datetime import datetime, timedelta
import sqlite3
import secrets

import streamlit as st
import pyotp
import qrcode
from twilio.rest import Client
import bcrypt

# =========================
# Konfigurasi & Utilitas
# =========================

DB_PATH = os.getenv("MFA_DB_PATH", "mfa_system.db")

# Gunakan env var untuk kredensial Twilio (lebih aman)
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN  = os.getenv("TWILIO_AUTH_TOKEN", "")
TWILIO_PHONE_FROM  = os.getenv("TWILIO_PHONE_FROM", "")

DEV_ECHO_SMS_CODE = os.getenv("DEV_ECHO_SMS_CODE", "1") == "1"  # mode dev: tampilkan kode SMS di UI

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash BLOB NOT NULL,
            phone_number TEXT,
            totp_secret TEXT,
            backup_codes TEXT,
            mfa_enabled BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS mfa_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            attempt_type TEXT,
            success BOOLEAN,
            ip_address TEXT,
            attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    conn.commit()
    conn.close()

def hash_password(password: str) -> bytes:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt)

def verify_password(password: str, hashed: bytes) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed)
    except Exception:
        return False

def b64_qr_image(data: str) -> str:
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()

def log_attempt(user_id: int, attempt_type: str, success: bool, ip_address: str = "127.0.0.1"):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO mfa_attempts (user_id, attempt_type, success, ip_address) VALUES (?, ?, ?, ?)",
        (user_id, attempt_type, success, ip_address)
    )
    conn.commit()
    conn.close()

def get_user_by_username(username: str):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    conn.close()
    return row

def get_user_by_id(user_id: int):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id=?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return row

# =========================
# Layanan MFA (fungsi DB)
# =========================

def register_user(username: str, password: str, phone_number: str | None):
    if not username or not password:
        return False, "Username dan password wajib diisi"
    if get_user_by_username(username):
        return False, "Username sudah terpakai"

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (username, password_hash, phone_number) VALUES (?, ?, ?)",
            (username, hash_password(password), phone_number)
        )
        conn.commit()
        return True, "Registrasi berhasil"
    except sqlite3.IntegrityError:
        return False, "Username sudah terpakai"
    finally:
        conn.close()

def authenticate_user(username: str, password: str):
    user = get_user_by_username(username)
    if not user:
        return False, None, "Username/password salah"
    if not verify_password(password, user["password_hash"]):
        return False, None, "Username/password salah"
    return True, user, "Autentikasi faktor-1 berhasil"

def setup_totp_for_user(user_id: int, issuer_name="MyApp"):
    secret = pyotp.random_base32()
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET totp_secret=? WHERE id=?", (secret, user_id))
    # generate backup codes
    backup_codes = [secrets.token_hex(4).upper() for _ in range(10)]
    cur.execute("UPDATE users SET backup_codes=? WHERE id=?", (json.dumps(backup_codes), user_id))
    conn.commit()
    # provisioning uri
    user = get_user_by_id(user_id)
    username = user["username"] if user else f"user{user_id}"
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name=issuer_name)
    return secret, backup_codes, uri

def verify_totp_code(user_id: int, token: str) -> tuple[bool, str]:
    user = get_user_by_id(user_id)
    if not user or not user["totp_secret"]:
        return False, "TOTP belum dikonfigurasi"
    totp = pyotp.TOTP(user["totp_secret"])
    ok = False
    try:
        ok = totp.verify(token, valid_window=1)
    except Exception:
        ok = False
    log_attempt(user_id, "TOTP", ok)
    return (True, "Verifikasi TOTP berhasil") if ok else (False, "Kode TOTP salah/kedaluwarsa")

def enable_mfa_for_user(user_id: int):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET mfa_enabled=TRUE WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    return True, "MFA berhasil diaktifkan"

# --- SMS OTP (opsional) ---
def _twilio_client():
    if not (TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_PHONE_FROM):
        return None
    try:
        return Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
    except Exception:
        return None

def send_sms_token(user_id: int):
    # Simpan token di session_state (demo lokal). Produksi: simpan di DB/Redis + expiry.
    token = f"{secrets.randbelow(1_000_000):06d}"
    expiry = datetime.now() + timedelta(minutes=5)
    st.session_state.setdefault("sms_tokens", {})
    st.session_state.sms_tokens[user_id] = {"token": token, "expiry": expiry}

    user = get_user_by_id(user_id)
    if not user or not user["phone_number"]:
        return False, "Nomor ponsel belum dikonfigurasi"

    client = _twilio_client()
    if client:
        try:
            client.messages.create(
                body=f"Your verification code is: {token}",
                from_=TWILIO_PHONE_FROM,
                to=user["phone_number"]
            )
            log_attempt(user_id, "SMS_SENT", True)
            return True, "Kode SMS dikirim (berlaku 5 menit)"
        except Exception as e:
            log_attempt(user_id, "SMS_SENT", False)
            return False, f"Gagal kirim SMS: {e}"
    else:
        # Mode dev: tampilkan di UI agar bisa dites tanpa Twilio
        log_attempt(user_id, "SMS_SENT_DEV", True)
        if DEV_ECHO_SMS_CODE:
            return True, f"[DEV] Kode SMS: {token} (kedaluwarsa 5 menit)"
        else:
            return True, "Kode SMS (dev) dibuat. (Tidak ditampilkan; aktifkan DEV_ECHO_SMS_CODE=1 untuk melihat)"

def verify_sms_token(user_id: int, token: str):
    entry = (st.session_state.get("sms_tokens") or {}).get(user_id)
    if not entry:
        return False, "Tidak ada token SMS aktif"
    if datetime.now() > entry["expiry"]:
        st.session_state.sms_tokens.pop(user_id, None)
        log_attempt(user_id, "SMS_VERIFY", False)
        return False, "Token SMS kedaluwarsa"
    ok = (entry["token"] == token)
    log_attempt(user_id, "SMS_VERIFY", ok)
    if ok:
        st.session_state.sms_tokens.pop(user_id, None)
        return True, "Verifikasi SMS berhasil"
    return False, "Token SMS salah"

# --- Backup codes ---
def verify_backup_code(user_id: int, code: str):
    user = get_user_by_id(user_id)
    if not user or not user["backup_codes"]:
        return False, "Backup codes tidak tersedia"
    codes = json.loads(user["backup_codes"])
    if code.upper() in codes:
        codes.remove(code.upper())
        conn = get_db()
        cur = conn.cursor()
        cur.execute("UPDATE users SET backup_codes=? WHERE id=?", (json.dumps(codes), user_id))
        conn.commit()
        conn.close()
        log_attempt(user_id, "BACKUP_CODE", True)
        return True, f"Backup code valid. Sisa: {len(codes)}"
    log_attempt(user_id, "BACKUP_CODE", False)
    return False, "Backup code tidak valid/terpakai"

def get_mfa_history(user_id: int, limit: int = 15):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT attempt_type, success, ip_address, attempt_time
        FROM mfa_attempts
        WHERE user_id=?
        ORDER BY attempt_time DESC
        LIMIT ?
    """, (user_id, limit))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows

# =========================
# Streamlit UI
# =========================

st.set_page_config(page_title="MFA Demo (Streamlit)", page_icon="🔐", layout="centered")
init_db()

if "auth" not in st.session_state:
    st.session_state.auth = {
        "user_id": None,
        "username": None,
        "first_factor_ok": False,
        "mfa_required": False,
        "mfa_complete": False,
    }

st.title("🔐 Implementasi MFA/2FA (Streamlit)")

with st.sidebar:
    st.markdown("### Navigasi")
    page = st.radio(
        "Pilih halaman:",
        ["Register", "Login", "Setup TOTP", "Verifikasi TOTP", "Kirim SMS", "Verifikasi SMS",
         "Verifikasi Backup Code", "Protected Resource", "Riwayat MFA", "Logout"],
        index=1
    )
    st.markdown("---")
    st.caption("Gunakan env var: TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_FROM")
    st.caption(f"DB: `{DB_PATH}`")

def require_first_factor():
    if not st.session_state.auth["first_factor_ok"]:
        st.warning("Harap login (faktor 1) terlebih dahulu di menu **Login**.")
        st.stop()

def require_fully_authenticated():
    if st.session_state.auth["mfa_required"] and not st.session_state.auth["mfa_complete"]:
        st.error("MFA diperlukan. Selesaikan verifikasi TOTP/SMS/Backup Code.")
        st.stop()

# ---- Register ----
if page == "Register":
    st.subheader("🆕 Registrasi")
    with st.form("register_form", clear_on_submit=False):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        phone = st.text_input("Nomor Ponsel (opsional, format E.164, mis. +62812xxxx)")
        submitted = st.form_submit_button("Daftar")
    if submitted:
        ok, msg = register_user(username, password, phone or None)
        (st.success if ok else st.error)(msg)

# ---- Login (Factor 1) ----
elif page == "Login":
    st.subheader("🔑 Login (Faktor 1)")
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")
    if submitted:
        ok, user, msg = authenticate_user(username, password)
        if ok:
            st.session_state.auth.update({
                "user_id": user["id"],
                "username": user["username"],
                "first_factor_ok": True,
                "mfa_required": bool(user["mfa_enabled"]),
                "mfa_complete": False,
            })
            st.success(msg)
            if user["mfa_enabled"]:
                st.info("MFA aktif. Lanjutkan ke **Verifikasi TOTP**, **Kirim/Verifikasi SMS**, atau **Verifikasi Backup Code**.")
            else:
                st.warning("MFA belum aktif. Silakan ke **Setup TOTP** lalu aktifkan MFA.")
        else:
            st.error(msg)

    if st.session_state.auth["first_factor_ok"]:
        st.info(f"Login sebagai: **{st.session_state.auth['username']}** (user_id={st.session_state.auth['user_id']})")
        st.write("Status MFA:", "Aktif" if st.session_state.auth["mfa_required"] else "Nonaktif")

# ---- Setup TOTP ----
elif page == "Setup TOTP":
    st.subheader("📲 Setup TOTP (Google/Microsoft Authenticator, Aegis, dsb.)")
    require_first_factor()

    if st.button("Generate Secret + QR"):
        secret, backup_codes, uri = setup_totp_for_user(st.session_state.auth["user_id"], issuer_name="StreamlitMFA")
        st.success("TOTP secret dibuat. Scan QR di aplikasi Authenticator.")
        b64img = b64_qr_image(uri)
        st.image(b64img, caption="Scan QR ini di aplikasi Authenticator", use_column_width=False)
        with st.expander("Manual Entry (kalau tidak bisa scan QR)"):
            st.code(secret, language="text")
        with st.expander("Backup Codes (catat & simpan aman)"):
            st.write(backup_codes)

    st.markdown("---")
    st.markdown("#### Aktifkan MFA")
    token = st.text_input("Masukkan kode TOTP saat ini (6 digit)")
    if st.button("Verifikasi & Aktifkan MFA"):
        ok, msg = verify_totp_code(st.session_state.auth["user_id"], token)
        if ok:
            ok2, msg2 = enable_mfa_for_user(st.session_state.auth["user_id"])
            st.session_state.auth["mfa_required"] = True
            (st.success if ok2 else st.error)(msg2)
        else:
            st.error(msg)

# ---- Verifikasi TOTP ----
elif page == "Verifikasi TOTP":
    st.subheader("✅ Verifikasi TOTP")
    require_first_factor()
    token = st.text_input("Kode TOTP (6 digit)")
    if st.button("Verifikasi"):
        ok, msg = verify_totp_code(st.session_state.auth["user_id"], token)
        if ok:
            st.session_state.auth["mfa_complete"] = True
            st.success("Login sukses via TOTP! 🎉")
        else:
            st.error(msg)

# ---- Kirim SMS ----
elif page == "Kirim SMS":
    st.subheader("📨 Kirim SMS OTP")
    require_first_factor()
    if st.button("Kirim Kode SMS"):
        ok, msg = send_sms_token(st.session_state.auth["user_id"])
        (st.success if ok else st.error)(msg)

# ---- Verifikasi SMS ----
elif page == "Verifikasi SMS":
    st.subheader("✅ Verifikasi SMS OTP")
    require_first_factor()
    token = st.text_input("Kode SMS (6 digit)")
    if st.button("Verifikasi"):
        ok, msg = verify_sms_token(st.session_state.auth["user_id"], token)
        if ok:
            st.session_state.auth["mfa_complete"] = True
            st.success("Login sukses via SMS! 🎉")
        else:
            st.error(msg)

# ---- Verifikasi Backup Code ----
elif page == "Verifikasi Backup Code":
    st.subheader("🛟 Verifikasi Backup Code")
    require_first_factor()
    code = st.text_input("Backup Code")
    if st.button("Verifikasi"):
        ok, msg = verify_backup_code(st.session_state.auth["user_id"], code)
        if ok:
            st.session_state.auth["mfa_complete"] = True
            st.success("Login sukses via Backup Code! 🎉")
        else:
            st.error(msg)

# ---- Protected Resource ----
elif page == "Protected Resource":
    st.subheader("🛡️ Resource Terproteksi")
    require_first_factor()
    require_fully_authenticated()
    st.success("Akses diberikan!")
    st.json({
        "message": "Access granted to protected resource!",
        "user_id": st.session_state.auth["user_id"],
        "username": st.session_state.auth["username"],
        "timestamp": datetime.now().isoformat()
    })

# ---- Riwayat MFA ----
elif page == "Riwayat MFA":
    st.subheader("🧾 Riwayat MFA")
    require_first_factor()
    rows = get_mfa_history(st.session_state.auth["user_id"], limit=30)
    if rows:
        st.table(rows)
    else:
        st.info("Belum ada riwayat.")

# ---- Logout ----
elif page == "Logout":
    st.subheader("🚪 Logout")
    st.write("Klik tombol di bawah untuk mengakhiri sesi.")
    if st.button("Logout"):
        st.session_state.auth = {
            "user_id": None,
            "username": None,
            "first_factor_ok": False,
            "mfa_required": False,
            "mfa_complete": False,
        }
        st.success("Berhasil logout.")
