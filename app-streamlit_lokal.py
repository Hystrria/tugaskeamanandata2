import streamlit as st
import pyotp, qrcode, io, base64, bcrypt, secrets, json
from datetime import datetime

st.set_page_config(page_title="MFA Lokal (Simulasi)", page_icon="🔐", layout="centered")

# =======================
# Penyimpanan "lokal"
# =======================
# Demi simulasi, kita simpan data di session_state (volatile).
if "users" not in st.session_state:
    # users[username] = {pwd_hash: bytes, totp_secret: str|None, backup_codes: [str], mfa_enabled: bool}
    st.session_state.users = {}
if "auth" not in st.session_state:
    st.session_state.auth = {
        "username": None, "first_factor_ok": False, "mfa_required": False, "mfa_complete": False
    }
if "audit" not in st.session_state:
    st.session_state.audit = []  # list of dicts

def log_attempt(username, typ, success):
    st.session_state.audit.insert(0, {
        "time": datetime.now().isoformat(timespec="seconds"),
        "username": username,
        "type": typ,
        "success": bool(success),
    })

# =======================
# Util keamanan
# =======================
def hash_pwd(p: str) -> bytes:
    return bcrypt.hashpw(p.encode("utf-8"), bcrypt.gensalt())

def check_pwd(p: str, h: bytes) -> bool:
    try: return bcrypt.checkpw(p.encode("utf-8"), h)
    except: return False

def b64_qr(uri: str) -> str:
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(uri); qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO(); img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()

# =======================
# UI
# =======================
st.title("🔐 MFA Lokal (Password + TOTP + Backup Codes) — Simulasi")

with st.sidebar:
    page = st.radio("Navigasi", [
        "Register", "Login (Faktor 1)", "Setup TOTP", "Verifikasi TOTP",
        "Verifikasi Backup Code", "Protected Resource", "Riwayat"
    ], index=1)
    st.caption("Semua data hanya di memori (session_state).")

def require_login():
    if not st.session_state.auth["first_factor_ok"]:
        st.warning("Silakan login dulu (faktor 1).")
        st.stop()

def require_full_auth():
    if st.session_state.auth["mfa_required"] and not st.session_state.auth["mfa_complete"]:
        st.error("MFA diperlukan. Selesaikan verifikasi TOTP atau backup code.")
        st.stop()

# ----------------------- Register -----------------------
if page == "Register":
    st.subheader("🆕 Register (lokal)")
    with st.form("reg"):
        u = st.text_input("Username")
        p = st.text_input("Password", type="password")
        submit = st.form_submit_button("Daftar")
    if submit:
        if not u or not p:
            st.error("Isi username & password.")
        elif u in st.session_state.users:
            st.error("Username sudah dipakai.")
        else:
            st.session_state.users[u] = {
                "pwd_hash": hash_pwd(p),
                "totp_secret": None,
                "backup_codes": [],
                "mfa_enabled": False,
            }
            st.success("Registrasi berhasil. Lanjut ke Login.")

# ----------------------- Login faktor 1 -----------------------
elif page == "Login (Faktor 1)":
    st.subheader("🔑 Login (Password)")
    with st.form("login"):
        u = st.text_input("Username")
        p = st.text_input("Password", type="password")
        submit = st.form_submit_button("Login")
    if submit:
        user = st.session_state.users.get(u)
        if not user or not check_pwd(p, user["pwd_hash"]):
            log_attempt(u or "-", "PASSWORD", False)
            st.error("Username/password salah.")
        else:
            st.session_state.auth.update({
                "username": u,
                "first_factor_ok": True,
                "mfa_required": bool(user["mfa_enabled"]),
                "mfa_complete": False,
            })
            log_attempt(u, "PASSWORD", True)
            st.success("Login faktor-1 OK.")
            if user["mfa_enabled"]:
                st.info("MFA aktif → lanjutkan Verifikasi TOTP atau Backup Code.")
            else:
                st.warning("MFA belum aktif → buka Setup TOTP.")

# ----------------------- Setup TOTP -----------------------
elif page == "Setup TOTP":
    st.subheader("📲 Setup TOTP (Authenticator App)")
    require_login()
    u = st.session_state.auth["username"]
    user = st.session_state.users[u]

    if st.button("Buat Secret + QR"):
        # generate secret & backup codes
        secret = pyotp.random_base32()
        user["totp_secret"] = secret
        user["backup_codes"] = [secrets.token_hex(4).upper() for _ in range(8)]
        # provisioning URI & QR
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=u, issuer_name="MFA-Lokal-Demo")
        st.image(b64_qr(uri), caption="Scan di Google/Microsoft Authenticator/Aegis", use_column_width=False)
        with st.expander("Manual entry key"):
            st.code(secret)
        with st.expander("Backup codes (catat & simpan aman)"):
            st.write(user["backup_codes"])
        st.info("Setelah scan, masukkan kode 6 digit TOTP di bawah untuk MENGAKTIFKAN MFA.")

    token = st.text_input("Kode TOTP (6 digit) untuk aktivasi")
    if st.button("Verifikasi & Aktifkan MFA"):
        if not user.get("totp_secret"):
            st.error("Belum generate secret. Klik 'Buat Secret + QR' dulu.")
        else:
            ok = pyotp.TOTP(user["totp_secret"]).verify(token, valid_window=1)
            log_attempt(u, "TOTP_ACTIVATE", ok)
            if ok:
                user["mfa_enabled"] = True
                st.session_state.auth["mfa_required"] = True
                st.success("MFA diaktifkan ✅")
            else:
                st.error("Kode TOTP salah/kedaluwarsa.")

# ----------------------- Verify TOTP -----------------------
elif page == "Verifikasi TOTP":
    st.subheader("✅ Verifikasi TOTP")
    require_login()
    u = st.session_state.auth["username"]
    user = st.session_state.users[u]
    code = st.text_input("Masukkan kode TOTP (6 digit)")
    if st.button("Verifikasi"):
        if not (user["mfa_enabled"] and user["totp_secret"]):
            st.error("MFA belum aktif / TOTP belum disetup.")
        else:
            ok = pyotp.TOTP(user["totp_secret"]).verify(code, valid_window=1)
            log_attempt(u, "TOTP_LOGIN", ok)
            if ok:
                st.session_state.auth["mfa_complete"] = True
                st.success("Login sukses via TOTP! 🎉")
            else:
                st.error("Kode TOTP salah/kedaluwarsa.")

# ----------------------- Verify Backup code -----------------------
elif page == "Verifikasi Backup Code":
    st.subheader("🛟 Verifikasi Backup Code")
    require_login()
    u = st.session_state.auth["username"]
    user = st.session_state.users[u]
    code = st.text_input("Masukkan backup code")
    if st.button("Verifikasi"):
        if code.upper() in user["backup_codes"]:
            user["backup_codes"].remove(code.upper())  # sekali pakai
            st.session_state.auth["mfa_complete"] = True
            log_attempt(u, "BACKUP_CODE", True)
            st.success("Login sukses via Backup Code! 🎉")
        else:
            log_attempt(u, "BACKUP_CODE", False)
            st.error("Backup code tidak valid / sudah dipakai.")

# ----------------------- Protected resource -----------------------
elif page == "Protected Resource":
    st.subheader("🛡️ Resource Terproteksi")
    require_login(); require_full_auth()
    st.success("Akses diberikan!")
    st.json({
        "message": "Access granted",
        "username": st.session_state.auth["username"],
        "timestamp": datetime.now().isoformat(timespec="seconds")
    })

# ----------------------- Audit / Riwayat -----------------------
elif page == "Riwayat":
    st.subheader("🧾 Riwayat Percobaan Auth/MFA (Audit lokal)")
    if not st.session_state.audit:
        st.info("Belum ada riwayat.")
    else:
        st.table(st.session_state.audit)
