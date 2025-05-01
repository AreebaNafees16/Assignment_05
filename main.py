
# Enhanced Streamlit Secure Data System with Improved UI
import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import uuid
from packaging import version

# Version Check
if version.parse(st.__version__) < version.parse("1.12.0"):
    st.warning("Please upgrade Streamlit to version 1.12.0 or higher for full functionality")

# Config
CONFIG_FILE = "secure_data_config.json"
MAX_ATTEMPTS = 3
LOCKOUT_TIME = 300
SESSION_EXPIRY = 1800

# Key Management
def get_encryption_key():
    if os.path.exists("secret.key"):
        with open("secret.key", "rb") as key_file:
            return key_file.read()
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    return key

KEY = get_encryption_key()
cipher = Fernet(KEY)

# Hashing

def hash_passkey(passkey, salt=None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    hashed = base64.urlsafe_b64encode(kdf.derive(passkey.encode()))
    return hashed, salt

# Data I/O

def load_data():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except:
            pass
    return {"stored_data": {}, "user_sessions": {}, "failed_attempts": {}, "lockouts": {}}

def save_data(data):
    with open(CONFIG_FILE, "w") as f:
        json.dump(data, f)

if 'data' not in st.session_state:
    st.session_state.data = load_data()

# Session

def create_session(user_id):
    session_id = str(uuid.uuid4())
    expiry = time.time() + SESSION_EXPIRY
    st.session_state.data['user_sessions'][user_id] = {'session_id': session_id, 'expiry': expiry}
    save_data(st.session_state.data)
    return session_id

def validate_session(user_id, session_id):
    session = st.session_state.data['user_sessions'].get(user_id)
    if not session or session['session_id'] != session_id:
        return False
    if time.time() > session['expiry']:
        del st.session_state.data['user_sessions'][user_id]
        save_data(st.session_state.data)
        return False
    session['expiry'] = time.time() + SESSION_EXPIRY
    save_data(st.session_state.data)
    return True

# Encrypt / Decrypt

def encrypt_data(text, passkey):
    try:
        return cipher.encrypt(text.encode()).decode()
    except Exception as e:
        st.error(f"Encryption error: {str(e)}")


def decrypt_data(encrypted_text, passkey, hashed_passkey, salt):
    try:
        test_hash, _ = hash_passkey(passkey, salt)
        if test_hash != hashed_passkey:
            return None
        return cipher.decrypt(encrypted_text.encode()).decode()
    except Exception as e:
        st.error(f"Decryption error: {str(e)}")

# Lockouts

def check_lockout(user_id):
    lockout_time = st.session_state.data['lockouts'].get(user_id)
    if lockout_time and time.time() < lockout_time:
        return True, int(lockout_time - time.time())
    st.session_state.data['lockouts'].pop(user_id, None)
    save_data(st.session_state.data)
    return False, 0

def record_failed_attempt(user_id):
    attempts = st.session_state.data['failed_attempts'].get(user_id, 0) + 1
    st.session_state.data['failed_attempts'][user_id] = attempts
    if attempts >= MAX_ATTEMPTS:
        st.session_state.data['lockouts'][user_id] = time.time() + LOCKOUT_TIME
        del st.session_state.data['failed_attempts'][user_id]
    save_data(st.session_state.data)
    return attempts >= MAX_ATTEMPTS

def reset_attempts(user_id):
    st.session_state.data['failed_attempts'].pop(user_id, None)
    save_data(st.session_state.data)

# Pages

def login_page():
    st.markdown("## 🔐 User Login")
    with st.form("login_form"):
        username = st.text_input("👤 Username")
        password = st.text_input("🔑 Password", type="password")
        login = st.form_submit_button("Login")
    if login:
        if username and password:
            st.session_state['user_id'] = username
            st.session_state['session_id'] = create_session(username)
            st.session_state['authenticated'] = True
            st.success("✅ Logged in successfully!")
            st.rerun()
        else:
            st.error("❌ Please enter both fields.")

def logout():
    user_id = st.session_state.get('user_id')
    if user_id:
        st.session_state.data['user_sessions'].pop(user_id, None)
        save_data(st.session_state.data)
    st.session_state.clear()
    st.rerun()

def home_page():
    st.markdown("## 🏠 Welcome")
    st.write(f"Hello, **{st.session_state['user_id']}**!")
    st.markdown("""### 🔒 Features:
- Fernet Encryption
- PBKDF2 Hashed Passkeys
- Session Timeout
- Lockout After Failed Attempts
- JSON Data Persistence
    """)
    data_count = len(st.session_state.data['stored_data'].get(st.session_state['user_id'], {}))
    st.info(f"📊 You have **{data_count}** entries stored.")

def store_data_page():
    st.markdown("### 📝 Store Data")
    st.divider()
    with st.form("store_form"):
        col1, col2 = st.columns(2)
        with col1:
            data_name = st.text_input("Data Name")
        with col2:
            passkey = st.text_input("Passkey", type="password")
        data_content = st.text_area("Enter Data")
        confirm_passkey = st.text_input("Confirm Passkey", type="password")
        submit = st.form_submit_button("Encrypt & Save")

    if submit:
        if not all([data_name, data_content, passkey, confirm_passkey]):
            st.error("⚠️ Fill in all fields.")
            return
        if passkey != confirm_passkey:
            st.error("❌ Passkeys do not match!")
            return
        if len(passkey) < 8:
            st.warning("Use a strong passkey (8+ chars).")
        data_id = str(uuid.uuid4())
        hashed_passkey, salt = hash_passkey(passkey)
        encrypted = encrypt_data(data_content, passkey)
        if not encrypted:
            return
        user_data = st.session_state.data['stored_data'].setdefault(st.session_state['user_id'], {})
        user_data[data_id] = {
            "name": data_name,
            "encrypted_text": encrypted,
            "hashed_passkey": hashed_passkey.decode(),
            "salt": base64.b64encode(salt).decode(),
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        save_data(st.session_state.data)
        st.success("✅ Data stored securely!")
        st.toast("Data saved.")
        st.balloons()

def retrieve_data_page():
    st.markdown("### 🔍 Retrieve Data")
    st.divider()
    user_id = st.session_state['user_id']
    is_locked, remaining = check_lockout(user_id)
    if is_locked:
        st.error(f"🔒 Locked out. Try again in {remaining//60}m {remaining%60}s")
        return
    user_data = st.session_state.data['stored_data'].get(user_id, {})
    if not user_data:
        st.warning("No data stored.")
        return
    options = {v['name']: k for k, v in user_data.items()}
    selected = st.selectbox("Select Entry", list(options.keys()))
    data_id = options[selected]
    passkey = st.text_input("Enter Passkey", type="password")
    if st.button("Decrypt"):
        entry = user_data[data_id]
        salt = base64.b64decode(entry['salt'].encode())
        decrypted = decrypt_data(entry['encrypted_text'], passkey, entry['hashed_passkey'].encode(), salt)
        if decrypted:
            reset_attempts(user_id)
            st.success("✅ Decrypted successfully!")
            st.text_area("Decrypted Data", decrypted, height=150)
            st.markdown(f"**Created at:** {entry['created_at']}")
        else:
            if record_failed_attempt(user_id):
                st.error("🔒 Too many attempts. Locked out.")
                st.rerun()
            else:
                left = MAX_ATTEMPTS - st.session_state.data['failed_attempts'].get(user_id, 0)
                st.error(f"Incorrect passkey. {left} attempts left.")

def manage_data_page():
    st.markdown("### 🗃️ Manage Data")
    st.divider()
    user_data = st.session_state.data['stored_data'].get(st.session_state['user_id'], {})
    if not user_data:
        st.info("No data entries available.")
        return
    for data_id, entry in user_data.items():
        with st.expander(f"{entry['name']} (Created: {entry['created_at']})"):
            st.code(entry['encrypted_text'])
            if st.button(f"🗑 Delete {entry['name']}", key=data_id):
                del user_data[data_id]
                save_data(st.session_state.data)
                st.success("Entry deleted.")
                st.rerun()

def account_settings_page():
    st.markdown("### ⚙️ Account Settings")
    st.divider()
    st.write(f"Logged in as: **{st.session_state['user_id']}**")
    with st.form("password_form"):
        old = st.text_input("Current Password", type="password")
        new = st.text_input("New Password", type="password")
        confirm = st.text_input("Confirm New Password", type="password")
        update = st.form_submit_button("Update Password")
    if update:
        if not all([old, new, confirm]):
            st.error("Please fill in all fields.")
        elif new != confirm:
            st.error("New passwords do not match.")
        else:
            st.success("(Simulated) Password updated.")

# Main App

def main():
    st.set_page_config(page_title="Secure Data System", page_icon="🔐")
    st.sidebar.image("https://www.svgrepo.com/show/216724/padlock-lock.svg", width=50)
    menu = ["Home", "Store Data", "Retrieve Data", "Manage Data", "Account Settings"]
    choice = st.sidebar.selectbox("Menu", menu)
    if st.sidebar.button("🚪 Logout"):
        logout()
    if not st.session_state.get('authenticated'):
        login_page()
        return
    if not validate_session(st.session_state['user_id'], st.session_state['session_id']):
        st.warning("⚠️ Session expired. Please log in again.")
        logout()
        return
    st.title("🔐 Secure Data System")
    if choice == "Home":
        home_page()
    elif choice == "Store Data":
        store_data_page()
    elif choice == "Retrieve Data":
        retrieve_data_page()
    elif choice == "Manage Data":
        manage_data_page()
    elif choice == "Account Settings":
        account_settings_page()
    st.markdown("---")
    st.caption("🔐 Secure Data System | Developed by Areeba Muhammad Nafees")

if __name__ == '__main__':
    main()
