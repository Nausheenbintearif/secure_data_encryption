import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# ----- Initialize Session State -----
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}  # Format: {label: {"encrypted_text": ..., "passkey": ...}}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "is_logged_in" not in st.session_state:
    st.session_state.is_logged_in = True  # Controls access after lockout

# ----- Encryption Setup -----
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# ----- Utility Functions -----
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(plain_text):
    return cipher.encrypt(plain_text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# ----- Streamlit UI -----
st.set_page_config(page_title="Secure Vault", layout="centered")
st.title("🔐 Secure Data Vault")

# ----- Navigation -----
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigate", menu)

# ----- Home Page -----
if choice == "Home":
    st.subheader("🏠 Welcome to Secure Vault")
    st.markdown("""
    - 🔒 Store data securely with a unique passkey.
    - 🔑 Retrieve data using the correct passkey.
    - 🔁 After 3 failed attempts, re-login is required.
    - 💾 No external storage — operates **in memory only**.
    """)

# ----- Store Data -----
elif choice == "Store Data":
    st.subheader("📥 Store New Data")

    label = st.text_input("Enter Data Label (unique key):")
    data = st.text_area("Enter Your Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if not label or not data or not passkey:
            st.error("⚠️ All fields are required.")
        elif label in st.session_state.stored_data:
            st.warning("⚠️ This label already exists. Use a different one.")
        else:
            encrypted_text = encrypt_data(data)
            hashed_passkey = hash_passkey(passkey)
            st.session_state.stored_data[label] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            st.success("✅ Data encrypted and stored successfully!")

# ----- Retrieve Data -----
elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Stored Data")

    if not st.session_state.is_logged_in:
        st.warning("🔒 Too many failed attempts. Please reauthorize in the **Login** tab.")
        st.stop()

    label = st.text_input("Enter Data Label:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if not label or not passkey:
            st.error("⚠️ Both fields are required.")
        elif label not in st.session_state.stored_data:
            st.error("❌ Label not found.")
        else:
            stored_entry = st.session_state.stored_data[label]
            hashed_pass = hash_passkey(passkey)

            if hashed_pass == stored_entry["passkey"]:
                decrypted_text = decrypt_data(stored_entry["encrypted_text"])
                st.success("✅ Data Decrypted Successfully:")
                st.code(decrypted_text)
                st.session_state.failed_attempts = 0  # Reset attempts
            else:
                st.session_state.failed_attempts += 1
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining}")

                if st.session_state.failed_attempts >= 3:
                    st.session_state.is_logged_in = False
                    st.warning("🔒 Too many failed attempts! Redirecting to login...")
                    st.experimental_rerun()

# ----- Login Page -----
elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")

    master_password = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if master_password == "admin123":  # 🔐 Change this in production
            st.session_state.failed_attempts = 0
            st.session_state.is_logged_in = True
            st.success("✅ Login successful. You may now retrieve data again.")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect master password.")
