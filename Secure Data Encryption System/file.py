import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Generate a key for encryption/decryption
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# Store data in memory (no database)
stored_data = {}  # Format: {"unique_id": {"encrypted_text": "...", "passkey": "hashed_passkey"}}

# Use session state for failed attempts so it persists properly across Streamlit reruns
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

MAX_ATTEMPTS = 3

# Helper functions
def hash_passkey(passkey):
    """Convert passkey to a secure hash"""
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text, passkey):
    """Encrypt the text using the cipher"""
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    """Decrypt the text if passkey matches"""
    for data_id, data in stored_data.items():
        if data["encrypted_text"] == encrypted_text:
            if data["passkey"] == hash_passkey(passkey):
                st.session_state.failed_attempts = 0  # Reset on success
                return cipher.decrypt(encrypted_text.encode()).decode()
    # Wrong passkey
    st.session_state.failed_attempts += 1
    return None

# Streamlit App UI
st.title("🔐 Simple Secure Data Storage")

# Navigation menu
page = st.sidebar.radio("Menu", ["Home", "Store Data", "Retrieve Data", "Login"])

if page == "Home":
    st.write("""
    ## Welcome to the Secure Data Storage!
    Here you can:
    - **Store** your secret data securely
    - **Retrieve** it later with your passkey

    🔒 Your data is encrypted before storage  
    🔑 Only you can decrypt it with your passkey
    """)

elif page == "Store Data":
    st.header("Store New Data")

    user_text = st.text_area("Enter your secret data:")
    user_passkey = st.text_input("Create a passkey:", type="password")

    if st.button("Store Securely"):
        if user_text and user_passkey:
            # Create a unique ID for this data
            data_id = f"data_{len(stored_data) + 1}"

            # Encrypt and store
            encrypted = encrypt_data(user_text, user_passkey)
            hashed_passkey = hash_passkey(user_passkey)

            stored_data[data_id] = {
                "encrypted_text": encrypted,
                "passkey": hashed_passkey
            }

            st.success("✅ Data stored securely!")
            st.code(f"Your encrypted data:\n{encrypted}")
            st.warning("⚠️ Copy this encrypted text - you'll need it to retrieve your data later!")
        else:
            st.error("Please enter both data and a passkey")

elif page == "Retrieve Data":
    st.header("Retrieve Your Data")

    if st.session_state.failed_attempts >= MAX_ATTEMPTS:
        st.error("🔒 Too many failed attempts! Please login first.")
        st.stop()

    encrypted_input = st.text_area("Paste your encrypted data:")
    passkey_input = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt Data"):
        if encrypted_input and passkey_input:
            decrypted = decrypt_data(encrypted_input, passkey_input)

            if decrypted:
                st.success("✅ Decryption successful!")
                st.text_area("Your decrypted data:", decrypted, height=150)
            else:
                remaining = MAX_ATTEMPTS - st.session_state.failed_attempts
                st.error(f"❌ Wrong passkey! {remaining} attempts remaining")
        else:
            st.error("Please enter both encrypted data and passkey")

elif page == "Login":
    st.header("Login Required")

    if st.session_state.failed_attempts < MAX_ATTEMPTS:
        st.info("You don't need to login yet.")
        if st.button("Go back"):
            st.experimental_rerun()
    else:
        login_pass = st.text_input("Enter admin password:", type="password")

        if st.button("Reset Attempts"):
            if login_pass == "admin123":
                st.session_state.failed_attempts = 0
                st.success("Login successful! Attempts reset.")
                st.experimental_rerun()
            else:
                st.error("Wrong password!")
