import streamlit as st
import hashlib
import itertools
import string
import time

st.set_page_config(page_title="Password Cracking Simulator", layout="centered")

st.title("🔐 Password Cracking Simulator")
st.caption("Educational cybersecurity project – ethical use only")

st.warning(
    "⚠️ This app is for EDUCATIONAL PURPOSES ONLY.\n"
    "Use only on passwords you own or in test environments."
)

# ---------------- Hash Generator ----------------
st.header("1️⃣ Password Hash Generator")

password = st.text_input("Enter password to hash", type="password")
algo = st.selectbox("Hash Algorithm", ["SHA-256", "MD5", "SHA-1"])

def make_hash(pwd, algo):
    if algo == "SHA-256":
        return hashlib.sha256(pwd.encode()).hexdigest()
    if algo == "MD5":
        return hashlib.md5(pwd.encode()).hexdigest()
    if algo == "SHA-1":
        return hashlib.sha1(pwd.encode()).hexdigest()

if st.button("Generate Hash"):
    if password:
        st.code(make_hash(password, algo))
    else:
        st.error("Please enter a password")

# ---------------- Attack Section ----------------
st.header("2️⃣ Password Cracking")

target_hash = st.text_input("Enter target hash (SHA-256)")
attack = st.radio("Select Attack Type", ["Dictionary Attack", "Brute Force Attack"])

# ---------------- Dictionary Attack ----------------
if attack == "Dictionary Attack":
    if st.button("Start Dictionary Attack"):
        start = time.time()
        found = False

        with open("wordlist.txt") as f:
            for word in f:
                word = word.strip()
                if hashlib.sha256(word.encode()).hexdigest() == target_hash:
                    st.success(f"✅ Password Cracked: {word}")
                    found = True
                    break

        if not found:
            st.error("❌ Password not found in wordlist")

        st.info(f"⏱ Time taken: {round(time.time() - start, 4)} seconds")

# ---------------- Brute Force Attack ----------------
if attack == "Brute Force Attack":
    max_len = st.slider("Max password length", 1, 5, 3)

    if st.button("Start Brute Force Attack"):
        start = time.time()
        found = False
        chars = string.ascii_lowercase + string.digits

        for length in range(1, max_len + 1):
            for guess in itertools.product(chars, repeat=length):
                guess = ''.join(guess)
                if hashlib.sha256(guess.encode()).hexdigest() == target_hash:
                    st.success(f"✅ Password Cracked: {guess}")
                    found = True
                    break
            if found:
                break

        if not found:
            st.error("❌ Password not cracked")

        st.info(f"⏱ Time taken: {round(time.time() - start, 4)} seconds")

# ---------------- Lessons ----------------
st.header("3️⃣ Security Lessons")
st.markdown("""
- Weak passwords are easy to crack
- Dictionary attacks are very fast
- Brute force grows exponentially
- Use **bcrypt / Argon2**
- Always **salt** passwords
- Enable **MFA**
""")
