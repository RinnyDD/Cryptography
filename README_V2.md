# 🔐 Padding Oracle Attack Demo - V2

A comprehensive demonstration of **Padding Oracle Attack** against AES-CBC encryption with a vulnerable Flask web server.

## 📋 Table of Contents

- [Overview](#overview)
- [Project Structure](#project-structure)
- [Vulnerability Explained](#vulnerability-explained)
- [Setup & Installation](#setup--installation)
- [Usage Guide](#usage-guide)
- [Attack Methodology](#attack-methodology)
- [How to Get the Flag](#how-to-get-the-flag)
- [Defense Recommendations](#defense-recommendations)
- [Educational Purpose](#educational-purpose)

---

## 🎯 Overview

This project demonstrates a **Padding Oracle Attack** - a cryptographic vulnerability that allows an attacker to decrypt AES-CBC encrypted data without knowing the encryption key.

### What is a Padding Oracle?

A **padding oracle** is a vulnerability where:
- A server decrypts user-provided data (e.g., cookies)
- The server reveals whether the padding is valid or invalid
- An attacker can use this information to decrypt the entire message

### Attack Goals

1. **Decrypt the session cookie** using padding oracle attack
2. **Modify the cookie** using CBC bit-flipping to gain admin access
3. **Capture the flag** 🚩

---

## 📁 Project Structure

```
.
├── Padding Attack/
│   └── know_username.py
├── V2/                          ← CURRENT VERSION
│   ├── webserver.py            # Vulnerable Flask server
│   └── padding_attack.py       # Automated attack script
├── vulnerable web server/
│   └── vulserver.py
└── README.md                    # This file
```

### V2 Files

| File | Description | Lines of Code |
|------|-------------|---------------|
| `webserver.py` | Vulnerable Flask server with padding oracle | ~200 |
| `padding_attack.py` | Automated padding oracle attack script | ~250 |

---

## 🔓 Vulnerability Explained

### The Vulnerable Code

**Location:** `webserver.py` - `/dashboard` endpoint (lines 101-110)

```python
try:
    cipher = get_cipher(iv)
    plaintext = cipher.decrypt(ciphertext)
    
    # PADDING ORACLE VULNERABILITY ← HERE!
    plaintext = unpad(plaintext, BLOCK_SIZE)
    
    data = json.loads(plaintext.decode())
    # ... process data ...
except Exception as e:
    # INFORMATION LEAK ← HERE!
    if "padding" in str(e).lower():
        return "500 Padding Error", 500    # ← Different error!
    else:
        return "400 Other Error", 400      # ← Different error!
```

### Why This is Vulnerable

The server **distinguishes** between two types of errors:
- ✅ **Valid padding** → Returns 200 OK (processes data)
- ❌ **Invalid padding** → Returns "500 Padding Error"
- ❌ **Other errors** → Returns "400 Other Error"

This distinction allows an attacker to:
1. Modify the encrypted cookie byte by byte
2. Send it to the server
3. Check if padding is valid
4. Deduce the plaintext one byte at a time

### Cookie Structure

```json
{
  "username": "bopha",
  "role": "user",
  "created": "2024-01-15",
  "access_level": "low"
}
```

**Encrypted format:**
```
[IV (16 bytes)][Block 1][Block 2][Block 3][Block 4][Block 5][Block 6]
     ↓             ↓         ↓         ↓         ↓         ↓         ↓
  Random    {"username"  : "bopha",  "role": "  user", "c  reated": "  2024-01-15  ", "access_  level": "l  ow"}+pad
```

---

## 🛠️ Setup & Installation

### Prerequisites

- **Python 3.7+**
- **pip** package manager
- **Terminal/Command Prompt**

### Installation Steps

1. **Navigate to the V2 directory:**
   ```bash
   cd V2
   ```

2. **Install required packages:**
   ```bash
   pip install Flask pycryptodome requests
   ```

3. **Verify installation:**
   ```bash
   python3 -c "import flask, Crypto, requests; print('✓ All packages installed')"
   ```

### Required Dependencies

```txt
Flask==2.3.0          # Web server framework
pycryptodome==3.18.0  # AES encryption/decryption
requests==2.31.0      # HTTP client for attack script
```

---

## 🚀 Usage Guide

### Step 1: Start the Vulnerable Server

Open a terminal in the `V2/` directory:

```bash
python3 webserver.py
```

**Expected Output:**
```
======================================================================
VULNERABLE WEB SERVER STARTING
======================================================================
Server: http://localhost:8080
Flag: PADDING_ORACLE_MASTER_A1B2C3D4E5F6G7H8
======================================================================
 * Running on http://0.0.0.0:8080
```

> 💡 **Note:** The flag is randomly generated each time the server starts!

### Step 2: Explore the Web Interface (Optional)

Open your browser and visit:

1. **Home:** http://localhost:8080
   - Shows welcome page with instructions

2. **Login:** http://localhost:8080/login
   - Gives you a session cookie (role: user)
   - Username: `bopha`

3. **Dashboard:** http://localhost:8080/dashboard
   - Shows user dashboard (not admin!)
   - Goal: Become admin to see the flag

### Step 3: Run the Padding Oracle Attack

**Open a NEW terminal** (keep server running):

```bash
cd V2
python3 padding_attack.py
```

**Expected Output:**
```
======================================================================
PADDING ORACLE ATTACK - NEW WEBSERVER
======================================================================

[*] Step 1: Getting valid session cookie from /login
[✓] Session cookie obtained
[*] Cookie (Base64): WfT3kL9mH2pQ8x...
[*] Cookie length: 152 characters

[*] Step 2: Performing padding oracle attack to decrypt cookie

======================================================================
PADDING ORACLE ATTACK - STARTING
======================================================================
[*] Cookie length: 96 bytes
[*] Number of blocks: 6 (1 IV + 5 ciphertext blocks)

[*] Attacking block 1/5
  [+] Attacking byte 15 (padding length: 1)
    [✓] Byte 15 found: 61 ('a')
  [+] Attacking byte 14 (padding length: 2)
    [✓] Byte 14 found: 68 ('h')
  ...

[*] Attacking block 2/5
  ...

======================================================================
ATTACK COMPLETE
======================================================================

[✓] Decryption successful!
[*] Recovered plaintext (UTF-8): {"username": "bopha", "role": "user", "created": "2024-01-15", "access_level": "low"}

[✓] Cookie data structure:
    username: bopha
    role: user
    created: 2024-01-15
    access_level: low

======================================================================
```

### Attack Statistics

| Metric | Value |
|--------|-------|
| **Time Duration** | 30-60 seconds |
| **HTTP Requests** | ~10,000-12,000 |
| **Blocks Attacked** | 5 ciphertext blocks |
| **Bytes per Block** | 16 |
| **Success Rate** | 100% |

---

## 🔬 Attack Methodology

### How the Attack Works

#### 1. **AES-CBC Decryption Formula**
```
Plaintext[i] = Decrypt(Ciphertext[i]) ⊕ Ciphertext[i-1]
```

#### 2. **Padding Oracle Technique**

For each byte (from right to left):

```python
for guess in range(256):  # Try all possible byte values
    # Modify the previous block
    modified_iv[byte_position] = guess
    
    # Send to server
    response = server.decrypt(modified_cookie)
    
    # Check response
    if response == "500 Padding Error":
        continue  # Wrong guess, try next
    else:
        # Valid padding found!
        intermediate = guess ⊕ padding_length
        plaintext = intermediate ⊕ original_iv[byte_position]
        break
```

#### 3. **Attack Flow Diagram**

```
┌─────────────┐
│ Get Cookie  │ ← http://localhost:8080/login
└──────┬──────┘
       │
       ▼
┌──────────────────┐
│ Decode Base64    │ ← 152 chars → 96 bytes
│ Split into Blocks│ ← 96 bytes = 6 blocks × 16 bytes
└──────┬───────────┘
       │
       ▼
┌────────────────────────────┐
│ FOR EACH BLOCK (1 to 5):   │
│   FOR EACH BYTE (15 to 0): │ ← Right to left
│     TRY 0x00 to 0xFF:      │ ← ~128 tries average
│       Send to /dashboard   │ ← HTTP request
│       Check: 500 or 200?   │ ← Oracle response
│       Calculate plaintext  │ ← XOR math
└──────┬─────────────────────┘
       │
       ▼
┌────────────────┐
│ Combine Blocks │ → {"username": "bopha", ...}
│ Remove Padding │
└──────┬─────────┘
       │
       ▼
┌──────────────┐
│ Plaintext! 🎉│
└──────────────┘
```

#### 4. **Mathematical Example**

**Attacking Byte 15 (last byte):**

```
Goal: Find value that makes plaintext = 0x01 (valid 1-byte padding)

Try IV[15] = 0x00:
  Decrypted = 0xA6 (server's intermediate value)
  Plaintext = 0xA6 ⊕ 0x00 = 0xA6 ❌ Not 0x01
  Server: "500 Padding Error"

Try IV[15] = 0xA7:
  Decrypted = 0xA6
  Plaintext = 0xA6 ⊕ 0xA7 = 0x01 ✓ Valid!
  Server: "200 OK"

Calculate:
  Intermediate[15] = 0xA7 ⊕ 0x01 = 0xA6
  Plaintext[15] = 0xA6 ⊕ Original_IV[15] = 0x61 = 'a'
```

---

## 🏆 How to Get the Flag

After successfully running the padding oracle attack, you have the decrypted cookie structure:

```json
{
  "username": "bopha",
  "role": "user",          ← Need to change this!
  "created": "2024-01-15",
  "access_level": "low"
}
```

### Option 1: CBC Bit-Flipping Attack (Manual)

**Step 1:** Find the position of `"user"` in the plaintext

Looking at the blocks, `"role": "user"` appears in Block 3.

**Step 2:** Calculate the XOR difference

```python
import base64
import requests

# Get the original cookie
response = requests.get("http://localhost:8080/login")
cookie = response.cookies.get("session")
cookie_bytes = bytearray(base64.b64decode(cookie))

# Position where "user" appears (you need to find this from decryption)
# Let's say "user" is at position 35-38 in plaintext
# Which means it's in Block 3, and we modify Block 2

# XOR difference between "user" and "admi"
old_text = b"user"
new_text = b"admi"  # Same length!

# Modify Block 2 bytes at the correct position
block2_start = 16 + 16  # Skip IV and Block 1
for i in range(4):
    cookie_bytes[block2_start + offset + i] ^= old_text[i] ^ new_text[i]

# Send modified cookie
modified_cookie = base64.b64encode(cookie_bytes).decode()
response = requests.get(
    "http://localhost:8080/dashboard",
    cookies={"session": modified_cookie}
)

# If successful, you'll see the admin dashboard with the FLAG!
print(response.text)
```

### Option 2: Create New Admin Cookie (Advanced)

If you know the encryption algorithm, you could create a completely new cookie:

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import json
import base64
import os

# This requires knowing or brute-forcing the key
KEY = b'123456789abcdef0'  # From server code (in real scenario, unknown)

data = {
    "username": "bopha",
    "role": "admin",  # Changed to admin!
    "created": "2024-01-15",
    "access_level": "high"
}

plaintext = json.dumps(data).encode()
iv = os.urandom(16)
cipher = AES.new(KEY, AES.MODE_CBC, iv)
encrypted = cipher.encrypt(pad(plaintext, 16))
cookie = base64.b64encode(iv + encrypted).decode()

# Use this cookie to access /dashboard
```

### Expected Result: Admin Dashboard

Once you successfully become admin, you'll see:

```html
👑 ADMIN DASHBOARD

Welcome Admin bopha!
Access Level: Maximum

🏁 FLAG: PADDING_ORACLE_MASTER_A1B2C3D4E5F6G7H8

System Information:
• Total Users: 1,247
• Active Sessions: 89
• Server Status: ONLINE

🔐 SECRET DATA:
API_KEY: ADMIN_SPECIAL_KEY_abc123def456
SSH_ACCESS: root@localhost
DATABASE: postgresql://admin:AdminPass123@localhost
```

---

## 🛡️ Defense Recommendations

### ❌ Vulnerable Code (Current)

```python
try:
    plaintext = unpad(plaintext, BLOCK_SIZE)
    data = json.loads(plaintext.decode())
except Exception as e:
    if "padding" in str(e).lower():
        return "500 Padding Error", 500  # ← LEAKS INFO!
    else:
        return "400 Other Error", 400     # ← LEAKS INFO!
```

### ✅ Secure Implementation

#### 1. **Use Authenticated Encryption (Best)**

```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def secure_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce + tag + ciphertext

def secure_decrypt(data, key):
    nonce = data[:16]
    tag = data[16:32]
    ciphertext = data[32:]
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        return None  # Generic error, no info leak
```

#### 2. **Add HMAC for Integrity**

```python
import hmac
import hashlib

def encrypt_with_mac(plaintext, enc_key, mac_key):
    iv = get_random_bytes(16)
    cipher = AES.new(enc_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, 16))
    
    # Add HMAC
    h = hmac.new(mac_key, iv + ciphertext, hashlib.sha256)
    mac = h.digest()
    
    return iv + ciphertext + mac

def decrypt_with_mac(data, enc_key, mac_key):
    iv = data[:16]
    ciphertext = data[16:-32]
    received_mac = data[-32:]
    
    # Verify HMAC first!
    h = hmac.new(mac_key, iv + ciphertext, hashlib.sha256)
    expected_mac = h.digest()
    
    if not hmac.compare_digest(received_mac, expected_mac):
        return None  # Tampered!
    
    # Now decrypt
    cipher = AES.new(enc_key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    
    try:
        return unpad(plaintext, 16)
    except ValueError:
        return None  # Same error for everything
```

#### 3. **Generic Error Messages**

```python
@app.route('/dashboard')
def dashboard():
    try:
        # ... decrypt and validate ...
    except Exception:
        # NEVER reveal specific error types!
        return "Invalid Session", 403
```

### Security Checklist

- [x] Use AES-GCM or ChaCha20-Poly1305 (authenticated encryption)
- [x] Add HMAC to detect tampering
- [x] Return same error for all failures
- [x] Use constant-time comparison for MACs
- [x] Don't reveal padding errors
- [x] Rotate keys regularly
- [x] Use secure random for IVs

---

## 📚 Educational Purpose

### ⚠️ **LEGAL WARNING**

This project is for **EDUCATIONAL PURPOSES ONLY**.

**DO NOT:**
- ❌ Use this code in production
- ❌ Attack systems without authorization
- ❌ Deploy vulnerable code intentionally

**LEGAL NOTICE:**
- Unauthorized access is illegal
- Always get written permission for security testing
- Use knowledge to build secure systems, not break them

### Learning Objectives

✅ Understand AES-CBC encryption  
✅ Learn about padding oracle vulnerabilities  
✅ Practice cryptographic attacks  
✅ Recognize secure vs insecure implementations  
✅ Implement proper error handling  
✅ Use authenticated encryption modes  

---

## 🐛 Troubleshooting

### Issue: "Connection Refused"
```bash
# Check if server is running
curl http://localhost:8080

# Check port usage
netstat -tulpn | grep 8080
```

### Issue: "No module named 'Crypto'"
```bash
# Install pycryptodome (NOT pycrypto)
pip install pycryptodome
```

### Issue: Attack Takes Too Long
```
Expected: 30-60 seconds
If longer: Check network latency
Run server and attack on same machine
```

### Issue: "Failed to find byte at index X"
```
Solution:
1. Restart the server
2. Get a fresh cookie
3. Run attack again
```

---

## 📊 Performance Metrics

### Typical Attack Run

```
Server: Flask (localhost:8080)
Cookie Size: 96 bytes (6 blocks)
Attack Duration: 45 seconds

Block 1: ~2,000 requests (8 sec)
Block 2: ~2,000 requests (8 sec)
Block 3: ~2,000 requests (8 sec)
Block 4: ~2,000 requests (8 sec)
Block 5: ~2,000 requests (8 sec)

Total: ~10,000 HTTP requests
Success Rate: 100%
```

---

## 🔗 References

- [Vaudenay, S. (2002). "Security Flaws Induced by CBC Padding"](https://www.iacr.org/archive/eurocrypt2002/23320530/cbc02_e02d.pdf)
- [OWASP: Padding Oracle Attack](https://owasp.org/www-community/attacks/Padding_Oracle_attack)
- [Cryptopals Crypto Challenges](https://cryptopals.com/)

---

## 🎓 What You've Learned

After completing this project:

1. ✅ **AES-CBC** - How block cipher modes work
2. ✅ **Padding** - PKCS7 padding scheme
3. ✅ **Oracle Attacks** - Information leakage exploitation
4. ✅ **XOR Properties** - Cryptographic mathematics
5. ✅ **Secure Coding** - How to prevent these attacks

---

## 📝 Quick Reference

### Start Server
```bash
cd V2
python3 webserver.py
```

### Run Attack
```bash
cd V2
python3 padding_attack.py
```

### Access Points
- Home: http://localhost:8080
- Login: http://localhost:8080/login
- Dashboard: http://localhost:8080/dashboard

---

**Remember: Use this knowledge ethically and responsibly!** 🛡️🔐

**Goal: Learn → Build Secure Systems → Protect Users**