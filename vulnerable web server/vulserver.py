from flask import Flask, request, make_response
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import os
import json

app = Flask(__name__)

KEY = b'123456789abcdef'
BLOCK_SIZE = 16

def get_cipher(iv):
    return AES.new(KEY, AES.MODE_CBC, iv)

# ORACLE LOGIC
def decrypt_and_check_padding(cookie_b64):
    try:
        # 1. Decode Base64
        encrypted_data = base64.b64decode(cookie_b64)
        
        # 2. Extract IV (first 16 bytes) and Ciphertext
        iv = encrypted_data[:BLOCK_SIZE]
        ciphertext = encrypted_data[BLOCK_SIZE:]
        
        # 3. Decrypt
        cipher = get_cipher(iv)
        plaintext = cipher.decrypt(ciphertext)
        
        # 4. Unpad (THE VULNERABILITY IS HERE)
        unpad(plaintext, BLOCK_SIZE)
        return True
    except Exception:
        return False

# HTTP ROUTES

@app.route('/')
def home():
    return "<h1>Welcome to VulServer!</h1><p>Go to http://localhost:8080/login?user=guest to get a cookie.</p>"

@app.route('/login')
def login():
    """Generates a valid encrypted cookie for a user."""
    username = request.args.get('user', 'guest')
    data = json.dumps({'user': username}).encode()
    
    # Encrypt the cookie data
    iv = os.urandom(BLOCK_SIZE)
    cipher = get_cipher(iv)
    encrypted = cipher.encrypt(pad(data, BLOCK_SIZE))
    cookie_val = base64.b64encode(iv + encrypted).decode()
    
    # Set the cookie in the browser/client
    resp = make_response(f"Logged in as {username}. Cookie set!")
    resp.set_cookie('auth_token', cookie_val)
    return resp

# Profile (The Target)

@app.route('/profile')
def profile():

    cookie_val = request.cookies.get('auth_token')
    
    if not cookie_val:
        return "403 Forbidden(No cookie found)", 403

    # ORACLE CHECK
    if decrypt_and_check_padding(cookie_val):
        # Padding is valid (user is authenticated)
        return "200 OK(Valid Padding)", 200
    else:
        # Padding is invalid (authentication failed)
        return "500 Internal Server Error(Padding Error!)", 500

# Starting the Server

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)