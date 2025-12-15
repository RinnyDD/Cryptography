from flask import Flask, request, make_response
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import os
import json

app = Flask(__name__)

KEY = b'123456789abcdef0'
BLOCK_SIZE = 16
FLAG = "PADDING_ORACLE_MASTER_{}".format(os.urandom(8).hex().upper())

def get_cipher(iv):
    return AES.new(KEY, AES.MODE_CBC, iv)

def encrypt_data(data):
    plaintext = json.dumps(data).encode()
    iv = os.urandom(BLOCK_SIZE)
    cipher = get_cipher(iv)
    encrypted = cipher.encrypt(pad(plaintext, BLOCK_SIZE))
    return base64.b64encode(iv + encrypted).decode()

@app.route('/')
def home():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Secure Portal</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
            .admin { background: #d4edda; padding: 20px; border-radius: 10px; margin: 20px 0; }
            .user { background: #fff3cd; padding: 20px; border-radius: 10px; margin: 20px 0; }
            .flag { color: #dc3545; font-weight: bold; font-size: 24px; padding: 15px; background: #f8f9fa; border-radius: 5px; }
        </style>
    </head>
    <body>
        <h1>🔐 Secure Portal</h1>
        <div class="user">
            <h2>Welcome!</h2>
            <p><strong>Goal:</strong> Get admin access to obtain the flag</p>
            <p><strong>Vulnerabilities:</strong></p>
            <ul>
                <li>Padding Oracle Attack (decrypt cookie)</li>
                <li>CBC Bit-Flipping Attack (modify role to admin)</li>
            </ul>
            <hr>
            <a href="/login"><button>Login as User</button></a>
            <a href="/dashboard"><button>Go to Dashboard</button></a>
        </div>
    </body>
    </html>
    """

@app.route('/login')
def login():
    data = {
        "username": "bopha",
        "role": "user",
        "created": "2024-01-15",
        "access_level": "low"
    }
    
    cookie_value = encrypt_data(data)
    
    resp = make_response("""
    <div class="user">
        <h2>✅ Login Successful</h2>
        <p>Session cookie has been set.</p>
        <p><strong>Role:</strong> Regular User</p>
        <p><strong>Access Level:</strong> Low</p>
        <a href="/dashboard"><button>Go to Dashboard</button></a>
    </div>
    """)
    resp.set_cookie("session", cookie_value, httponly=True)
    return resp

@app.route('/dashboard')
def dashboard():
    cookie = request.cookies.get("session")
    
    if not cookie:
        return """
        <div class="user">
            <h2>⚠️ Access Denied</h2>
            <p>No session cookie found.</p>
            <a href="/login"><button>Login First</button></a>
        </div>
        """, 403
    
    try:
        encrypted = base64.b64decode(cookie)
        
        if len(encrypted) < BLOCK_SIZE * 2:
            return "400 Invalid format", 400
            
        iv = encrypted[:BLOCK_SIZE]
        ciphertext = encrypted[BLOCK_SIZE:]
        
        cipher = get_cipher(iv)
        plaintext = cipher.decrypt(ciphertext)
        
        # PADDING ORACLE VULNERABILITY
        plaintext = unpad(plaintext, BLOCK_SIZE)
        
        data = json.loads(plaintext.decode())
        
        # CBC BIT-FLIPPING VULNERABILITY
        if data.get("role") == "admin":
            return f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Admin Dashboard</title>
                <style>
                    body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }}
                    .admin {{ background: #d4edda; padding: 20px; border-radius: 10px; margin: 20px 0; }}
                    .flag {{ color: #dc3545; font-weight: bold; font-size: 24px; padding: 15px; background: #f8f9fa; border-radius: 5px; }}
                    .secret {{ background: #000; color: #0f0; padding: 15px; font-family: monospace; }}
                </style>
            </head>
            <body>
                <div class="admin">
                    <h1>👑 ADMIN DASHBOARD</h1>
                    <p><strong>Welcome Admin {data.get('username', '')}!</strong></p>
                    <p><strong>Access Level:</strong> Maximum</p>
                    
                    <div class="flag">
                        🏁 FLAG: {FLAG}
                    </div>
                    
                    <h3>System Information:</h3>
                    <ul>
                        <li>Total Users: 1,247</li>
                        <li>Active Sessions: 89</li>
                        <li>Server Status: ONLINE</li>
                    </ul>
                    
                    <div class="secret">
                        <h4>🔐 SECRET DATA:</h4>
                        <pre>API_KEY: ADMIN_SPECIAL_KEY_{os.urandom(12).hex()}
SSH_ACCESS: root@localhost
DATABASE: postgresql://admin:AdminPass123@localhost</pre>
                    </div>
                </div>
            </body>
            </html>
            """
        else:
            return f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>User Dashboard</title>
                <style>
                    body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }}
                    .user {{ background: #fff3cd; padding: 20px; border-radius: 10px; margin: 20px 0; }}
                </style>
            </head>
            <body>
                <div class="user">
                    <h1>👤 User Dashboard</h1>
                    <p><strong>Hello {data.get('username', 'User')}!</strong></p>
                    <p><strong>Role:</strong> {data.get('role', 'user').upper()}</p>
                    <p><strong>Access Level:</strong> {data.get('access_level', 'low').upper()}</p>
                    
                    <h3>Your Information:</h3>
                    <ul>
                        <li>Username: {data.get('username', 'N/A')}</li>
                        <li>Account Created: {data.get('created', 'N/A')}</li>
                        <li>Last Login: Today</li>
                    </ul>
                    
                    <div style="background: #f8f9fa; padding: 15px; margin: 20px 0; border-radius: 5px;">
                        <h4>⚠️ Limited Access Notice:</h4>
                        <p>As a regular user, you cannot:</p>
                        <ul>
                            <li>View the flag</li>
                            <li>Access admin panel</li>
                            <li>View system secrets</li>
                        </ul>
                        <p><em>Only admin users can see the flag.</em></p>
                    </div>
                </div>
            </body>
            </html>
            """
            
    except Exception as e:
        # PADDING ORACLE LEAK
        if "padding" in str(e).lower():
            return "500 Padding Error", 500
        else:
            return "400 Other Error", 400



if __name__ == "__main__":
    print("="*70)
    print("VULNERABLE WEB SERVER STARTING")
    print("="*70)
    print(f"Server: http://localhost:8080")
    print(f"Flag: {FLAG}")
    print("="*70)
    app.run(host="0.0.0.0", port=8080, debug=False)