# Cryptography Team 2 Group Project

### Installation & Setup Instructions

System Requirements:
- Python version 3.0 or higher
- pip (Python Package Installer) installed

+ Step 1: Clone my repository
Open your terminal and run:
```bash
git clone https://github.com/RinnyDD/Cryptography.git
cd Cryptography
cd "vulnerable web server"
```

+ step 2: Install Dependencies
Open your terminal and run:
```bash
pip install flask pycryptodome
```

+ step 3: Run the Server
Open your terminal and run:
```bash
python vulserver.py
```
You should see the following output indicating the server is working:
```Output
Serving Flask app 'app'
Debug mode: off
Running on [http://0.0.0.0:8080](http://0.0.0.0:8080)
```
### Usage Guide

The server listens on Port 8080. You can interact with it using a web browser or a command-line tool for example curl.

1. Login to Generate a Cookie
Generates an encrypted authentication cookie for a user.

Method: Using a Web Browser

Step 1: Open Chrome or Edge.

Step 2: Go to: http://localhost:8080/login?user=guest

You should see text on the screen: Logged in as guest. Cookie set!

Step 3: Open Developer Tools (Press F12).

Step 4: Go to the Application tab (or "Storage" in Firefox).

Step 5: Click Cookies -> http://localhost:8080.

You will see a cookie named auth_token. Double-click the value and copy it.

2. Profile (The Target)
Attempts to decrypt the auth_token cookie to verify the user identity.

Go to: http://localhost:8080/profile

Oracle response:

HTTP 200 OK: padding is correct.

If we want to get an error Oracle response:

Step 1: Go back to Developer Tools (F12) -> Application -> Cookies.

Step 2: Find the auth_token value.

Step 3: Change the cookie value to anything else

Step 4: Press Enter to save the change.

Step 5: Refresh the page (http://localhost:8080/profile).

The page should now say:

Padding Error! (500 Internal Server Error)

