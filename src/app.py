"""
Vulnerable Python Web Application - FOR SECURITY TESTING ONLY

Vulnerabilities present:
  - SQL injection (CWE-89)
  - Cross-site scripting / XSS (CWE-79)
  - Hardcoded secrets & credentials (CWE-798)
  - Command injection via subprocess/os.system (CWE-78)
  - Path traversal (CWE-22)
  - Insecure deserialization via pickle (CWE-502)
  - Debug mode enabled in production (CWE-94)
  - Weak cryptography / MD5 passwords (CWE-327)
  - Missing authentication on sensitive endpoints (CWE-306)
  - Open redirect (CWE-601)
  - SSRF via requests (CWE-918)
  - XML external entity injection (CWE-611)
  - Insecure JWT secret
"""

import os
import subprocess
import sqlite3
import pickle
import hashlib
import xml.etree.ElementTree as ET
from flask import Flask, request, render_template_string, redirect, session
import requests

app = Flask(__name__)

# VULNERABILITY: Hardcoded secrets (CWE-798)
app.secret_key = "hardcoded_flask_secret_key_1234"
DATABASE_URL    = "postgresql://admin:prod_password@db.prod.internal:5432/users"
AWS_ACCESS_KEY  = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY  = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
STRIPE_SECRET   = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
GITHUB_TOKEN    = "ghp_1234567890abcdefghijklmnopqrstuvwxyz12"
SENDGRID_KEY    = "SG.xxxxxxxxxx.yyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"
JWT_SECRET      = "secret"


def get_db():
    return sqlite3.connect("app.db")


# VULNERABILITY: SQL injection (CWE-89)
@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]

    db = get_db()
    # Raw string formatting - classic SQLi
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor = db.execute(query)
    user = cursor.fetchone()

    if user:
        session["user"] = username
        return "Login successful"
    return "Invalid credentials"


# VULNERABILITY: SQL injection in search (CWE-89)
@app.route("/search")
def search():
    term = request.args.get("q", "")
    db = get_db()
    results = db.execute("SELECT * FROM products WHERE name LIKE '%" + term + "%'")
    return str(results.fetchall())


# VULNERABILITY: Reflected XSS (CWE-79)
@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    # User input rendered directly into HTML - no escaping
    return render_template_string(f"<h1>Hello, {name}!</h1>")


# VULNERABILITY: Stored XSS via comment (CWE-79)
@app.route("/comment", methods=["POST"])
def comment():
    content = request.form.get("content", "")
    db = get_db()
    db.execute(f"INSERT INTO comments (text) VALUES ('{content}')")
    db.commit()
    return render_template_string(f"<p>Comment saved: {content}</p>")


# VULNERABILITY: Command injection (CWE-78)
@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    # User input flows directly into shell command
    output = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return output.decode()


# VULNERABILITY: Command injection via os.system (CWE-78)
@app.route("/dns")
def dns_lookup():
    domain = request.args.get("domain", "")
    os.system(f"nslookup {domain}")
    return "Done"


# VULNERABILITY: Path traversal (CWE-22)
@app.route("/file")
def read_file():
    filename = request.args.get("name", "")
    # No sanitisation - allows ../../../../etc/passwd
    with open(f"./uploads/{filename}", "r") as f:
        return f.read()


# VULNERABILITY: Insecure deserialization (CWE-502)
@app.route("/load_session", methods=["POST"])
def load_session():
    data = request.get_data()
    # Unpickling untrusted user data - arbitrary code execution
    obj = pickle.loads(data)
    return str(obj)


# VULNERABILITY: Weak password hashing with MD5 (CWE-327)
def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


# VULNERABILITY: Missing authentication (CWE-306)
@app.route("/admin/users")
def admin_users():
    # No authentication check whatsoever
    db = get_db()
    return str(db.execute("SELECT * FROM users").fetchall())


# VULNERABILITY: Open redirect (CWE-601)
@app.route("/redirect")
def open_redirect():
    url = request.args.get("url", "/")
    # No validation of destination - can redirect to attacker site
    return redirect(url)


# VULNERABILITY: SSRF (CWE-918)
@app.route("/fetch")
def fetch_url():
    url = request.args.get("url", "")
    # Fetches arbitrary URLs including internal services
    resp = requests.get(url)
    return resp.text


# VULNERABILITY: XML External Entity injection (CWE-611)
@app.route("/parse_xml", methods=["POST"])
def parse_xml():
    xml_data = request.get_data()
    # Default ElementTree is not vulnerable but exposes pattern;
    # using lxml with resolve_entities=True would be fully exploitable
    tree = ET.fromstring(xml_data)
    return ET.tostring(tree).decode()


# VULNERABILITY: Debug mode exposes Werkzeug console (CWE-94 / misconfig)
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)  # debug=True in production
