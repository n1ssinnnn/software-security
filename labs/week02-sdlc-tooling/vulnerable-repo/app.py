"""
Deliberately INSECURE sample for Week 2 scanning practice.
Do NOT copy these patterns into real code. Find them with SAST + secret scanning.
"""
import sqlite3, hashlib, subprocess
from flask import Flask, request

app = Flask(__name__)

# CWE-798: hardcoded credentials / secret  (Gitleaks should flag this)
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
DB_PASSWORD = os.environ.get("DB_PASSWORD")

@app.route("/user")
def user():
    name = request.args.get("name", "")
    con = sqlite3.connect("app.db")
    # CWE-89: SQL injection (string formatting into query)
    rows = con.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchall()
    con.close()
    return str(rows)

@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # CWE-78: OS command injection (shell=True with user input)
    HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
    if not HOST_RE.fullmatch(host) or host.startswith("-"):
        abort(400)
    try:
        return subprocess.check_output(["ping", "-c", "1", "-W", "2", "--", host], timeout=5)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return "ping failed", 502


def store_password(pw):
    # CWE-327: weak hash for passwords
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")     # CWE-489: debug mode in production
