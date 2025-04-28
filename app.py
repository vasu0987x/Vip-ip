import os
import asyncio
import socket
import datetime
from flask import Flask, request, redirect, url_for, render_template_string, session, send_file

# --- Flask Config ---
app = Flask(__name__)
app.secret_key = os.urandom(24)  # Random session key

# --- Settings ---
ADMIN_PASSWORD = "2412"

# --- HTML Templates (Direct inside app.py) ---
login_page = '''
<!doctype html>
<title>DarkIp Admin - Login</title>
<h2 style="text-align:center; margin-top:20px;">DarkIp Admin Panel</h2>
<form method="POST" style="text-align:center; margin-top:40px;">
    <input type="password" name="password" placeholder="Enter Password" style="padding:10px; width:200px;"><br><br>
    <input type="submit" value="Login" style="padding:10px 20px;">
</form>
'''

dashboard_page = '''
<!doctype html>
<title>DarkIp Admin - Dashboard</title>
<h2 style="text-align:center; margin-top:20px;">Welcome to DarkIp Admin</h2>
<form method="POST" action="/scan" style="text-align:center; margin-top:40px;">
    <input type="text" name="target" placeholder="Enter IP or CIDR" style="padding:10px; width:300px;"><br><br>
    <input type="submit" value="Start Scan" style="padding:10px 20px;">
</form>
<br><br>
<div style="text-align:center;">
    <a href="/report" style="padding:10px 20px; background:black; color:white; text-decoration:none;">Download Last Report</a>
</div>
'''

result_page = '''
<!doctype html>
<title>DarkIp Admin - Scan Result</title>
<h2 style="text-align:center; margin-top:20px;">Scan Completed!</h2>
<div style="margin:30px;">
<pre>
{{ result }}
</pre>
</div>
<div style="text-align:center;">
    <a href="/dashboard" style="padding:10px 20px; background:green; color:white; text-decoration:none;">Back to Dashboard</a>
</div>
'''

# --- Routes ---
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form.get('password')
        if password == ADMIN_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
        else:
            return "Wrong Password. Access Denied."
    return render_template_string(login_page)

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template_string(dashboard_page)

@app.route('/scan', methods=['POST'])
def scan():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    target = request.form.get('target')
    if not target:
        return "Please enter a valid IP or CIDR Range."

    result = run_scan(target)

    # Save result
    with open('last_report.txt', 'w') as f:
        f.write(result)

    return render_template_string(result_page, result=result)

@app.route('/report')
def report():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return send_file('last_report.txt', as_attachment=True)

# --- Core Scan Function ---
def run_scan(target):
    result = f"Scan result for {target}:\n"
    open_ports = []
    common_ports = [80, 443, 554, 8000, 8080, 8443, 21, 22, 23, 53, 123]

    for port in common_ports:
        try:
            sock = socket.socket()
            sock.settimeout(1)
            sock.connect((target, port))
            open_ports.append(port)
            sock.close()
        except:
            pass

    if open_ports:
        result += "Open ports: " + ", ".join([str(p) for p in open_ports]) + "\n"
    else:
        result += "No open ports detected.\n"

    result += "Scanned: " + datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Y")
    return result

# --- Run Server ---
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
