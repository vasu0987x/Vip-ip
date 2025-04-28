import os
import subprocess
import datetime
from flask import Flask, request, redirect, url_for, render_template_string, session, send_file

# Flask setup
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Settings
ADMIN_PASSWORD = "2412"

# HTML Templates
login_page = '''
<!doctype html>
<title>DarkIp Admin - Login</title>
<h2 style="text-align:center; margin-top:20px;">DarkIp Admin Panel (RustScan Powered)</h2>
<form method="POST" style="text-align:center; margin-top:40px;">
    <input type="password" name="password" placeholder="Enter Password" style="padding:10px; width:200px;"><br><br>
    <input type="submit" value="Login" style="padding:10px 20px;">
</form>
'''

dashboard_page = '''
<!doctype html>
<title>DarkIp Admin - Dashboard</title>
<h2 style="text-align:center; margin-top:20px;">Welcome to DarkIp Admin Panel</h2>
<form method="POST" action="/scan" style="text-align:center; margin-top:40px;">
    <input type="text" name="target" placeholder="Enter IP or CIDR Range" style="padding:10px; width:300px;"><br><br>
    <input type="submit" value="Start RustScan" style="padding:10px 20px;">
</form>
<br><br>
<div style="text-align:center;">
    <a href="/report" style="padding:10px 20px; background:black; color:white; text-decoration:none;">Download Last Report</a>
</div>
'''

result_page = '''
<!doctype html>
<title>DarkIp Admin - Scan Result</title>
<h2 style="text-align:center; margin-top:20px;">RustScan Result</h2>
<div style="margin:30px;">
<pre>
{{ result }}
</pre>
</div>
<div style="text-align:center;">
    <a href="/dashboard" style="padding:10px 20px; background:green; color:white; text-decoration:none;">Back to Dashboard</a>
</div>
'''

# Routes
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

    result = run_rustscan(target)

    # Save result
    with open('last_report.txt', 'w') as f:
        f.write(result)

    return render_template_string(result_page, result=result)

@app.route('/report')
def report():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return send_file('last_report.txt', as_attachment=True)

# Core RustScan Function
def run_rustscan(target):
    try:
        output = subprocess.check_output(['rustscan', '-a', target, '--', '-sV'], stderr=subprocess.DEVNULL, timeout=120)
        result = output.decode()
    except subprocess.TimeoutExpired:
        result = "Scan timed out!"
    except Exception as e:
        result = f"Error running RustScan: {str(e)}"
    
    now = datetime.datetime.now()
    result = f"Scan Target: {target}\nTime: {now}\n\n{result}"
    return result

# Run server
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
    
