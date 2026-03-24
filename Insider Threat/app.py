# ============================================================

# Insider Threat Detection Using Activity Logs

# app.py - Main Flask Application

# ============================================================
 
from flask import Flask, render_template, request, redirect, url_for, session, flash

from flask import send_from_directory

import sqlite3

import hashlib

import os

from datetime import datetime
 
app = Flask(__name__)

app.secret_key = 'insider_threat_secret_key_2024'
 
# ─────────────────────────────────────────────

# DATABASE SETUP

# ─────────────────────────────────────────────
 
DB_PATH = 'database.db'
 
def get_db():

    """Create and return a database connection."""

    conn = sqlite3.connect(DB_PATH)

    conn.row_factory = sqlite3.Row  # allows dict-like access

    return conn
 
def init_db():

    """Initialize database tables and default admin account."""

    conn = get_db()

    c = conn.cursor()
 
    # Users table

    c.execute('''

        CREATE TABLE IF NOT EXISTS users (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            username TEXT UNIQUE NOT NULL,

            password TEXT NOT NULL,

            role TEXT DEFAULT 'user'

        )

    ''')
 
    # Activity logs table

    c.execute('''

        CREATE TABLE IF NOT EXISTS activity_logs (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER,

            username TEXT,

            login_time TEXT,

            logout_time TEXT,

            activity_type TEXT,

            file_name TEXT,

            downloads INTEGER DEFAULT 0,

            failed_attempts INTEGER DEFAULT 0,

            device TEXT DEFAULT 'Laptop',

            location TEXT DEFAULT 'Pune',

            status TEXT DEFAULT 'Normal',

            reason TEXT

        )

    ''')
 
    # Session evaluations table

    c.execute('''

        CREATE TABLE IF NOT EXISTS session_evaluations (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER,

            username TEXT,

            session_start TEXT,

            session_end TEXT,

            total_activities INTEGER DEFAULT 0,

            total_downloads INTEGER DEFAULT 0,

            failed_attempts INTEGER DEFAULT 0,

            sensitive_access_count INTEGER DEFAULT 0,

            final_status TEXT DEFAULT 'Normal',

            evaluation_remark TEXT

        )

    ''')
 
    # Create default admin account if not exists

    admin_pass = hashlib.sha256('admin123'.encode()).hexdigest()

    c.execute("SELECT * FROM users WHERE username='admin'")

    if not c.fetchone():

        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",

                  ('admin', admin_pass, 'admin'))
 
    conn.commit()

    conn.close()
 
 
# ─────────────────────────────────────────────

# HELPER FUNCTIONS

# ─────────────────────────────────────────────
 
def hash_password(password):

    return hashlib.sha256(password.encode()).hexdigest()
 
def is_unusual_time():

    """Check if current hour is between 12 AM and 4 AM."""

    hour = datetime.now().hour

    return 0 <= hour < 4
 
def evaluate_session(user_id, username, session_start):

    """

    Evaluate a user's session and determine final threat status.

    Called on logout to generate session evaluation.

    """

    conn = get_db()

    c = conn.cursor()
 
    session_end = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
 
    # Count activities for this session

    c.execute('''

        SELECT

            COUNT(*) as total_activities,

            SUM(downloads) as total_downloads,

            SUM(failed_attempts) as failed_attempts,

            SUM(CASE WHEN file_name IN ('Salary_Data.xlsx','Confidential_Report.pdf') THEN 1 ELSE 0 END) as sensitive_count,

            SUM(CASE WHEN status='Suspicious' THEN 1 ELSE 0 END) as suspicious_count,

            SUM(CASE WHEN status='High Risk' THEN 1 ELSE 0 END) as highrisk_count

        FROM activity_logs

        WHERE user_id=? AND login_time >= ?

    ''', (user_id, session_start))
 
    row = c.fetchone()

    total_activities    = row['total_activities'] or 0

    total_downloads     = int(row['total_downloads'] or 0)

    failed_attempts     = int(row['failed_attempts'] or 0)

    sensitive_count     = int(row['sensitive_count'] or 0)

    suspicious_count    = int(row['suspicious_count'] or 0)

    highrisk_count      = int(row['highrisk_count'] or 0)
 
    # Determine final status

    risk_flags = 0

    remarks = []
 
    if is_unusual_time():

        risk_flags += 1

        remarks.append("Login during unusual hours (12AM–4AM)")

    if sensitive_count > 0:

        risk_flags += 1

        remarks.append(f"Accessed {sensitive_count} sensitive file(s)")

    if failed_attempts > 3:

        risk_flags += 1

        remarks.append(f"Failed login attempts: {failed_attempts}")

    if total_downloads > 5:

        risk_flags += 1

        remarks.append(f"Excessive downloads: {total_downloads}")
 
    if risk_flags >= 2 or highrisk_count > 0:

        final_status = 'High Risk'

    elif risk_flags == 1 or suspicious_count > 0:

        final_status = 'Suspicious'

    else:

        final_status = 'Normal'
 
    evaluation_remark = '; '.join(remarks) if remarks else 'No suspicious activity detected.'
 
    c.execute('''

        INSERT INTO session_evaluations

        (user_id, username, session_start, session_end, total_activities,

         total_downloads, failed_attempts, sensitive_access_count, final_status, evaluation_remark)

        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

    ''', (user_id, username, session_start, session_end, total_activities,

          total_downloads, failed_attempts, sensitive_count, final_status, evaluation_remark))
 
    conn.commit()

    conn.close()
 
def log_activity(user_id, username, activity_type, file_name=None,

                 downloads=0, failed_attempts=0):

    """

    Log any user activity into the activity_logs table.

    Automatically determines status based on detection rules.

    """

    conn = get_db()

    c = conn.cursor()
 
    login_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    status = 'Normal'

    reasons = []
 
    # Rule 1: Unusual login time

    if is_unusual_time():

        status = 'Suspicious'

        reasons.append('Unusual login time (12AM–4AM)')
 
    # Rule 2: Sensitive file accessed

    sensitive_files = ['Salary_Data.xlsx', 'Confidential_Report.pdf']

    if file_name and file_name in sensitive_files:

        status = 'Suspicious'

        reasons.append(f'Sensitive file accessed: {file_name}')
 
    # Rule 3: Failed login attempts > 3

    if failed_attempts > 3:

        status = 'Suspicious'

        reasons.append(f'Failed attempts: {failed_attempts}')
 
    # Rule 4: Downloads > 5

    if downloads > 5:

        status = 'Suspicious'

        reasons.append(f'High download count: {downloads}')
 
    # Rule 5: Multiple suspicious flags → High Risk

    if len(reasons) >= 2:

        status = 'High Risk'
 
    reason_text = '; '.join(reasons) if reasons else 'Normal activity'
 
    c.execute('''

        INSERT INTO activity_logs

        (user_id, username, login_time, activity_type, file_name,

         downloads, failed_attempts, device, location, status, reason)

        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

    ''', (user_id, username, login_time, activity_type, file_name,

          downloads, failed_attempts, 'Laptop', 'Pune', status, reason_text))
 
    conn.commit()

    conn.close()
 
 
# ─────────────────────────────────────────────

# ROUTES

# ─────────────────────────────────────────────
 
@app.route('/')

def index():

    """Home page with project description."""

    return render_template('index.html')
 
 
# ── REGISTER ─────────────────────────────────
 
@app.route('/register', methods=['GET', 'POST'])

def register():

    if request.method == 'POST':

        username = request.form['username'].strip()

        password = request.form['password'].strip()
 
        if not username or not password:

            flash('All fields are required.', 'danger')

            return render_template('register.html')
 
        conn = get_db()

        c = conn.cursor()

        c.execute("SELECT * FROM users WHERE username=?", (username,))

        if c.fetchone():

            flash('Username already exists.', 'danger')

            conn.close()

            return render_template('register.html')
 
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",

                  (username, hash_password(password), 'user'))

        conn.commit()

        conn.close()

        flash('Registration successful! Please login.', 'success')

        return redirect(url_for('login'))
 
    return render_template('register.html')
 
 
# ── LOGIN ─────────────────────────────────────
 
@app.route('/login', methods=['GET', 'POST'])

def login():

    if request.method == 'POST':

        username = request.form['username'].strip()

        password = request.form['password'].strip()
 
        conn = get_db()

        c = conn.cursor()

        c.execute("SELECT * FROM users WHERE username=?", (username,))

        user = c.fetchone()

        conn.close()
 
        if user and user['password'] == hash_password(password):

            # Successful login

            session['user_id']   = user['id']

            session['username']  = user['username']

            session['role']      = user['role']

            session['login_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            session['downloads'] = 0
 
            log_activity(user['id'], user['username'], 'Login')
 
            if user['role'] == 'admin':

                return redirect(url_for('admin_dashboard'))

            return redirect(url_for('user_dashboard'))

        else:

            # Failed login — log suspicious attempt

            # Try to get user_id for logging (may not exist)

            conn2 = get_db()

            c2 = conn2.cursor()

            c2.execute("SELECT * FROM users WHERE username=?", (username,))

            attempted_user = c2.fetchone()

            conn2.close()
 
            uid  = attempted_user['id']       if attempted_user else 0

            uname = attempted_user['username'] if attempted_user else username
 
            # Count previous failed attempts for this user

            conn3 = get_db()

            c3 = conn3.cursor()

            c3.execute('''

                SELECT SUM(failed_attempts) as total_fails

                FROM activity_logs WHERE username=?

            ''', (uname,))

            row = c3.fetchone()

            conn3.close()

            prev_fails = int(row['total_fails'] or 0)

            new_fails  = prev_fails + 1
 
            log_activity(uid, uname, 'Failed Login',

                         failed_attempts=new_fails)

            flash('Invalid username or password.', 'danger')
 
    return render_template('login.html')
 
 
# ── LOGOUT ────────────────────────────────────
 
@app.route('/logout')

def logout():

    if 'user_id' not in session:

        return redirect(url_for('login'))
 
    user_id    = session['user_id']

    username   = session['username']

    login_time = session.get('login_time', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
 
    # Log the logout activity

    log_activity(user_id, username, 'Logout')
 
    # Generate session evaluation

    evaluate_session(user_id, username, login_time)
 
    session.clear()

    flash('You have been logged out. Session evaluated.', 'info')

    return redirect(url_for('login'))
 
 
# ── USER DASHBOARD ────────────────────────────
 
@app.route('/dashboard')

def user_dashboard():

    if 'user_id' not in session or session.get('role') != 'user':

        return redirect(url_for('login'))

    return render_template('user_dashboard.html',

                           username=session['username'])
 
 
# ── FILE ACCESS ───────────────────────────────
 
@app.route('/access/<filename>')

def access_file(filename):

    """Log file access action."""

    if 'user_id' not in session:

        return redirect(url_for('login'))
 
    log_activity(session['user_id'], session['username'],

                 'File Access', file_name=filename)

    flash(f'"{filename}" has been accessed and activity logged.', 'info')

    return redirect(url_for('user_dashboard'))
 
 
@app.route('/download/<filename>')

def download_file(filename):

    """Log file download action and increment download count."""

    if 'user_id' not in session:

        return redirect(url_for('login'))
 
    session['downloads'] = session.get('downloads', 0) + 1
 
    log_activity(session['user_id'], session['username'],

                 'File Download', file_name=filename,

                 downloads=session['downloads'])

    flash(f'"{filename}" download logged successfully.', 'success')

    return redirect(url_for('user_dashboard'))
 
 
# ── ADMIN DASHBOARD ───────────────────────────
 
@app.route('/admin')

def admin_dashboard():

    if 'user_id' not in session or session.get('role') != 'admin':

        return redirect(url_for('login'))
 
    conn = get_db()

    c = conn.cursor()
 
    # Stats

    c.execute("SELECT COUNT(*) as cnt FROM activity_logs")

    total_logs = c.fetchone()['cnt']
 
    c.execute("SELECT COUNT(*) as cnt FROM users WHERE role='user'")

    total_users = c.fetchone()['cnt']
 
    c.execute("SELECT COUNT(*) as cnt FROM activity_logs WHERE status='Suspicious'")

    suspicious_count = c.fetchone()['cnt']
 
    c.execute("SELECT COUNT(*) as cnt FROM activity_logs WHERE status='High Risk'")

    highrisk_count = c.fetchone()['cnt']
 
    # Recent logs (last 10)

    c.execute("SELECT * FROM activity_logs ORDER BY id DESC LIMIT 10")

    recent_logs = c.fetchall()
 
    # Recent evaluations (last 10)

    c.execute("SELECT * FROM session_evaluations ORDER BY id DESC LIMIT 10")

    recent_evals = c.fetchall()
 
    # Chart data — evaluation distribution

    c.execute('''

        SELECT final_status, COUNT(*) as cnt

        FROM session_evaluations

        GROUP BY final_status

    ''')

    chart_rows = c.fetchall()

    chart_data = {'Normal': 0, 'Suspicious': 0, 'High Risk': 0}

    for row in chart_rows:

        chart_data[row['final_status']] = row['cnt']
 
    conn.close()
 
    return render_template('admin_dashboard.html',

        total_logs=total_logs,

        total_users=total_users,

        suspicious_count=suspicious_count,

        highrisk_count=highrisk_count,

        recent_logs=recent_logs,

        recent_evals=recent_evals,

        chart_data=chart_data

    )
 
 
# ── ALL LOGS PAGE ─────────────────────────────
 
@app.route('/logs')

def logs():

    if 'user_id' not in session or session.get('role') != 'admin':

        return redirect(url_for('login'))
 
    conn = get_db()

    c = conn.cursor()

    c.execute("SELECT * FROM activity_logs ORDER BY id DESC")

    all_logs = c.fetchall()

    conn.close()

    return render_template('logs.html', logs=all_logs)
 
 
# ── ALL EVALUATIONS PAGE ──────────────────────
 
@app.route('/evaluations')

def evaluations():

    if 'user_id' not in session or session.get('role') != 'admin':

        return redirect(url_for('login'))
 
    conn = get_db()

    c = conn.cursor()

    c.execute("SELECT * FROM session_evaluations ORDER BY id DESC")

    all_evals = c.fetchall()

    conn.close()

    return render_template('evaluations.html', evaluations=all_evals)
 
 
# ─────────────────────────────────────────────

# MAIN

# ─────────────────────────────────────────────
 
if __name__ == '__main__':
    init_db()
    app.run(host='127.0.0.1', port=5000, debug=False)