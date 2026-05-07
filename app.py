"""
Secure Web Application — Authentication, RBAC, and AES Encryption
Tech Stack: Flask · SQLite · Werkzeug PBKDF2 · AES-256 (cryptography)
"""

import sqlite3
import os
from functools import wraps
from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, g)
from werkzeug.security import generate_password_hash, check_password_hash
from encryption import encrypt_data, decrypt_data

# ──────────────────────────────────────────────
# App setup
# ──────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.urandom(32)          # Random secret per run
DATABASE = 'secure_app.db'


# ──────────────────────────────────────────────
# Database helpers
# ──────────────────────────────────────────────
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT    UNIQUE NOT NULL,
                password TEXT    NOT NULL,
                role     TEXT    NOT NULL DEFAULT 'user',
                note_enc TEXT
            );
        """)
        db.commit()

        # Seed an admin account if none exists
        admin = db.execute(
            "SELECT id FROM users WHERE username = 'admin'"
        ).fetchone()
        if not admin:
            db.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                ('admin',
                 generate_password_hash('Admin@1234'),
                 'admin')
            )
            db.commit()


# ──────────────────────────────────────────────
# Decorators
# ──────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('Access Denied: Admins only.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated


# ──────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────
@app.route('/')
def index():
    return redirect(url_for('login'))


# ── Register ──────────────────────────────────
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        note     = request.form.get('note', '').strip()

        if not username or not password:
            flash('Username and password are required.', 'danger')
            return render_template('register.html')

        hashed   = generate_password_hash(password)
        note_enc = encrypt_data(note) if note else ''

        try:
            db = get_db()
            db.execute(
                "INSERT INTO users (username, password, role, note_enc) VALUES (?, ?, 'user', ?)",
                (username, hashed, note_enc)
            )
            db.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already taken.', 'danger')

    return render_template('register.html')


# ── Login ─────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        db   = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if user and check_password_hash(user['password'], password):
            session['user_id']  = user['id']
            session['username'] = user['username']
            session['role']     = user['role']
            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')


# ── Logout ────────────────────────────────────
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# ── Dashboard (all authenticated users) ───────
@app.route('/dashboard')
@login_required
def dashboard():
    db   = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE id = ?", (session['user_id'],)
    ).fetchone()

    decrypted_note = ''
    if user['note_enc']:
        decrypted_note = decrypt_data(user['note_enc'])

    return render_template('dashboard.html',
                           user=user,
                           decrypted_note=decrypted_note)


# ── Save note (demonstrates encryption) ───────
@app.route('/save_note', methods=['POST'])
@login_required
def save_note():
    note     = request.form.get('note', '').strip()
    note_enc = encrypt_data(note) if note else ''

    db = get_db()
    db.execute(
        "UPDATE users SET note_enc = ? WHERE id = ?",
        (note_enc, session['user_id'])
    )
    db.commit()
    flash('Note saved and encrypted successfully.', 'success')
    return redirect(url_for('dashboard'))


# ── Admin panel (admin only) ───────────────────
@app.route('/admin')
@admin_required
def admin():
    db    = get_db()
    users = db.execute("SELECT id, username, role, note_enc FROM users").fetchall()
    return render_template('admin.html', users=users)


# ── Admin: promote / demote ───────────────────
@app.route('/admin/toggle_role/<int:user_id>')
@admin_required
def toggle_role(user_id):
    db   = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user:
        new_role = 'admin' if user['role'] == 'user' else 'user'
        db.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
        db.commit()
        flash(f"{user['username']} is now {new_role}.", 'info')
    return redirect(url_for('admin'))


# ── Admin: delete user ────────────────────────
@app.route('/admin/delete/<int:user_id>')
@admin_required
def delete_user(user_id):
    if user_id == session['user_id']:
        flash("You cannot delete your own account.", 'warning')
        return redirect(url_for('admin'))
    db = get_db()
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    flash('User deleted.', 'info')
    return redirect(url_for('admin'))


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────
if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)
