# 🔐 SecureApp — Secure Web Application

A Flask-based web application demonstrating:
- **Authentication** with PBKDF2-SHA256 password hashing
- **Role-Based Access Control (RBAC)** — user / admin roles
- **AES-256-CBC Encryption** for sensitive stored data
- **Session management** with Flask sessions

---

## 🚀 Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the application
python app.py

# 3. Open in browser
# http://127.0.0.1:5000
```

---

## 🧪 Demo Credentials

| Role  | Username | Password    |
|-------|----------|-------------|
| Admin | `admin`  | `Admin@1234` |

Register any new account to get a `user` role.

---

## 📁 Project Structure

```
secure_webapp/
├── app.py            ← Flask app, routes, auth, RBAC
├── encryption.py     ← AES-256-CBC encrypt / decrypt
├── requirements.txt
├── secure_app.db     ← SQLite database (auto-created)
├── static/
│   └── style.css
└── templates/
    ├── base.html
    ├── login.html
    ├── register.html
    ├── dashboard.html
    └── admin.html
```

---

## 🔒 Security Features

### 1. Password Hashing
- Algorithm: **PBKDF2-SHA256** (via Werkzeug)
- Passwords are **never stored in plaintext**
- Verification uses constant-time comparison

### 2. Role-Based Access Control
| Route       | user | admin |
|-------------|------|-------|
| `/dashboard`| ✅   | ✅    |
| `/admin`    | 🚫   | ✅    |

### 3. AES-256-CBC Encryption
- Algorithm: **AES-256 in CBC mode**
- A unique **random IV** is generated per encryption
- Encrypted data stored as `base64(IV + ciphertext)`
- Set `AES_SECRET_KEY` env variable in production

### 4. Session Management
- Flask server-side sessions
- `login_required` and `admin_required` decorators

---

## ⚠️ Production Checklist

- [ ] Set `SECRET_KEY` and `AES_SECRET_KEY` as environment variables
- [ ] Use a production WSGI server (Gunicorn, uWSGI)
- [ ] Enable HTTPS / TLS
- [ ] Add CSRF tokens to all forms
- [ ] Switch from SQLite to PostgreSQL/MySQL
- [ ] Add rate limiting on login endpoint
- [ ] Implement account lockout after failed attempts
