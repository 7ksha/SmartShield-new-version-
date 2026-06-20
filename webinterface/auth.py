"""
SmartShield Web Interface Authentication
=========================================
Adds login-required protection to all SmartShield web interface routes.

Usage
-----
Install: pip install flask-login flask-bcrypt
Config:  Set WEB_ADMIN_USER / WEB_ADMIN_PASSWORD environment variables,
         or edit the defaults below.

The default credentials (admin / SmartShield2024!) MUST be changed before
any production deployment.  Set environment variables:

    export SMARTSHIELD_WEB_USER=myuser
    export SMARTSHIELD_WEB_PASSWORD=my_strong_password_here

Integration
-----------
Import and call ``init_auth(app)`` from webinterface/app.py after creating
the Flask app.  Then decorate protected blueprints with ``@login_required``.
"""

import os
import functools
from datetime import timedelta

from flask import (
    Blueprint,
    render_template_string,
    request,
    redirect,
    url_for,
    session,
    flash,
)

# ── Credentials (override via environment variables) ─────────────────────────
_DEFAULT_USER = "admin"
_DEFAULT_PASSWORD = "SmartShield2024!"  # MUST be changed in production

ADMIN_USER = os.environ.get("SMARTSHIELD_WEB_USER", _DEFAULT_USER)
ADMIN_PASSWORD = os.environ.get("SMARTSHIELD_WEB_PASSWORD", _DEFAULT_PASSWORD)

# ── Blueprint ─────────────────────────────────────────────────────────────────
auth_bp = Blueprint("auth", __name__)

# ── Login page template ───────────────────────────────────────────────────────
_LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>SmartShield — Login</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: #0f1117;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
    }
    .card {
      background: #1a1d27;
      border: 1px solid #2e3347;
      border-radius: 12px;
      padding: 2.5rem 2rem;
      width: 100%;
      max-width: 380px;
    }
    .logo {
      text-align: center;
      margin-bottom: 2rem;
    }
    .logo h1 {
      color: #4fc3f7;
      font-size: 1.6rem;
      font-weight: 600;
      letter-spacing: 0.5px;
    }
    .logo p {
      color: #8892a4;
      font-size: 0.8rem;
      margin-top: 4px;
    }
    label {
      display: block;
      color: #8892a4;
      font-size: 0.8rem;
      font-weight: 500;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 6px;
    }
    input[type=text], input[type=password] {
      width: 100%;
      padding: 0.7rem 0.9rem;
      background: #0f1117;
      border: 1px solid #2e3347;
      border-radius: 8px;
      color: #e2e8f0;
      font-size: 0.95rem;
      outline: none;
      margin-bottom: 1.2rem;
      transition: border-color 0.2s;
    }
    input:focus { border-color: #4fc3f7; }
    button {
      width: 100%;
      padding: 0.75rem;
      background: #1565c0;
      border: none;
      border-radius: 8px;
      color: #fff;
      font-size: 0.95rem;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.2s;
    }
    button:hover { background: #1976d2; }
    .error {
      background: #3b1a1a;
      border: 1px solid #c62828;
      color: #ef9a9a;
      border-radius: 8px;
      padding: 0.7rem 0.9rem;
      font-size: 0.85rem;
      margin-bottom: 1.2rem;
    }
    .warning {
      background: #3b2a0a;
      border: 1px solid #e65100;
      color: #ffcc80;
      border-radius: 8px;
      padding: 0.7rem 0.9rem;
      font-size: 0.8rem;
      margin-top: 1.2rem;
      text-align: center;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">
      <h1>SmartShield IPS</h1>
      <p>Factory OT/ICS Intrusion Prevention</p>
    </div>
    {% if error %}
    <div class="error">{{ error }}</div>
    {% endif %}
    <form method="post">
      <label>Username</label>
      <input type="text" name="username" autocomplete="username"
             autofocus required>
      <label>Password</label>
      <input type="password" name="password"
             autocomplete="current-password" required>
      <button type="submit">Sign in</button>
    </form>
    {% if using_default_password %}
    <div class="warning">
      &#9888; Default password in use. Set SMARTSHIELD_WEB_PASSWORD
      environment variable before factory deployment.
    </div>
    {% endif %}
  </div>
</body>
</html>
"""


# ── Auth helpers ──────────────────────────────────────────────────────────────

def is_logged_in() -> bool:
    return session.get("smartshield_authenticated") is True


def login_required(f):
    """
    Route decorator.  Redirects unauthenticated requests to /login.

    Usage::

        @app.route("/sensitive")
        @login_required
        def sensitive():
            ...
    """
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not is_logged_in():
            return redirect(url_for("auth.login", next=request.path))
        return f(*args, **kwargs)
    return decorated


# ── Routes ────────────────────────────────────────────────────────────────────

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if username == ADMIN_USER and password == ADMIN_PASSWORD:
            session.permanent = True
            session["smartshield_authenticated"] = True
            session["smartshield_user"] = username
            next_url = request.args.get("next") or url_for("index")
            return redirect(next_url)
        else:
            # Constant-time-ish delay to slow brute force
            import time
            time.sleep(0.5)
            error = "Invalid username or password."

    return render_template_string(
        _LOGIN_HTML,
        error=error,
        using_default_password=(ADMIN_PASSWORD == _DEFAULT_PASSWORD),
    )


@auth_bp.route("/logout")
def logout():
    session.pop("smartshield_authenticated", None)
    session.pop("smartshield_user", None)
    return redirect(url_for("auth.login"))


# ── App integration ───────────────────────────────────────────────────────────

def init_auth(app):
    """
    Call this after creating the Flask app to enable authentication.

    Example (webinterface/app.py)::

        from webinterface.auth import init_auth, login_required
        app = create_app()
        init_auth(app)
    """
    import secrets
    # Use a fixed secret key from environment (required for session persistence
    # across restarts). If not set, generate one (sessions lost on restart).
    app.secret_key = os.environ.get(
        "SMARTSHIELD_SECRET_KEY",
        secrets.token_hex(32)
    )
    app.permanent_session_lifetime = timedelta(hours=8)
    app.register_blueprint(auth_bp)

    # Protect every request: redirect to login if not authenticated,
    # except for the login route itself and static files.
    @app.before_request
    def require_login():
        allowed_paths = {"/login", "/logout", "/favicon.ico"}
        if request.path in allowed_paths:
            return None
        if request.path.startswith("/static"):
            return None
        if not is_logged_in():
            return redirect(url_for("auth.login", next=request.path))
        return None

    return app
