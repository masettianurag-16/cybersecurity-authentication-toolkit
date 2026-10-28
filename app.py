import os
import re
import secrets
import sqlite3
from functools import wraps
from datetime import datetime
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    g,
    abort
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Security: Load secret key from environment or generate a secure fallback
app.secret_key = os.environ.get("SECRET_KEY", "dev-secure-fallback-" + secrets.token_hex(16))

# Cookie security settings
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # Set to True in production with HTTPS
)

DATABASE = os.path.join(os.path.abspath(os.path.dirname(__file__)), "database.db")


def get_db():
    """Get a thread-safe database connection for the current request context."""
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    """Close database connection at the end of the request."""
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    """Initialize SQLite database with the secure users table."""
    conn = sqlite3.connect(DATABASE)
    try:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
    finally:
        conn.close()


# Initialize database when module is imported
init_db()


# ====================================================================
# Security Helpers & Middleware
# ====================================================================

def validate_password_policy(password: str) -> tuple[bool, str]:
    """
    Validate password against cybersecurity complexity standards:
    - At least 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number
    - At least one special character
    """
    if not password:
        return False, "Password cannot be empty."
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number."
    if not re.search(r'[!@#$%^&*(),.?":{}|<>\-_=+[\]\\/;\'`~]', password):
        return False, "Password must contain at least one special character (e.g. !@#$%^&*)."
    return True, ""


def validate_email_format(email: str) -> bool:
    """Validate email format using standard regular expression."""
    pattern = r"^[\w\.-]+@[\w\.-]+\.\w{2,}$"
    return bool(re.match(pattern, email.strip()))


def login_required(f):
    """Decorator to enforce session authentication on protected routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("You must be logged in to view the dashboard.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


@app.before_request
def csrf_protect():
    """
    Basic CSRF Protection:
    Ensures that every session has a unique CSRF token,
    and all POST requests provide a matching token.
    """
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(24)

    if request.method == "POST":
        token = request.form.get("csrf_token")
        if not token or token != session.get("csrf_token"):
            flash("Security check failed: Invalid or missing CSRF token. Please try again.", "danger")
            return redirect(request.url)


@app.context_processor
def inject_csrf_token():
    """Inject CSRF token into all Jinja templates automatically."""
    return dict(csrf_token=session.get("csrf_token"))


# ====================================================================
# Application Routes
# ====================================================================

@app.route("/")
def index():
    """Home landing page explaining the toolkit and security principles."""
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """User registration route with full validation and password hashing."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # 1. Input presence validation
        if not username:
            flash("Username is required.", "danger")
            return render_template("register.html", username=username, email=email)

        if not email or not validate_email_format(email):
            flash("Please enter a valid email address.", "danger")
            return render_template("register.html", username=username, email=email)

        # 2. Password match check
        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("register.html", username=username, email=email)

        # 3. Password complexity policy check
        is_valid, msg = validate_password_policy(password)
        if not is_valid:
            flash(msg, "danger")
            return render_template("register.html", username=username, email=email)

        # 4. Duplicate user / email check (prevent account collision)
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            flash("Username is already taken. Please choose another.", "danger")
            return render_template("register.html", username=username, email=email)

        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        if cursor.fetchone():
            flash("Email is already registered. Please login or use another email.", "danger")
            return render_template("register.html", username=username, email=email)

        # 5. Secure password hashing (Werkzeug generate_password_hash)
        password_hash = generate_password_hash(password)

        # 6. Store user in database with parameterized query (prevents SQL injection)
        cursor.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, password_hash)
        )
        db.commit()

        flash("Registration successful! You can now log in securely.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Login route with credential verification and generic failure errors."""
    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")

        if not identifier or not password:
            flash("Please enter both your username/email and password.", "danger")
            return render_template("login.html", identifier=identifier)

        # Look up user by username OR email (case-insensitive for email)
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            (identifier, identifier.lower())
        )
        user = cursor.fetchone()

        # Secure verification:
        # Check password hash using constant-time comparison.
        # If user does not exist or password is wrong, return identical generic message.
        # This prevents User Enumeration attacks.
        if user and check_password_hash(user["password_hash"], password):
            # Establish authenticated session
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["email"] = user["email"]
            session["logged_in_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            # Generate fresh CSRF token for the authenticated session
            session["csrf_token"] = secrets.token_hex(24)

            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password.", "danger")
            return render_template("login.html", identifier=identifier)

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    """Protected dashboard showing session status and security controls."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT created_at FROM users WHERE id = ?", (session["user_id"],))
    user_row = cursor.fetchone()
    account_created = user_row["created_at"] if user_row else "Unknown"

    return render_template(
        "dashboard.html",
        username=session.get("username"),
        email=session.get("email"),
        logged_in_at=session.get("logged_in_at"),
        account_created=account_created
    )


@app.route("/logout")
def logout():
    """Clear session data and redirect to login."""
    session.clear()
    flash("You have been logged out securely.", "info")
    return redirect(url_for("login"))


if __name__ == "__main__":
    # Run development server locally with auto-reloader disabled
    app.run(host="127.0.0.1", port=5000, debug=True, use_reloader=False)

