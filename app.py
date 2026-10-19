from flask import Flask, abort, current_app, flash, g, has_app_context, render_template, request, session, redirect, url_for
import re
import os
import secrets
import hmac
import threading
from urllib.parse import urlencode
from datetime import datetime, timedelta
from urllib.parse import urlsplit
from decimal import Decimal, InvalidOperation
import click
from dotenv import load_dotenv

load_dotenv()

try:
    import mysql.connector
    from mysql.connector import IntegrityError
    from mysql.connector.pooling import MySQLConnectionPool
except ImportError:
    mysql = None
    MySQLConnectionPool = None

    class IntegrityError(Exception):
        pass

from werkzeug.security import generate_password_hash, check_password_hash
import requests

app = Flask(__name__)

APP_ENV = os.getenv("APP_ENV", "development").strip().lower()
configured_secret = (os.getenv("APP_SECRET_KEY") or os.getenv("SECRET_KEY") or "").strip()
if APP_ENV == "production" and (
    len(configured_secret) < 32
    or configured_secret == "change-me-to-a-long-random-secret"
):
    raise RuntimeError("APP_SECRET_KEY must contain at least 32 characters in production.")
app.config["SECRET_KEY"] = configured_secret or os.urandom(32).hex()
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
secure_cookie_default = "true" if APP_ENV == "production" else "false"
app.config["SESSION_COOKIE_SECURE"] = os.getenv(
    "SESSION_COOKIE_SECURE",
    secure_cookie_default
).strip().lower() in {"1", "true", "yes", "on"}
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=int(os.getenv("SESSION_TIMEOUT_MINUTES", "30")))


def csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def validate_csrf_token():
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return None
    expected = session.get("_csrf_token", "")
    supplied = request.form.get("_csrf_token") or request.headers.get("X-CSRF-Token", "")
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        abort(400, description="The request could not be verified. Refresh the page and try again.")
    return None


@app.errorhandler(requests.RequestException)
def handle_external_request_error(error):
    current_app.logger.warning("External HTTP request failed: %s", error)
    if request.path in {"/buyer/ai-support/chat", "/seller/ai-assistant/chat"}:
        return {"error": "The local AI service is unavailable."}, 503
    return render_template(
        "auth/login.html",
        error="Google sign-in could not be completed. Please try again.",
        email=""
    ), 502


def _internal_error_response(error, operation):
    current_app.logger.error(
        "%s",
        operation,
        exc_info=(type(error), error, error.__traceback__)
    )
    return "The request could not be completed. Please try again.", 500


GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:5000/google/callback").strip()
GOOGLE_OAUTH_ENABLED = bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)


# =========================================================
# MYSQL CONNECTION
# =========================================================
# Supports both local names (MYSQL_HOST ...) and Railway names (MYSQLHOST ...).

MYSQL_HOST = os.getenv("MYSQL_HOST") or os.getenv("MYSQLHOST", "localhost")
MYSQL_USER = os.getenv("MYSQL_USER") or os.getenv("MYSQLUSER", "root")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD") or os.getenv("MYSQLPASSWORD", "")
MYSQL_DB = os.getenv("MYSQL_DB") or os.getenv("MYSQLDATABASE", "women_empowerment")
MYSQL_PORT = int(os.getenv("MYSQL_PORT") or os.getenv("MYSQLPORT", "3306"))


MYSQL_POOL_SIZE = int(os.getenv("MYSQL_POOL_SIZE", "5"))
_db_pool = None
_db_pool_lock = threading.Lock()


def _get_db_pool():
    global _db_pool
    if mysql is None or MySQLConnectionPool is None:
        raise RuntimeError("mysql-connector-python is required to access the database.")
    if _db_pool is None:
        with _db_pool_lock:
            if _db_pool is None:
                _db_pool = MySQLConnectionPool(
                    pool_name="sherise_pool",
                    pool_size=MYSQL_POOL_SIZE,
                    pool_reset_session=True,
                    host=MYSQL_HOST,
                    port=MYSQL_PORT,
                    user=MYSQL_USER,
                    password=MYSQL_PASSWORD,
                    database=MYSQL_DB
                )
    return _db_pool


def _get_db_connection():
    if not has_app_context():
        raise RuntimeError("Database access requires an active Flask application context.")
    connection = g.get("db_connection")
    if connection is None:
        connection = _get_db_pool().get_connection()
        g.db_connection = connection
    return connection


class DatabaseProxy:
    def __getattr__(self, name):
        return getattr(_get_db_connection(), name)


db = DatabaseProxy()


@app.cli.command("create-admin")
@click.option("--email", prompt=True, help="Email address for the administrator.")
@click.option("--full-name", prompt=True, help="Administrator's display name.")
@click.option(
    "--password",
    prompt=True,
    hide_input=True,
    confirmation_prompt=True,
    help="Use a unique password with at least 12 characters."
)
def create_admin(email, full_name, password):
    email = email.strip().lower()
    full_name = full_name.strip()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise click.ClickException("Enter a valid email address.")
    if not full_name or len(full_name) > 150:
        raise click.ClickException("Enter a name of 1 to 150 characters.")
    if len(password) < 12:
        raise click.ClickException("Administrator passwords must be at least 12 characters.")

    cursor = None
    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT id, role FROM users WHERE email = %s", (email,))
        existing = cursor.fetchone()
        password_hash = generate_password_hash(password)
        if existing:
            if existing["role"] != "admin":
                raise click.ClickException("That email belongs to a non-administrator account.")
            cursor.execute("""
                UPDATE users
                SET full_name = %s, password = %s
                WHERE id = %s AND role = 'admin'
            """, (full_name, password_hash, existing["id"]))
        else:
            cursor.execute("""
                INSERT INTO users (full_name, email, mobile, password, role)
                VALUES (%s, %s, %s, %s, 'admin')
            """, (full_name, email, "0000000000", password_hash))
        db.commit()
        click.echo("Administrator credentials have been provisioned.")
    except click.ClickException:
        db.rollback()
        raise
    except Exception as e:
        db.rollback()
        current_app.logger.exception("Administrator provisioning failed.")
        raise click.ClickException("Administrator provisioning failed; check the database connection and schema.") from e
    finally:
        if cursor:
            cursor.close()


@app.teardown_appcontext
def release_db_connection(error=None):
    connection = g.pop("db_connection", None)
    if connection is None:
        return
    try:
        connection.rollback()
    except Exception:
        current_app.logger.exception("Failed to roll back the request database connection.")
    finally:
        connection.close()

# =========================================================
# DATABASE HELPER
# =========================================================

def ensure_db_connection():
    connection = _get_db_connection()
    connection.ping(reconnect=True, attempts=3, delay=1)


def ensure_auth_security_tables():
    """Use the auth-security table created by the database installation script."""
    ensure_db_connection()


def login_locked(email):
    """Return True when the account is temporarily locked for repeated failures."""
    ensure_auth_security_tables()
    cursor = None
    try:
        cursor = db.cursor(dictionary=True)
        cursor.execute("""
            SELECT failed_attempts, first_failed_at, locked_until
            FROM login_attempts
            WHERE email = %s
        """, (email,))
        record = cursor.fetchone()
        if not record:
            return False

        if record["locked_until"] and record["locked_until"] > datetime.now():
            return True

        if record["first_failed_at"] and datetime.now() - record["first_failed_at"] > timedelta(minutes=15):
            cursor.execute("DELETE FROM login_attempts WHERE email = %s", (email,))
            db.commit()
            return False

        return False
    finally:
        if cursor:
            cursor.close()


def register_failed_login(email):
    """Track a failed login and lock the account after 5 failures within 15 minutes."""
    ensure_auth_security_tables()
    cursor = None
    try:
        cursor = db.cursor(dictionary=True)
        cursor.execute("""
            SELECT failed_attempts, first_failed_at, locked_until
            FROM login_attempts
            WHERE email = %s
        """, (email,))
        record = cursor.fetchone()
        now = datetime.now()

        if not record:
            cursor.execute("""
                INSERT INTO login_attempts (email, failed_attempts, first_failed_at, last_failed_at)
                VALUES (%s, 1, %s, %s)
            """, (email, now, now))
            db.commit()
            return False

        if record["locked_until"] and record["locked_until"] > now:
            return True

        if record["first_failed_at"] and now - record["first_failed_at"] > timedelta(minutes=15):
            cursor.execute("""
                UPDATE login_attempts
                SET failed_attempts = 1,
                    first_failed_at = %s,
                    last_failed_at = %s,
                    locked_until = NULL
                WHERE email = %s
            """, (now, now, email))
            db.commit()
            return False

        failed_attempts = int(record["failed_attempts"] or 0) + 1
        locked_until = None
        if failed_attempts >= 5:
            locked_until = now + timedelta(minutes=15)

        cursor.execute("""
            UPDATE login_attempts
            SET failed_attempts = %s,
                last_failed_at = %s,
                locked_until = %s
            WHERE email = %s
        """, (failed_attempts, now, locked_until, email))
        db.commit()
        return failed_attempts >= 5
    finally:
        if cursor:
            cursor.close()


def clear_failed_logins(email):
    """Clear any blocked login state after a successful authentication."""
    ensure_auth_security_tables()
    cursor = None
    try:
        cursor = db.cursor()
        cursor.execute("DELETE FROM login_attempts WHERE email = %s", (email,))
        db.commit()
    except Exception:
        db.rollback()
    finally:
        if cursor:
            cursor.close()


# =========================================================
# HOME PAGE
# =========================================================

# Registered under both endpoint names so templates can use
# url_for('index') or url_for('home').
@app.route("/", endpoint="index")
@app.route("/")
def home():
    """Open the public website landing page at the root URL."""
    return render_template("index.html")


# =========================================================
# REGISTRATION - GOOGLE AUTHENTICATION REQUIRED
# =========================================================

@app.route("/register", methods=["GET", "POST"])
def register():
    """
    Start registration for a buyer, seller, or mentor.

    The user enters the registration details first. The account is NOT
    created until Google authenticates the email address. This prevents
    unverified email accounts from being created through normal registration.
    """
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        mobile = request.form.get("mobile", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        role = request.form.get("role", "").strip().lower()

        form_data = {
            "full_name": full_name,
            "email": email,
            "mobile": mobile,
            "role": role
        }

        def render_error(message):
            return render_template(
                "auth/register.html",
                error=message,
                form_data=form_data
            )

        if not full_name or not email or not mobile or not password or not confirm_password:
            return render_error("Please fill all required fields.")

        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            return render_error("Please enter a valid email address.")

        if not re.fullmatch(r"\d{10}", mobile):
            return render_error("Mobile number must contain exactly 10 digits.")

        if role not in ["buyer", "seller", "mentor"]:
            return render_error("Invalid role selected.")

        if (
            len(password) < 8
            or not re.search(r"[A-Z]", password)
            or not re.search(r"[a-z]", password)
            or not re.search(r"\d", password)
        ):
            return render_error(
                "Password must contain at least 8 characters, one uppercase letter, "
                "one lowercase letter, and one number."
            )

        if password != confirm_password:
            return render_error("Passwords do not match.")

        cursor = None
        try:
            ensure_db_connection()
            cursor = db.cursor(dictionary=True)
            cursor.execute("""
                SELECT id
                FROM users
                WHERE email = %s OR mobile = %s
                LIMIT 1
            """, (email, mobile))

            if cursor.fetchone():
                return render_error(
                    "An account with this email or mobile number already exists."
                )

            if not google_oauth_enabled():
                return render_error(
                    "Google registration is not configured yet. Please configure "
                    "GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET first."
                )

            # Never store a plaintext password in the session. The temporary
            # registration data contains only the password hash.
            session["pending_registration"] = {
                "full_name": full_name,
                "email": email,
                "mobile": mobile,
                "password_hash": generate_password_hash(password),
                "role": role
            }
            return redirect(url_for("register_google"))

        except Exception:
            current_app.logger.exception("Registration preparation failed.")
            return render_error(
                "Unable to start registration right now. Please try again."
            )
        finally:
            if cursor:
                cursor.close()

    return render_template(
        "auth/register.html",
        error=None,
        message=None,
        form_data={}
    )


# =========================================================
# LOGIN - PASSWORD
# =========================================================


# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        cursor = None

        if not email or not password:
            return render_template(
                "auth/login.html",
                error="Please enter your email and password.",
                email=email
            )

        if login_locked(email):
            return render_template(
                "auth/login.html",
                error="Your account has been temporarily locked for 15 minutes due to repeated failed login attempts.",
                email=email
            )

        try:
            ensure_db_connection()
            cursor = db.cursor(dictionary=True)
            cursor.execute("""
                SELECT id, full_name, email, password, role
                FROM users
                WHERE email = %s
            """, (email,))
            user = cursor.fetchone()

            if not user or not check_password_hash(user["password"], password):
                register_failed_login(email)
                return render_template(
                    "auth/login.html",
                    error="Incorrect email or password.",
                    email=email
                )

            clear_failed_logins(email)
            establish_login_session(user)
            return redirect_after_login(user)

        except Exception:
            current_app.logger.exception("Password sign-in failed.")
            return render_template(
                "auth/login.html",
                error="Sign-in could not be completed. Please try again.",
                email=email
            )
        finally:
            if cursor:
                cursor.close()

    message = None
    if request.args.get("registered") == "1":
        message = "Account created successfully. You can now log in."

    return render_template("auth/login.html", message=message)


# =========================================================
# GOOGLE OAUTH - LOGIN AND REGISTRATION
# =========================================================

def google_oauth_enabled():
    """Return True when the app is configured to accept Google sign-ins."""
    return bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)


def _google_authorize(mode):
    if not google_oauth_enabled():
        template = "auth/register.html" if mode == "register" else "auth/login.html"
        return render_template(
            template,
            error="Google authentication is not configured. Add GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET to your environment.",
            email=""
        )

    state = secrets.token_urlsafe(32)
    session["google_oauth_state"] = state
    session["google_oauth_mode"] = mode

    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "online",
        "prompt": "select_account",
        "state": state
    }
    auth_url = "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)
    return redirect(auth_url)


@app.route("/login/google")
def login_google():
    return _google_authorize("login")


@app.route("/register/google")
def register_google():
    pending = session.get("pending_registration")
    if not pending:
        return redirect(url_for("register"))
    return _google_authorize("register")


@app.route("/google/callback")
def google_callback():
    expected_state = session.pop("google_oauth_state", "")
    mode = session.pop("google_oauth_mode", "login")
    returned_state = request.args.get("state", "")

    if not expected_state or not returned_state or not hmac.compare_digest(
        expected_state,
        returned_state
    ):
        template = "auth/register.html" if mode == "register" else "auth/login.html"
        return render_template(
            template,
            error="Google authentication could not be verified. Please try again.",
            email=""
        ), 400

    error_message = request.args.get("error")
    if error_message:
        if mode == "register":
            session.pop("pending_registration", None)
        template = "auth/register.html" if mode == "register" else "auth/login.html"
        return render_template(
            template,
            error="Google authentication was cancelled or could not be completed.",
            email=""
        )

    code = request.args.get("code")
    if not code:
        if mode == "register":
            session.pop("pending_registration", None)
        template = "auth/register.html" if mode == "register" else "auth/login.html"
        return render_template(
            template,
            error="Google authentication failed: no authorization code returned.",
            email=""
        )

    try:
        token_response = requests.post(
            "https://oauth2.googleapis.com/token",
            data={
                "code": code,
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uri": GOOGLE_REDIRECT_URI,
                "grant_type": "authorization_code"
            },
            timeout=15
        )
        token_response.raise_for_status()

        token_data = token_response.json()
        access_token = token_data.get("access_token")
        if not access_token:
            raise RuntimeError("Google did not return an access token.")

        userinfo_response = requests.get(
            "https://openidconnect.googleapis.com/v1/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=15
        )
        userinfo_response.raise_for_status()

        userinfo = userinfo_response.json()
        if userinfo.get("email_verified") is not True:
            raise RuntimeError("Google did not verify the email address.")

        google_email = (userinfo.get("email") or "").strip().lower()
        if not google_email:
            raise RuntimeError("Google did not return an email address.")

        google_name = (
            userinfo.get("name")
            or userinfo.get("given_name")
            or "Google User"
        ).strip() or "Google User"

    except requests.RequestException:
        current_app.logger.exception("Google HTTP request failed.")
        if mode == "register":
            session.pop("pending_registration", None)
        template = "auth/register.html" if mode == "register" else "auth/login.html"
        return render_template(
            template,
            error="Google authentication could not be completed. Please try again.",
            email=""
        ), 502
    except Exception:
        current_app.logger.exception("Google profile validation failed.")
        if mode == "register":
            session.pop("pending_registration", None)
        template = "auth/register.html" if mode == "register" else "auth/login.html"
        return render_template(
            template,
            error="Google authentication could not be completed. Please try again.",
            email=""
        ), 400

    cursor = None
    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        cursor.execute("""
            SELECT id, full_name, email, password, role
            FROM users
            WHERE email = %s
        """, (google_email,))
        user = cursor.fetchone()

        if mode == "register":
            pending = session.pop("pending_registration", None)
            if not pending:
                return redirect(url_for("register"))

            # The email typed on the registration form must belong to the
            # Google account being authenticated.
            if pending["email"] != google_email:
                return render_template(
                    "auth/register.html",
                    error=(
                        "The Google email does not match the email entered in "
                        "the registration form. Please use the same email."
                    ),
                    form_data={
                        "full_name": pending["full_name"],
                        "email": pending["email"],
                        "mobile": pending["mobile"],
                        "role": pending["role"]
                    }
                ), 400

            if user:
                return render_template(
                    "auth/register.html",
                    error="An account with this Google email already exists. Please log in instead.",
                    form_data={
                        "full_name": pending["full_name"],
                        "email": pending["email"],
                        "mobile": pending["mobile"],
                        "role": pending["role"]
                    }
                )

            cursor.execute("""
                SELECT id
                FROM users
                WHERE mobile = %s
                LIMIT 1
            """, (pending["mobile"],))
            if cursor.fetchone():
                return render_template(
                    "auth/register.html",
                    error="An account with this mobile number already exists.",
                    form_data={
                        "full_name": pending["full_name"],
                        "email": pending["email"],
                        "mobile": pending["mobile"],
                        "role": pending["role"]
                    }
                )

            cursor.execute("""
                INSERT INTO users (full_name, email, mobile, password, role)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                pending["full_name"],
                google_email,
                pending["mobile"],
                pending["password_hash"],
                pending["role"]
            ))
            user_id = cursor.lastrowid

            if pending["role"] == "seller":
                cursor.execute("""
                    INSERT INTO seller_approvals (seller_id, status)
                    VALUES (%s, 'pending')
                """, (user_id,))

            db.commit()

            cursor.execute("""
                SELECT id, full_name, email, password, role
                FROM users
                WHERE id = %s
            """, (user_id,))
            user = cursor.fetchone()

        else:
            # Google login is for accounts that already exist. Registration
            # must go through /register so the user explicitly selects a role.
            if not user:
                return render_template(
                    "auth/login.html",
                    error="No account was found for this Google email. Please register first.",
                    email=google_email
                )

        clear_failed_logins(google_email)
        establish_login_session(user)
        return redirect_after_login(user)

    except IntegrityError:
        db.rollback()
        current_app.logger.exception("Google account creation conflict.")
        template = "auth/register.html" if mode == "register" else "auth/login.html"
        return render_template(
            template,
            error="An account with these details already exists. Please try again.",
            email=google_email
        ), 409
    except Exception:
        db.rollback()
        current_app.logger.exception("Google authentication database operation failed.")
        template = "auth/register.html" if mode == "register" else "auth/login.html"
        return render_template(
            template,
            error="Google authentication could not be completed. Please try again.",
            email=google_email
        ), 500
    finally:
        if cursor:
            cursor.close()


# =========================================================
# LOGIN SESSION + ROLE REDIRECT
# =========================================================

def establish_login_session(user):
    """Create the application session after password authentication."""
    session.clear()
    session.permanent = True
    session["user_id"] = user["id"]
    session["full_name"] = user["full_name"]
    session["email"] = user["email"]
    session["role"] = user["role"]


def redirect_after_login(user):
    """Send the user to the dashboard belonging to their role."""
    role = (user.get("role") or "").strip().lower()

    if role == "seller":
        if not seller_has_access(user["id"]):
            return redirect(url_for("seller_pending_approval"))
        return redirect(url_for("seller_dashboard"))
    if role == "buyer":
        return redirect(url_for("buyer_dashboard"))
    if role == "mentor":
        return redirect(url_for("mentor_dashboard"))
    if role == "admin":
        return redirect(url_for("admin_dashboard"))

    session.clear()
    return redirect(url_for("login"))


# =========================================================
# BUYER ACCESS CHECK
# =========================================================

def buyer_required():

    return (
        "user_id" in session
        and session.get("role") == "buyer"
    )


# =========================================================
# SELLER ACCESS CHECK
# =========================================================

def seller_required():
    if "user_id" not in session or session.get("role") != "seller":
        return False
    return seller_has_access(session["user_id"])


def seller_has_access(seller_id):
    cursor = None
    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute("""
            SELECT status, account_status
            FROM seller_approvals
            WHERE seller_id = %s
            LIMIT 1
        """, (seller_id,))
        approval = cursor.fetchone()
        return bool(
            approval
            and approval["status"] == "approved"
            and approval["account_status"] == "active"
        )
    except Exception:
        current_app.logger.exception("Unable to verify seller account access.")
        abort(503, description="Seller access could not be verified. Please try again later.")
    finally:
        if cursor:
            cursor.close()


@app.route("/seller/pending-approval")
def seller_pending_approval():
    if "user_id" not in session or session.get("role") != "seller":
        return redirect(url_for("login"))

    cursor = None
    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute("""
            SELECT status, account_status, review_note
            FROM seller_approvals
            WHERE seller_id = %s
            LIMIT 1
        """, (session["user_id"],))
        approval = cursor.fetchone() or {
            "status": "pending",
            "account_status": "active",
            "review_note": None
        }
        if approval["status"] == "approved" and approval["account_status"] == "active":
            return redirect(url_for("seller_dashboard"))
        return render_template("seller/pending.html", approval=approval)
    except Exception:
        current_app.logger.exception("Unable to load seller approval status.")
        return "Unable to load seller approval status.", 500
    finally:
        if cursor:
            cursor.close()

def admin_required():

    return (
        "user_id" in session
        and session.get("role") == "admin"
    )


# =========================================================
# MENTOR ACCESS + DATABASE HELPERS
# =========================================================

def mentor_required():
    return (
        "user_id" in session
        and session.get("role") == "mentor"
    )


def ensure_mentor_tables():
    """Create the mentorship tables used by the Mentor Portal."""
    ensure_db_connection()
    cursor = None

    try:
        cursor = db.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS mentor_profiles (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                expertise VARCHAR(255) NULL,
                bio TEXT NULL,
                experience_years INT NOT NULL DEFAULT 0,
                availability VARCHAR(255) NULL,
                status VARCHAR(30) NOT NULL DEFAULT 'pending',
                review_note TEXT NULL,
                reviewed_by INT NULL,
                reviewed_at TIMESTAMP NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY uq_mentor_profile_user (user_id),
                INDEX idx_mentor_profile_status (status),
                INDEX idx_mentor_profile_expertise (expertise),
                CONSTRAINT fk_mentor_profile_user
                    FOREIGN KEY (user_id) REFERENCES users(id)
                    ON DELETE CASCADE,
                CONSTRAINT fk_mentor_profile_reviewer
                    FOREIGN KEY (reviewed_by) REFERENCES users(id)
                    ON DELETE SET NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS mentorship_requests (
                id INT AUTO_INCREMENT PRIMARY KEY,
                mentor_id INT NOT NULL,
                entrepreneur_id INT NOT NULL,
                subject VARCHAR(255) NOT NULL,
                message TEXT NULL,
                status VARCHAR(30) NOT NULL DEFAULT 'pending',
                mentor_response TEXT NULL,
                scheduled_at DATETIME NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_mentorship_requests_mentor (mentor_id),
                INDEX idx_mentorship_requests_entrepreneur (entrepreneur_id),
                INDEX idx_mentorship_requests_status (status),
                INDEX idx_mentorship_requests_created (created_at),
                CONSTRAINT fk_mentorship_request_mentor
                    FOREIGN KEY (mentor_id) REFERENCES users(id)
                    ON DELETE CASCADE,
                CONSTRAINT fk_mentorship_request_entrepreneur
                    FOREIGN KEY (entrepreneur_id) REFERENCES users(id)
                    ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS mentorship_sessions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                request_id INT NOT NULL,
                mentor_id INT NOT NULL,
                entrepreneur_id INT NOT NULL,
                scheduled_at DATETIME NULL,
                duration_minutes INT NOT NULL DEFAULT 60,
                notes TEXT NULL,
                status VARCHAR(30) NOT NULL DEFAULT 'scheduled',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_mentorship_sessions_request (request_id),
                INDEX idx_mentorship_sessions_mentor (mentor_id),
                INDEX idx_mentorship_sessions_entrepreneur (entrepreneur_id),
                INDEX idx_mentorship_sessions_status (status),
                CONSTRAINT fk_mentorship_session_request
                    FOREIGN KEY (request_id) REFERENCES mentorship_requests(id)
                    ON DELETE CASCADE,
                CONSTRAINT fk_mentorship_session_mentor
                    FOREIGN KEY (mentor_id) REFERENCES users(id)
                    ON DELETE CASCADE,
                CONSTRAINT fk_mentorship_session_entrepreneur
                    FOREIGN KEY (entrepreneur_id) REFERENCES users(id)
                    ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS mentorship_feedback (
                id INT AUTO_INCREMENT PRIMARY KEY,
                session_id INT NOT NULL,
                mentor_id INT NOT NULL,
                entrepreneur_id INT NOT NULL,
                rating TINYINT NOT NULL,
                feedback_text TEXT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_mentorship_feedback_session (session_id),
                INDEX idx_mentorship_feedback_mentor (mentor_id),
                INDEX idx_mentorship_feedback_entrepreneur (entrepreneur_id),
                CONSTRAINT fk_mentorship_feedback_session
                    FOREIGN KEY (session_id) REFERENCES mentorship_sessions(id)
                    ON DELETE CASCADE,
                CONSTRAINT fk_mentorship_feedback_mentor
                    FOREIGN KEY (mentor_id) REFERENCES users(id)
                    ON DELETE CASCADE,
                CONSTRAINT fk_mentorship_feedback_entrepreneur
                    FOREIGN KEY (entrepreneur_id) REFERENCES users(id)
                    ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            INSERT INTO mentor_profiles (user_id, status)
            SELECT u.id, 'pending'
            FROM users u
            LEFT JOIN mentor_profiles mp ON mp.user_id = u.id
            WHERE u.role = 'mentor' AND mp.id IS NULL
        """)

        db.commit()
    finally:
        if cursor:
            cursor.close()
