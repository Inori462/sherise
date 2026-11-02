from flask import (
    Flask,
    abort,
    current_app,
    flash,
    g,
    has_app_context,
    render_template,
    request,
    session,
    redirect,
    url_for
)

import os
import re
import secrets
import hmac
import threading
import requests
import click

from urllib.parse import urlencode, urlsplit
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation

from dotenv import load_dotenv

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from psycopg2.pool import ThreadedConnectionPool
from psycopg2.extras import RealDictCursor

load_dotenv()

try:
    import psycopg2
    from psycopg2 import IntegrityError
    from psycopg2.pool import ThreadedConnectionPool
    from psycopg2.extras import RealDictCursor
except ImportError:
    psycopg2 = None
    IntegrityError = Exception
    ThreadedConnectionPool = None
    RealDictCursor = None

app = Flask(__name__)

APP_ENV = os.getenv("APP_ENV", "development").strip().lower()
configured_secret = (
    os.getenv("APP_SECRET_KEY") or os.getenv("SECRET_KEY") or ""
).strip()

if APP_ENV == "production" and (
    len(configured_secret) < 32
    or configured_secret == "change-me-to-a-long-random-secret"
):
    raise RuntimeError(
        "APP_SECRET_KEY must contain at least 32 characters in production."
    )

app.config["SECRET_KEY"] = configured_secret or os.urandom(32).hex()
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = APP_ENV == "production"
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

secure_cookie_default = "true" if APP_ENV == "production" else "false"

app.config["SESSION_COOKIE_SECURE"] = os.getenv(
    "SESSION_COOKIE_SECURE",
    secure_cookie_default
).strip().lower() in {"1", "true", "yes", "on"}

app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(
    minutes=int(os.getenv("SESSION_TIMEOUT_MINUTES", "30"))
)


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
    supplied = (
        request.form.get("_csrf_token")
        or request.headers.get("X-CSRF-Token", "")
    )

    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        abort(
            400,
            description="The request could not be verified. Refresh the page and try again."
        )

    return None


@app.errorhandler(requests.RequestException)
def handle_external_request_error(error):
    current_app.logger.warning(
        "External HTTP request failed: %s", error
    )

    if request.path == "/buyer/ai-support/chat":
        return {"error": "The local AI service is unavailable."}, 503

    if request.path in {
        "/seller/ai-assistant/chat",
        "/seller/marketing/generate"
    }:
        return {
            "error": "The AI service is temporarily unavailable. Please try again."
        }, 503

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
GOOGLE_REDIRECT_URI = os.getenv(
    "GOOGLE_REDIRECT_URI",
    "http://localhost:5000/google/callback"
).strip()
GOOGLE_OAUTH_ENABLED = bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)


# =========================================================
# POSTGRESQL CONNECTION
# =========================================================

DATABASE_URL = os.getenv("DATABASE_URL")
PGHOST = os.getenv("PGHOST", os.getenv("DB_HOST", "localhost"))
PGPORT = int(os.getenv("PGPORT", os.getenv("DB_PORT", "5432")))
PGUSER = os.getenv("PGUSER", os.getenv("DB_USER", "postgres"))
PGPASSWORD = os.getenv("PGPASSWORD", os.getenv("DB_PASSWORD", ""))
PGDATABASE = os.getenv("PGDATABASE", os.getenv("DB_NAME", "postgres"))

PG_POOL_SIZE = int(os.getenv("PG_POOL_SIZE", "5"))

_db_pool = None
_db_pool_lock = threading.Lock()


def _get_db_pool():
    global _db_pool

    if psycopg2 is None or ThreadedConnectionPool is None:
        raise RuntimeError("psycopg2 is required to access the database.")

    if _db_pool is None:
        with _db_pool_lock:
            if _db_pool is None:
                if DATABASE_URL:
                    _db_pool = ThreadedConnectionPool(
                        minconn=1,
                        maxconn=PG_POOL_SIZE,
                        dsn=DATABASE_URL
                    )
                else:
                    _db_pool = ThreadedConnectionPool(
                        minconn=1,
                        maxconn=PG_POOL_SIZE,
                        host=PGHOST,
                        port=PGPORT,
                        user=PGUSER,
                        password=PGPASSWORD,
                        database=PGDATABASE
                    )

    return _db_pool


def _get_db_connection():
    if not has_app_context():
        raise RuntimeError(
            "Database access requires an active Flask application context."
        )

    connection = g.get("db_connection")

    if connection is None:
        connection = _get_db_pool().getconn()
        g.db_connection = connection

    return connection


class DatabaseProxy:

    def cursor(self, *args, **kwargs):
        conn = _get_db_connection()

        if kwargs.pop("dictionary", False):
            kwargs["cursor_factory"] = RealDictCursor

        return conn.cursor(*args, **kwargs)

    def commit(self):
        return _get_db_connection().commit()

    def rollback(self):
        return _get_db_connection().rollback()

    def __getattr__(self, name):
        return getattr(_get_db_connection(), name)


db = DatabaseProxy()


@app.cli.command("create-admin")
@click.option(
    "--email",
    prompt=True,
    help="Email address for the administrator."
)
@click.option(
    "--full-name",
    prompt=True,
    help="Administrator's display name."
)
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
        raise click.ClickException(
            "Enter a name of 1 to 150 characters."
        )

    if len(password) < 12:
        raise click.ClickException(
            "Administrator passwords must be at least 12 characters."
        )

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        cursor.execute(
            "SELECT id, role FROM users WHERE email = %s",
            (email,)
        )

        existing = cursor.fetchone()
        password_hash = generate_password_hash(password)

        if existing:
            if existing["role"] != "admin":
                raise click.ClickException(
                    "That email belongs to a non-administrator account."
                )

            cursor.execute("""
                UPDATE users
                SET full_name = %s, password = %s
                WHERE id = %s AND role = 'admin'
            """, (full_name, password_hash, existing["id"]))

        else:
            cursor.execute("""
                INSERT INTO users (full_name, email, mobile, password, role)
                VALUES (%s, %s, %s, %s, 'admin')
            """, (
                full_name,
                email,
                "0000000000",
                password_hash
            ))

        db.commit()
        click.echo(
            "Administrator credentials have been provisioned."
        )

    except click.ClickException:
        db.rollback()
        raise

    except Exception as e:
        db.rollback()
        current_app.logger.exception(
            "Administrator provisioning failed."
        )
        raise click.ClickException(
            "Administrator provisioning failed; check the database connection and schema."
        ) from e

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
        current_app.logger.exception(
            "Failed to roll back the request database connection."
        )

    finally:
        try:
            _db_pool.putconn(connection)

        except Exception:
            connection.close()


# =========================================================
# DATABASE HELPER
# =========================================================

def ensure_db_connection():
    connection = _get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")

    except Exception:
        g.pop("db_connection", None)

        try:
            _db_pool.putconn(connection, close=True)
        except Exception:
            connection.close()

        _get_db_connection()


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

        if (
            record["first_failed_at"]
            and datetime.now() - record["first_failed_at"]
            > timedelta(minutes=15)
        ):
            cursor.execute(
                "DELETE FROM login_attempts WHERE email = %s",
                (email,)
            )
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
                INSERT INTO login_attempts
                (email, failed_attempts, first_failed_at, last_failed_at)
                VALUES (%s, 1, %s, %s)
            """, (email, now, now))

            db.commit()
            return False

        if record["locked_until"] and record["locked_until"] > now:
            return True

        if (
            record["first_failed_at"]
            and now - record["first_failed_at"] > timedelta(minutes=15)
        ):
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

        cursor.execute(
            "DELETE FROM login_attempts WHERE email = %s",
            (email,)
        )

        db.commit()

    except Exception:
        db.rollback()

    finally:
        if cursor:
            cursor.close()


# =========================================================
# HOME PAGE
# =========================================================

@app.route("/")
def home():
    """Open the public website landing page at the root URL."""
    return render_template("index.html")


# =========================================================
# REGISTRATION - GOOGLE AUTHENTICATION REQUIRED
# =========================================================

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        role = request.form.get("role", "").strip().lower()

        form_data = {
            "full_name": full_name,
            "email": email,
            "role": role
        }

        def render_error(message):
            return render_template(
                "auth/register.html",
                error=message,
                form_data=form_data
            )

        if not full_name or not email or not password or not confirm_password:
            return render_error("Please fill all required fields.")

        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            return render_error("Please enter a valid email address.")

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
                WHERE email = %s
                LIMIT 1
            """, (email,))

            if cursor.fetchone():
                return render_error(
                    "An account with this email already exists. Please log in."
                )

            if not google_oauth_enabled():
                return render_error(
                    "Google registration is not configured yet. Please configure "
                    "GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET first."
                )

            session["pending_registration"] = {
                "full_name": full_name,
                "email": email,
                "password_hash": generate_password_hash(password),
                "role": role
            }

            return redirect(url_for("register_google"))

        except Exception:
            current_app.logger.exception(
                "Registration preparation failed."
            )

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

            if not user or not check_password_hash(
                user["password"], password
            ):
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
            current_app.logger.exception(
                "Password sign-in failed."
            )

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

    return render_template(
        "auth/login.html",
        message=message
    )


# =========================================================
# GOOGLE OAUTH - LOGIN AND REGISTRATION
# =========================================================

def google_oauth_enabled():
    """Return True when the app is configured to accept Google sign-ins."""
    return bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)


def _google_authorize(mode):
    if not google_oauth_enabled():
        template = (
            "auth/register.html"
            if mode == "register"
            else "auth/login.html"
        )

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

    auth_url = (
        "https://accounts.google.com/o/oauth2/v2/auth?"
        + urlencode(params)
    )

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
    mode = session.pop("google_oauth_mode", "")
    returned_state = request.args.get("state", "")

    if (
        not expected_state
        or not returned_state
        or not hmac.compare_digest(expected_state, returned_state)
    ):
        template = (
            "auth/register.html"
            if mode == "register"
            else "auth/login.html"
        )

        return render_template(
            template,
            error="Google authentication could not be verified. Please try again.",
            email=""
        ), 400

    if mode not in {"login", "register"}:
        session.pop("pending_registration", None)
        return redirect(url_for("login"))

    if mode != "register":
        session.pop("pending_registration", None)

    error_message = request.args.get("error")

    if error_message:
        if mode == "register":
            session.pop("pending_registration", None)

        template = (
            "auth/register.html"
            if mode == "register"
            else "auth/login.html"
        )

        return render_template(
            template,
            error="Google authentication was cancelled or could not be completed.",
            email=""
        )

    code = request.args.get("code")

    if not code:
        if mode == "register":
            session.pop("pending_registration", None)

        template = (
            "auth/register.html"
            if mode == "register"
            else "auth/login.html"
        )

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
            raise RuntimeError(
                "Google did not return an access token."
            )

        userinfo_response = requests.get(
            "https://openidconnect.googleapis.com/v1/userinfo",
            headers={
                "Authorization": f"Bearer {access_token}"
            },
            timeout=15
        )

        userinfo_response.raise_for_status()

        userinfo = userinfo_response.json()

        if userinfo.get("email_verified") is not True:
            raise RuntimeError(
                "Google did not verify the email address."
            )

        google_email = (
            userinfo.get("email") or ""
        ).strip().lower()

        if not google_email:
            raise RuntimeError(
                "Google did not return an email address."
            )

        google_name = (
            userinfo.get("name")
            or userinfo.get("given_name")
            or "Google User"
        ).strip() or "Google User"

    except requests.RequestException:
        current_app.logger.exception(
            "Google HTTP request failed."
        )

        if mode == "register":
            session.pop("pending_registration", None)

        template = (
            "auth/register.html"
            if mode == "register"
            else "auth/login.html"
        )

        return render_template(
            template,
            error="Google authentication could not be completed. Please try again.",
            email=""
        ), 502

    except Exception:
        current_app.logger.exception(
            "Google profile validation failed."
        )

        if mode == "register":
            session.pop("pending_registration", None)

        template = (
            "auth/register.html"
            if mode == "register"
            else "auth/login.html"
        )

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
                        "role": pending["role"]
                    }
                )

            cursor.execute("""
                INSERT INTO users (full_name, email, mobile, password, role)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id
            """, (
                pending["full_name"],
                google_email,
                None,
                pending["password_hash"],
                pending["role"]
            ))

            row = cursor.fetchone()
            user_id = row["id"]

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

        current_app.logger.exception(
            "Google account creation conflict."
        )

        template = (
            "auth/register.html"
            if mode == "register"
            else "auth/login.html"
        )

        return render_template(
            template,
            error="An account with these details already exists. Please try again.",
            email=google_email
        ), 409

    except Exception:
        db.rollback()

        current_app.logger.exception(
            "Google authentication database operation failed."
        )

        template = (
            "auth/register.html"
            if mode == "register"
            else "auth/login.html"
        )

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
    session.clear()
    session.permanent = True
    session["user_id"] = user["id"]
    session["full_name"] = user["full_name"]
    session["email"] = user["email"]
    session["role"] = user["role"]


def redirect_after_login(user):
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
    if (
        "user_id" not in session
        or session.get("role") != "seller"
    ):
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
        current_app.logger.exception(
            "Unable to verify seller account access."
        )

        abort(
            503,
            description="Seller access could not be verified. Please try again later."
        )

    finally:
        if cursor:
            cursor.close()


@app.route("/seller/pending-approval")
def seller_pending_approval():
    if (
        "user_id" not in session
        or session.get("role") != "seller"
    ):
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

        if (
            approval["status"] == "approved"
            and approval["account_status"] == "active"
        ):
            return redirect(url_for("seller_dashboard"))

        return render_template(
            "seller/pending.html",
            approval=approval
        )

    except Exception:
        current_app.logger.exception(
            "Unable to load seller approval status."
        )

        return "Unable to load seller approval status.", 500

    finally:
        if cursor:
            cursor.close()


# =========================================================
# ADMIN ACCESS CHECK
# =========================================================

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
                id SERIAL PRIMARY KEY,
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
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                CONSTRAINT uq_mentor_profile_user UNIQUE (user_id),
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
                id SERIAL PRIMARY KEY,
                mentor_id INT NOT NULL,
                entrepreneur_id INT NOT NULL,
                subject VARCHAR(255) NOT NULL,
                message TEXT NULL,
                status VARCHAR(30) NOT NULL DEFAULT 'pending',
                mentor_response TEXT NULL,
                scheduled_at TIMESTAMP NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
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
                id SERIAL PRIMARY KEY,
                request_id INT NOT NULL,
                mentor_id INT NOT NULL,
                entrepreneur_id INT NOT NULL,
                scheduled_at TIMESTAMP NULL,
                duration_minutes INT NOT NULL DEFAULT 60,
                notes TEXT NULL,
                status VARCHAR(30) NOT NULL DEFAULT 'scheduled',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
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
                id SERIAL PRIMARY KEY,
                session_id INT NOT NULL,
                mentor_id INT NOT NULL,
                entrepreneur_id INT NOT NULL,
                rating SMALLINT NOT NULL,
                feedback_text TEXT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
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

    except Exception:
        db.rollback()
        raise

    finally:
        if cursor:
            cursor.close()


# =========================================================
# BUYER DASHBOARD
# =========================================================

@app.route("/buyer/dashboard")
def buyer_dashboard():
    if not buyer_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        search = request.args.get("search", "").strip()
        category = request.args.get("category", "").strip()

        query = """
            SELECT
                products.id,
                products.name,
                products.description,
                products.price,
                products.stock,
                products.image_url,
                categories.name AS category_name,
                users.full_name AS seller_name
            FROM products
            INNER JOIN categories
                ON products.category_id = categories.id
            INNER JOIN users
                ON products.seller_id = users.id
            WHERE products.status = 'active'
            AND products.stock > 0
        """

        params = []

        if search:
            query += """
                AND (
                    products.name ILIKE %s
                    OR products.description ILIKE %s
                )
            """

            value = "%" + search + "%"
            params.extend([value, value])

        if category:
            query += """
                AND categories.name = %s
            """

            params.append(category)

        query += """
            ORDER BY products.created_at DESC
        """

        cursor.execute(query, tuple(params))
        products = cursor.fetchall()

        return render_template(
            "buyer/dashboard.html",
            products=products
        )

    except Exception as e:
        return _internal_error_response(
            e,
            "Unable to load buyer dashboard."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# BUYER MARKETPLACE
# =========================================================

@app.route("/buyer/products")
def buyer_products():
    if not buyer_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        search = request.args.get("search", "").strip()
        category = request.args.get("category", "").strip()

        query = """
            SELECT
                products.id,
                products.name,
                products.description,
                products.price,
                products.stock,
                products.image_url,
                categories.name AS category_name,
                users.full_name AS seller_name
            FROM products
            INNER JOIN categories
                ON products.category_id = categories.id
            INNER JOIN users
                ON products.seller_id = users.id
            WHERE products.status = 'active'
            AND products.stock > 0
        """

        params = []

        if search:
            query += """
                AND (
                    products.name ILIKE %s
                    OR products.description ILIKE %s
                )
            """

            value = "%" + search + "%"
            params.extend([value, value])

        if category:
            query += """
                AND categories.name = %s
            """

            params.append(category)

        query += """
            ORDER BY products.created_at DESC
        """

        cursor.execute(query, tuple(params))
        products = cursor.fetchall()

        cursor.execute("""
            SELECT id, name
            FROM categories
            ORDER BY name
        """)

        categories = cursor.fetchall()

        return render_template(
            "buyer/products.html",
            products=products,
            categories=categories,
            search=search,
            selected_category=category
        )

    except Exception as e:
        return _internal_error_response(
            e,
            "Unable to load the product marketplace."
        )

    finally:
        if cursor:
            cursor.close()



# =========================================================
# BUYER PRODUCT DETAILS
# =========================================================

@app.route("/buyer/product/<int:product_id>")
def buyer_product_details(product_id):
    if not buyer_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                products.id,
                products.name,
                products.description,
                products.price,
                products.stock,
                products.image_url,
                categories.name AS category_name,
                users.full_name AS seller_name
            FROM products
            INNER JOIN categories
                ON products.category_id = categories.id
            INNER JOIN users
                ON products.seller_id = users.id
            WHERE products.id = %s
            AND products.status = 'active'
        """, (product_id,))

        product = cursor.fetchone()

        if not product:
            return "Product not found.", 404

        return render_template(
            "buyer/product_details.html",
            product=product
        )

    except Exception as e:
        return _internal_error_response(
            e,
            "Unable to load product details."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# BUYER CART
# =========================================================

@app.route("/buyer/cart")
def buyer_cart():
    if not buyer_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        buyer_id = session["user_id"]

        cursor.execute("""
            SELECT id
            FROM cart
            WHERE buyer_id = %s
        """, (buyer_id,))

        cart = cursor.fetchone()

        items = []
        total = 0

        if cart:
            cursor.execute("""
                SELECT
                    cart_items.id AS cart_item_id,
                    cart_items.quantity,
                    products.id AS product_id,
                    products.name,
                    products.price,
                    products.stock,
                    products.image_url,
                    (cart_items.quantity * products.price) AS subtotal
                FROM cart_items
                INNER JOIN products
                    ON cart_items.product_id = products.id
                WHERE cart_items.cart_id = %s
                ORDER BY cart_items.id DESC
            """, (cart["id"],))

            items = cursor.fetchall()

            total = sum(
                float(item["subtotal"] or 0)
                for item in items
            )

        return render_template(
            "buyer/cart.html",
            items=items,
            total=total
        )

    except Exception as e:
        return _internal_error_response(
            e,
            "Unable to load the buyer cart."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# BUYER ADD TO CART
# =========================================================

@app.route("/buyer/cart/add/<int:product_id>", methods=["POST"])
def add_to_cart(product_id):
    if not buyer_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        buyer_id = session["user_id"]

        cursor.execute("""
            SELECT id, stock, status
            FROM products
            WHERE id = %s
        """, (product_id,))

        product = cursor.fetchone()

        if not product:
            return "Product not found.", 404

        if product["status"] != "active" or product["stock"] <= 0:
            return "This product is currently unavailable.", 409

        cursor.execute("""
            SELECT id
            FROM cart
            WHERE buyer_id = %s
        """, (buyer_id,))

        cart = cursor.fetchone()

        if not cart:
            cursor.execute("""
                INSERT INTO cart (buyer_id)
                VALUES (%s)
                RETURNING id
            """, (buyer_id,))

            row = cursor.fetchone()
            cart_id = row["id"]
        else:
            cart_id = cart["id"]

        cursor.execute("""
            SELECT id, quantity
            FROM cart_items
            WHERE cart_id = %s AND product_id = %s
        """, (cart_id, product_id))

        existing = cursor.fetchone()

        if existing:
            new_quantity = existing["quantity"] + 1

            if new_quantity > product["stock"]:
                return "You cannot add more than the available stock.", 409

            cursor.execute("""
                UPDATE cart_items
                SET quantity = %s
                WHERE id = %s
            """, (new_quantity, existing["id"]))

        else:
            cursor.execute("""
                INSERT INTO cart_items (cart_id, product_id, quantity)
                VALUES (%s, %s, 1)
            """, (cart_id, product_id))

        db.commit()

        return redirect(url_for("buyer_cart"))

    except Exception as e:
        db.rollback()

        return _internal_error_response(
            e,
            "Unable to add the product to the cart."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# BUYER UPDATE CART
# =========================================================

@app.route("/buyer/cart/update/<int:cart_item_id>", methods=["POST"])
def update_cart(cart_item_id):
    if not buyer_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        try:
            quantity = int(request.form.get("quantity", 1))
        except (ValueError, TypeError):
            return "Quantity must be a valid number.", 400

        if quantity < 1:
            return "Quantity must be at least 1.", 400

        cursor.execute("""
            SELECT cart_items.id, products.stock
            FROM cart_items
            INNER JOIN cart
                ON cart_items.cart_id = cart.id
            INNER JOIN products
                ON cart_items.product_id = products.id
            WHERE cart_items.id = %s
            AND cart.buyer_id = %s
        """, (cart_item_id, session["user_id"]))

        item = cursor.fetchone()

        if not item:
            return "Cart item not found.", 404

        if quantity > item["stock"]:
            return "Quantity cannot be greater than available stock.", 409

        cursor.execute("""
            UPDATE cart_items
            SET quantity = %s
            WHERE id = %s
        """, (quantity, cart_item_id))

        db.commit()

        return redirect(url_for("buyer_cart"))

    except Exception as e:
        db.rollback()

        return _internal_error_response(
            e,
            "Unable to update the buyer cart."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# BUYER REMOVE FROM CART
# =========================================================

@app.route("/buyer/cart/remove/<int:cart_item_id>", methods=["POST"])
def remove_from_cart(cart_item_id):
    if not buyer_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor()

        cursor.execute("""
            DELETE FROM cart_items
            USING cart
            WHERE cart_items.cart_id = cart.id
            AND cart_items.id = %s
            AND cart.buyer_id = %s
        """, (cart_item_id, session["user_id"]))

        db.commit()

        return redirect(url_for("buyer_cart"))

    except Exception as e:
        db.rollback()

        return _internal_error_response(
            e,
            "Unable to remove the cart item."
        )

    finally:
        if cursor:
            cursor.close()

# =========================================================
# BUYER WISHLIST
# =========================================================

@app.route("/buyer/wishlist")
def buyer_wishlist():
    if not buyer_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                wishlist.id AS wishlist_id,
                products.id AS product_id,
                products.name,
                products.description,
                products.price,
                products.stock,
                products.image_url,
                categories.name AS category_name,
                users.full_name AS seller_name
            FROM wishlist
            INNER JOIN products
                ON wishlist.product_id = products.id
            INNER JOIN categories
                ON products.category_id = categories.id
            INNER JOIN users
                ON products.seller_id = users.id
            WHERE wishlist.buyer_id = %s
            ORDER BY wishlist.id DESC
        """, (session["user_id"],))

        products = cursor.fetchall()

        return render_template(
            "buyer/wishlist.html",
            products=products
        )

    except Exception as e:
        return _internal_error_response(
            e,
            "Unable to load the buyer wishlist."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# BUYER ADD TO WISHLIST
# =========================================================

@app.route("/buyer/wishlist/add/<int:product_id>", methods=["POST"])
def add_to_wishlist(product_id):
    if not buyer_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor()

        cursor.execute("""
            INSERT INTO wishlist (buyer_id, product_id)
            VALUES (%s, %s)
            ON CONFLICT (buyer_id, product_id) DO NOTHING
        """, (session["user_id"], product_id))

        db.commit()

        return redirect(url_for("buyer_wishlist"))

    except Exception as e:
        db.rollback()

        return _internal_error_response(
            e,
            "Unable to add the wishlist item."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# BUYER REMOVE FROM WISHLIST
# =========================================================

@app.route("/buyer/wishlist/remove/<int:wishlist_id>", methods=["POST"])
def remove_from_wishlist(wishlist_id):
    if not buyer_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor()

        cursor.execute("""
            DELETE FROM wishlist
            WHERE id = %s AND buyer_id = %s
        """, (wishlist_id, session["user_id"]))

        db.commit()

        return redirect(url_for("buyer_wishlist"))

    except Exception as e:
        db.rollback()

        return _internal_error_response(
            e,
            "Unable to remove the wishlist item."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# BUYER ORDERS
# =========================================================

@app.route("/buyer/orders")
def buyer_orders():
    if not buyer_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                orders.id,
                orders.total_amount,
                orders.status,
                orders.shipping_address,
                orders.created_at,
                payments.payment_status,
                payments.payment_method
            FROM orders
            LEFT JOIN payments
                ON orders.id = payments.order_id
            WHERE orders.buyer_id = %s
            ORDER BY orders.created_at DESC
        """, (session["user_id"],))

        orders = cursor.fetchall()

        for order in orders:
            cursor.execute("""
                SELECT
                    order_items.quantity,
                    order_items.unit_price,
                    order_items.subtotal,
                    products.name,
                    products.image_url
                FROM order_items
                INNER JOIN products
                    ON order_items.product_id = products.id
                WHERE order_items.order_id = %s
            """, (order["id"],))

            order["items"] = cursor.fetchall()

        return render_template(
            "buyer/orders.html",
            orders=orders
        )

    except Exception as e:
        return _internal_error_response(
            e,
            "Unable to load buyer orders."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# BUYER CHECKOUT
# =========================================================

@app.route("/buyer/checkout", methods=["POST"])
def checkout():
    if not buyer_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        buyer_id = session["user_id"]

        address_line = request.form.get("address_line", "").strip()
        city = request.form.get("city", "").strip()
        state = request.form.get("state", "").strip()
        pincode = request.form.get("pincode", "").strip()

        if not address_line or not city or not state or not pincode:
            return "Please enter complete shipping address.", 400

        if not re.fullmatch(r"\d{6}", pincode):
            return "Pincode must contain exactly 6 digits.", 400

        # Lock the buyer's cart during checkout.
        cursor.execute("""
            SELECT id
            FROM cart
            WHERE buyer_id = %s
            FOR UPDATE
        """, (buyer_id,))

        cart = cursor.fetchone()

        if not cart:
            return "Your cart is empty.", 400

        # Lock the selected product rows while checking stock.
        cursor.execute("""
            SELECT
                cart_items.product_id,
                cart_items.quantity,
                products.name,
                products.price,
                products.stock,
                products.seller_id,
                products.status
            FROM cart_items
            INNER JOIN products
                ON cart_items.product_id = products.id
            WHERE cart_items.cart_id = %s
            FOR UPDATE OF products
        """, (cart["id"],))

        items = cursor.fetchall()

        if not items:
            return "Your cart is empty.", 400

        total = Decimal("0.00")

        for item in items:
            if item["status"] != "active":
                return f"{item['name']} is no longer available.", 409

            if item["quantity"] > item["stock"]:
                return f"Not enough stock for {item['name']}.", 409

            total += Decimal(str(item["price"])) * item["quantity"]

        shipping_address = (
            f"{address_line}, {city}, {state} - {pincode}"
        )

        cursor.execute("""
            INSERT INTO orders (
                buyer_id,
                total_amount,
                status,
                shipping_address
            )
            VALUES (%s, %s, 'pending', %s)
            RETURNING id
        """, (buyer_id, total, shipping_address))

        row = cursor.fetchone()
        order_id = row["id"]

        cursor.execute("""
            INSERT INTO order_status_history (
                order_id,
                status,
                note
            )
            VALUES (
                %s,
                'pending',
                'Order placed with Cash on Delivery'
            )
        """, (order_id,))

        for item in items:
            subtotal = (
                Decimal(str(item["price"])) * item["quantity"]
            )

            cursor.execute("""
                INSERT INTO order_items (
                    order_id,
                    product_id,
                    seller_id,
                    quantity,
                    unit_price,
                    subtotal
                )
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                order_id,
                item["product_id"],
                item["seller_id"],
                item["quantity"],
                item["price"],
                subtotal
            ))

            cursor.execute("""
                UPDATE products
                SET stock = stock - %s
                WHERE id = %s
                AND stock >= %s
            """, (
                item["quantity"],
                item["product_id"],
                item["quantity"]
            ))

            if cursor.rowcount == 0:
                raise Exception(
                    f"Unable to update stock for {item['name']}."
                )

        cursor.execute("""
            INSERT INTO payments (
                order_id,
                payment_method,
                amount,
                payment_status
            )
            VALUES (%s, 'Cash on Delivery', %s, 'pending')
        """, (order_id, total))

        cursor.execute("""
            DELETE FROM cart_items
            WHERE cart_id = %s
        """, (cart["id"],))

        db.commit()

        flash("Order placed successfully.", "success")

        return redirect(url_for("buyer_orders"))

    except Exception as e:
        db.rollback()

        return _internal_error_response(
            e,
            "Cash on Delivery checkout failed."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# BUYER PROFILE
# =========================================================

@app.route("/buyer/profile", methods=["GET", "POST"])
def buyer_profile():
    if not buyer_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        if request.method == "POST":
            full_name = request.form.get("full_name", "").strip()
            mobile = request.form.get("mobile", "").strip()

            if not full_name:
                return "Full name is required.", 400

            if not re.fullmatch(r"\d{10}", mobile):
                return "Mobile number must contain exactly 10 digits.", 400

            cursor.execute("""
                UPDATE users
                SET full_name = %s, mobile = %s
                WHERE id = %s AND role = 'buyer'
            """, (
                full_name,
                mobile,
                session["user_id"]
            ))

            if cursor.rowcount == 0:
                db.rollback()
                return "Buyer profile not found.", 404

            db.commit()

            session["full_name"] = full_name

            return redirect(url_for("buyer_profile"))

        cursor.execute("""
            SELECT id, full_name, email, mobile
            FROM users
            WHERE id = %s AND role = 'buyer'
        """, (session["user_id"],))

        user = cursor.fetchone()

        if not user:
            return "Buyer profile not found.", 404

        cursor.execute("""
            SELECT
                id,
                address_line,
                city,
                state,
                pincode,
                is_default
            FROM buyer_addresses
            WHERE buyer_id = %s
            ORDER BY is_default DESC, id DESC
        """, (session["user_id"],))

        addresses = cursor.fetchall()

        return render_template(
            "buyer/profile.html",
            user=user,
            addresses=addresses
        )

    except Exception as e:
        db.rollback()

        return _internal_error_response(
            e,
            "Unable to load the buyer profile."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# BUYER SAVE ADDRESS
# =========================================================

@app.route("/buyer/address/add", methods=["POST"])
def add_buyer_address():
    if not buyer_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor()

        address_line = request.form.get("address_line", "").strip()
        city = request.form.get("city", "").strip()
        state = request.form.get("state", "").strip()
        pincode = request.form.get("pincode", "").strip()

        if not address_line or not city or not state or not pincode:
            return "Please fill all address fields.", 400

        if not re.fullmatch(r"\d{6}", pincode):
            return "Pincode must contain exactly 6 digits.", 400

        cursor.execute("""
            INSERT INTO buyer_addresses (
                buyer_id,
                address_line,
                city,
                state,
                pincode
            )
            VALUES (%s, %s, %s, %s, %s)
        """, (
            session["user_id"],
            address_line,
            city,
            state,
            pincode
        ))

        db.commit()

        flash("Address saved successfully.", "success")

        return redirect(url_for("buyer_profile"))

    except Exception as e:
        db.rollback()

        return _internal_error_response(
            e,
            "Unable to save the buyer address."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# BUYER CUSTOM PRODUCT REQUEST
# =========================================================

@app.route(
    "/buyer/custom-requests",
    methods=["GET", "POST"],
    endpoint="buyer_custom_requests"
)
@app.route(
    "/buyer/custom-request",
    methods=["GET", "POST"]
)
def buyer_custom_request():
    if not buyer_required():
        return redirect(url_for("login"))

    if request.method == "POST":
        cursor = None

        try:
            ensure_db_connection()
            cursor = db.cursor()

            product_name = request.form.get(
                "product_name", ""
            ).strip()

            description = request.form.get(
                "description", ""
            ).strip()

            budget = request.form.get(
                "budget", ""
            ).strip()

            if not product_name or len(product_name) > 150:
                return (
                    "Product name is required and must be 150 characters or fewer.",
                    400
                )

            if not description or len(description) > 5000:
                return (
                    "Product description is required and must be 5,000 characters or fewer.",
                    400
                )

            budget_value = None

            if budget:
                try:
                    budget_value = Decimal(budget)
                except (InvalidOperation, ValueError):
                    return "Budget must be a valid number.", 400

                if (
                    not budget_value.is_finite()
                    or budget_value < 0
                    or budget_value > Decimal("99999999.99")
                    or budget_value != budget_value.quantize(
                        Decimal("0.01")
                    )
                ):
                    return (
                        "Budget must be between 0 and 99,999,999.99 "
                        "with at most two decimal places.",
                        400
                    )

            cursor.execute("""
                INSERT INTO custom_requests (
                    buyer_id,
                    product_name,
                    description,
                    budget,
                    status
                )
                VALUES (%s, %s, %s, %s, 'pending')
            """, (
                session["user_id"],
                product_name,
                description,
                budget_value
            ))

            db.commit()

            flash(
                "Custom request submitted successfully.",
                "success"
            )

            return redirect(url_for("buyer_custom_requests"))

        except Exception as e:
            db.rollback()

            return _internal_error_response(
                e,
                "Unable to submit the buyer custom request."
            )

        finally:
            if cursor:
                cursor.close()

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                id,
                product_name,
                description,
                budget,
                status,
                quotation_amount,
                seller_response,
                created_at
            FROM custom_requests
            WHERE buyer_id = %s
            ORDER BY created_at DESC, id DESC
        """, (session["user_id"],))

        requests_list = cursor.fetchall()

        return render_template(
            "buyer/custom_requests.html",
            requests=requests_list
        )

    except Exception as e:
        return _internal_error_response(
            e,
            "Unable to load buyer custom requests."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# BUYER ORDER HELPER
# =========================================================

def _buyer_order(cursor, order_id, buyer_id):
    cursor.execute("""
        SELECT
            o.id,
            o.total_amount,
            o.status,
            o.shipping_address,
            o.created_at,
            p.payment_method,
            p.payment_status
        FROM orders o
        LEFT JOIN payments p
            ON p.order_id = o.id
        WHERE o.id = %s
        AND o.buyer_id = %s
        ORDER BY p.id DESC
        LIMIT 1
    """, (order_id, buyer_id))

    return cursor.fetchone()


# =========================================================
# BUYER REVIEWS
# =========================================================

@app.route("/buyer/reviews")
def buyer_reviews():
    if not buyer_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        buyer_id = session["user_id"]

        cursor.execute("""
            SELECT
                oi.product_id,
                oi.order_id,
                p.name,
                p.image_url,
                o.created_at
            FROM order_items oi
            INNER JOIN orders o
                ON o.id = oi.order_id
            INNER JOIN products p
                ON p.id = oi.product_id
            LEFT JOIN reviews r
                ON r.buyer_id = o.buyer_id
                AND r.product_id = oi.product_id
                AND r.order_id = oi.order_id
            WHERE o.buyer_id = %s
            AND o.status IN ('delivered', 'completed')
            AND r.id IS NULL
            ORDER BY o.created_at DESC
        """, (buyer_id,))

        reviewable = cursor.fetchall()

        cursor.execute("""
            SELECT
                r.id,
                r.product_id,
                r.order_id,
                r.rating,
                r.review_text,
                r.created_at,
                p.name AS product_name
            FROM reviews r
            INNER JOIN products p
                ON p.id = r.product_id
            WHERE r.buyer_id = %s
            ORDER BY r.created_at DESC
        """, (buyer_id,))

        reviews = cursor.fetchall()

        return render_template(
            "buyer/reviews.html",
            reviewable=reviewable,
            reviews=reviews
        )

    except Exception as e:
        return _internal_error_response(
            e,
            "Unable to load buyer reviews."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# BUYER SUBMIT REVIEW
# =========================================================

@app.route("/buyer/review/add", methods=["POST"])
def submit_review():
    if not buyer_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        buyer_id = session["user_id"]

        purchase_key = request.form.get("purchase", "")
        purchase_parts = purchase_key.split(":", 1)

        if (
            len(purchase_parts) != 2
            or not all(part.isdecimal() for part in purchase_parts)
        ):
            return "Select a product purchase to review.", 400

        order_id, product_id = map(int, purchase_parts)

        rating = request.form.get("rating", type=int)
        review_text = request.form.get(
            "review_text", ""
        ).strip()

        if not product_id or not order_id:
            return "Product and order are required.", 400

        if rating is None or rating < 1 or rating > 5:
            return "Rating must be between 1 and 5.", 400

        if not review_text:
            return "Review text is required.", 400

        cursor.execute("""
            SELECT
                oi.product_id,
                o.id AS order_id
            FROM order_items oi
            INNER JOIN orders o
                ON o.id = oi.order_id
            WHERE o.id = %s
            AND o.buyer_id = %s
            AND oi.product_id = %s
            AND o.status IN ('delivered', 'completed')
            LIMIT 1
        """, (order_id, buyer_id, product_id))

        purchase = cursor.fetchone()

        if not purchase:
            return (
                "You can review only a product you purchased and received.",
                403
            )

        cursor.execute("""
            SELECT id
            FROM reviews
            WHERE buyer_id = %s
            AND product_id = %s
            AND order_id = %s
            LIMIT 1
        """, (buyer_id, product_id, order_id))

        if cursor.fetchone():
            return "You have already reviewed this purchase.", 409

        cursor.execute("""
            INSERT INTO reviews (
                buyer_id,
                product_id,
                order_id,
                rating,
                review_text
            )
            VALUES (%s, %s, %s, %s, %s)
        """, (
            buyer_id,
            product_id,
            order_id,
            rating,
            review_text
        ))

        db.commit()

        flash("Review submitted successfully.", "success")

        return redirect(url_for("buyer_reviews"))

    except Exception as e:
        db.rollback()

        return _internal_error_response(
            e,
            "Unable to submit the buyer review."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# BUYER ORDER DETAILS
# =========================================================

@app.route("/buyer/order/<int:order_id>")
def buyer_order_details(order_id):
    if not buyer_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        buyer_id = session["user_id"]

        order = _buyer_order(cursor, order_id, buyer_id)

        if not order:
            return "Order not found.", 404

        cursor.execute("""
            SELECT
                oi.product_id,
                oi.quantity,
                oi.unit_price,
                oi.subtotal,
                p.name,
                p.image_url
            FROM order_items oi
            INNER JOIN products p
                ON p.id = oi.product_id
            WHERE oi.order_id = %s
            ORDER BY oi.id
        """, (order_id,))

        order["items"] = cursor.fetchall()

        cursor.execute("""
            SELECT
                status,
                note,
                created_at
            FROM order_status_history
            WHERE order_id = %s
            ORDER BY created_at ASC, id ASC
        """, (order_id,))

        tracking = cursor.fetchall()

        if not tracking:
            tracking = [{
                "status": order["status"],
                "note": "Current order status",
                "created_at": order["created_at"]
            }]

        cursor.execute("""
            SELECT
                id,
                reason,
                status,
                seller_response,
                created_at,
                updated_at
            FROM return_requests
            WHERE order_id = %s
            AND buyer_id = %s
            ORDER BY id DESC
            LIMIT 1
        """, (order_id, buyer_id))

        return_request = cursor.fetchone()

        return render_template(
            "buyer/order_details.html",
            order=order,
            tracking=tracking,
            return_request=return_request
        )

    except Exception as e:
        return _internal_error_response(
            e,
            "Unable to load buyer order details."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# BUYER CANCEL ORDER
# =========================================================

@app.route(
    "/buyer/order/<int:order_id>/cancel",
    methods=["POST"]
)
def cancel_order(order_id):
    if not buyer_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        buyer_id = session["user_id"]

        # Lock the order row to prevent simultaneous cancellation.
        cursor.execute("""
            SELECT id, status
            FROM orders
            WHERE id = %s
            AND buyer_id = %s
            FOR UPDATE
        """, (order_id, buyer_id))

        locked_order = cursor.fetchone()

        if not locked_order:
            return "Order not found.", 404

        status = str(
            locked_order["status"] or ""
        ).lower()

        if status not in {"pending", "processing"}:
            return (
                "This order cannot be cancelled after shipment "
                "or completion.",
                409
            )

        cursor.execute("""
            SELECT product_id, quantity
            FROM order_items
            WHERE order_id = %s
        """, (order_id,))

        items = cursor.fetchall()

        cursor.execute("""
            UPDATE orders
            SET status = 'cancelled'
            WHERE id = %s
            AND buyer_id = %s
            AND status IN ('pending', 'processing')
        """, (order_id, buyer_id))

        if cursor.rowcount != 1:
            return "Unable to cancel this order.", 409

        for item in items:
            cursor.execute("""
                UPDATE products
                SET stock = stock + %s
                WHERE id = %s
            """, (
                item["quantity"],
                item["product_id"]
            ))

        cursor.execute("""
            INSERT INTO order_status_history (
                order_id,
                status,
                note
            )
            VALUES (
                %s,
                'cancelled',
                'Cancelled by buyer'
            )
        """, (order_id,))

        cursor.execute("""
            UPDATE payments
            SET payment_status = CASE
                WHEN payment_status = 'paid'
                    THEN 'refund_pending'
                ELSE 'cancelled'
            END
            WHERE order_id = %s
        """, (order_id,))

        db.commit()

        flash("Order cancelled successfully.", "success")

        return redirect(
            url_for(
                "buyer_order_details",
                order_id=order_id
            )
        )

    except Exception as e:
        db.rollback()

        return _internal_error_response(
            e,
            "Unable to cancel the buyer order."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# BUYER REQUEST RETURN
# =========================================================

@app.route(
    "/buyer/order/<int:order_id>/return",
    methods=["POST"]
)
def request_return(order_id):
    if not buyer_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        buyer_id = session["user_id"]

        reason = request.form.get("reason", "").strip()

        if not reason or len(reason) > 2000:
            return (
                "A return reason of 1 to 2,000 characters is required.",
                400
            )

        # Lock the order before checking its status.
        cursor.execute("""
            SELECT id, status
            FROM orders
            WHERE id = %s
            AND buyer_id = %s
            FOR UPDATE
        """, (order_id, buyer_id))

        order = cursor.fetchone()

        if not order:
            return "Order not found.", 404

        if str(order["status"] or "").lower() not in {
            "delivered",
            "completed"
        }:
            return (
                "A return can be requested only for a delivered order.",
                409
            )

        cursor.execute("""
            SELECT id
            FROM return_requests
            WHERE order_id = %s
            AND buyer_id = %s
            AND status NOT IN ('rejected', 'cancelled')
            LIMIT 1
        """, (order_id, buyer_id))

        if cursor.fetchone():
            return (
                "A return request already exists for this order.",
                409
            )

        cursor.execute("""
            INSERT INTO return_requests (
                order_id,
                buyer_id,
                reason,
                status
            )
            VALUES (%s, %s, %s, 'requested')
        """, (order_id, buyer_id, reason))

        cursor.execute("""
            INSERT INTO order_status_history (
                order_id,
                status,
                note
            )
            VALUES (
                %s,
                'return_requested',
                'Return requested by buyer'
            )
        """, (order_id,))

        db.commit()

        flash("Return request submitted successfully.", "success")

        return redirect(
            url_for(
                "buyer_order_details",
                order_id=order_id
            )
        )

    except Exception as e:
        db.rollback()

        return _internal_error_response(
            e,
            "Unable to create the return request."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# BUYER PAYMENT DETAILS
# =========================================================

@app.route("/buyer/payment/<int:order_id>")
def buyer_payment(order_id):
    if not buyer_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        order = _buyer_order(
            cursor,
            order_id,
            session["user_id"]
        )

        if not order:
            return "Order not found.", 404

        return render_template(
            "buyer/payment.html",
            order=order
        )

    except Exception:
        current_app.logger.exception(
            "Unable to load the COD payment details."
        )

        return "Unable to load payment details.", 500

    finally:
        if cursor:
            cursor.close()


# =========================================================
# BUYER AI SUPPORT PAGE
# =========================================================

@app.route("/buyer/ai-support")
def buyer_ai_support():
    if not buyer_required():
        return redirect(url_for("login"))

    return render_template("buyer/ai_support.html")


# =========================================================
# LOCAL OLLAMA CONFIGURATION
# =========================================================

OLLAMA_BASE_URL = os.getenv(
    "OLLAMA_BASE_URL",
    "http://127.0.0.1:11434"
).strip().rstrip("/")

OLLAMA_MODEL = os.getenv(
    "OLLAMA_MODEL",
    "llama3.2:3b"
).strip()


# =========================================================
# OFFLINE SUPPORT ANSWER
# =========================================================

def offline_support_answer(message):
    text = message.lower()

    if any(word in text for word in (
        "track", "tracking", "where is", "order status"
    )):
        return (
            "Open Orders from your buyer dashboard, then select "
            "the order to view its latest status and tracking history."
        )

    if any(word in text for word in ("return", "refund")):
        return (
            "Open the delivered order details and submit a return "
            "request with a reason. A platform administrator must "
            "review it; refunds are not processed automatically."
        )

    if any(word in text for word in (
        "payment", "pay", "cash", "cod"
    )):
        return (
            "Checkout currently supports Cash on Delivery only. "
            "Payment is due when the order is delivered."
        )

    if any(word in text for word in (
        "custom", "request", "quotation"
    )):
        return (
            "Use Custom Request from your buyer dashboard to submit "
            "a product request. You can review seller responses "
            "in Custom Requests."
        )

    if any(word in text for word in ("review", "rating")):
        return (
            "You can review a product after its order has been marked "
            "delivered. Open Reviews from your buyer dashboard."
        )

    if any(word in text for word in (
        "cart", "wishlist", "product", "browse"
    )):
        return (
            "Browse Products to find items, add them to your cart "
            "or wishlist, and check out when you are ready."
        )

    return (
        "I can help with orders, returns, Cash on Delivery, reviews, "
        "products, and custom requests. Try asking about one of "
        "those topics, or use the related dashboard page."
    )


# =========================================================
# LOCAL AI ANSWER
# =========================================================

def local_ai_answer(
    message,
    system_prompt,
    fallback_answer=offline_support_answer
):
    fallback = (
        fallback_answer(message)
        if fallback_answer
        else None
    )

    parsed_url = urlsplit(OLLAMA_BASE_URL)

    if (
        parsed_url.scheme not in {"http", "https"}
        or parsed_url.hostname not in {
            "localhost",
            "127.0.0.1",
            "::1"
        }
    ):
        current_app.logger.error(
            "OLLAMA_BASE_URL must point to a local loopback address."
        )

        return (
            fallback,
            "faq_fallback" if fallback is not None else "unavailable"
        )

    try:
        response = requests.post(
            f"{OLLAMA_BASE_URL}/api/chat",
            json={
                "model": OLLAMA_MODEL,
                "stream": False,
                "messages": [
                    {
                        "role": "system",
                        "content": system_prompt
                    },
                    {
                        "role": "user",
                        "content": message
                    }
                ],
                "options": {
                    "num_predict": 400
                }
            },
            timeout=20
        )

        response.raise_for_status()
        result = response.json()

    except (requests.RequestException, ValueError) as e:
        current_app.logger.info(
            "Local Ollama request failed: %s",
            e
        )

        return (
            fallback,
            "faq_fallback" if fallback is not None else "unavailable"
        )

    message_result = (
        result.get("message")
        if isinstance(result, dict)
        else None
    )

    answer = (
        message_result.get("content", "").strip()
        if isinstance(message_result, dict)
        and isinstance(message_result.get("content"), str)
        else ""
    )

    if not answer:
        current_app.logger.warning(
            "Local Ollama returned an empty response."
        )

        return (
            fallback,
            "faq_fallback" if fallback is not None else "unavailable"
        )

    return answer, "success"


# =========================================================
# GEMINI CONFIGURATION
# =========================================================

GEMINI_API_KEY = os.getenv(
    "GEMINI_API_KEY",
    ""
).strip()

GEMINI_MODEL = (
    os.getenv(
        "GEMINI_MODEL",
        "gemini-2.5-flash"
    ).strip()
    or "gemini-2.5-flash"
)


# =========================================================
# GEMINI AI ANSWER
# =========================================================

def gemini_ai_answer(
    message,
    system_prompt,
    temperature=0.5,
    max_output_tokens=1600
):
    if not GEMINI_API_KEY:
        current_app.logger.error(
            "Gemini API key is not configured."
        )

        return None, "not_configured"

    if not isinstance(message, str) or not message.strip():
        return None, "unavailable"

    if (
        not isinstance(system_prompt, str)
        or not system_prompt.strip()
    ):
        return None, "unavailable"

    endpoint = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"{GEMINI_MODEL}:generateContent"
    )

    payload = {
        "systemInstruction": {
            "parts": [
                {
                    "text": system_prompt.strip()
                }
            ]
        },
        "contents": [
            {
                "role": "user",
                "parts": [
                    {
                        "text": message.strip()
                    }
                ]
            }
        ],
        "generationConfig": {
            "temperature": temperature,
            "maxOutputTokens": max_output_tokens
        }
    }

    try:
        response = requests.post(
            endpoint,
            params={"key": GEMINI_API_KEY},
            json=payload,
            timeout=60
        )

        if response.status_code == 429:
            current_app.logger.warning(
                "Gemini quota or rate limit reached."
            )

            return None, "quota_exceeded"

        if response.status_code in (401, 403):
            current_app.logger.error(
                "Gemini rejected API credentials. HTTP %s",
                response.status_code
            )

            return None, "invalid_key"

        if not response.ok:
            current_app.logger.error(
                "Gemini API returned HTTP %s: %s",
                response.status_code,
                response.text[:1000]
            )

            return None, "unavailable"

        result = response.json()

    except requests.Timeout:
        current_app.logger.warning(
            "Gemini API request timed out."
        )

        return None, "timeout"

    except requests.RequestException:
        current_app.logger.exception(
            "Gemini API request failed."
        )

        return None, "unavailable"

    except ValueError:
        current_app.logger.warning(
            "Gemini returned invalid JSON."
        )

        return None, "unavailable"

    if not isinstance(result, dict):
        return None, "unavailable"

    prompt_feedback = result.get("promptFeedback", {})

    if (
        isinstance(prompt_feedback, dict)
        and prompt_feedback.get("blockReason")
    ):
        current_app.logger.warning(
            "Gemini blocked the prompt: %s",
            prompt_feedback.get("blockReason")
        )

        return None, "blocked"

    candidates = result.get("candidates", [])

    if not candidates or not isinstance(candidates[0], dict):
        current_app.logger.warning(
            "Gemini returned no response candidates."
        )

        return None, "unavailable"

    candidate = candidates[0]
    content = candidate.get("content", {})

    parts = (
        content.get("parts", [])
        if isinstance(content, dict)
        else []
    )

    answer = "\n".join(
        part["text"].strip()
        for part in parts
        if isinstance(part, dict)
        and isinstance(part.get("text"), str)
        and part["text"].strip()
    ).strip()

    if not answer:
        return None, "unavailable"

    return answer, "success"


# =========================================================
# GEMINI ERROR MESSAGE
# =========================================================

def gemini_error_message(status):
    messages = {
        "not_configured": (
            "Gemini is not configured yet. Add GEMINI_API_KEY "
            "to your .env file and restart Flask."
        ),
        "quota_exceeded": (
            "Gemini's free-tier quota or rate limit has been "
            "reached. Wait and try again."
        ),
        "invalid_key": (
            "Gemini rejected the API key. Check GEMINI_API_KEY "
            "in your .env file."
        ),
        "timeout": (
            "Gemini took too long to respond. Please try again."
        ),
        "blocked": (
            "Gemini could not answer that request. "
            "Please rephrase and try again."
        ),
        "unavailable": (
            "Gemini is temporarily unavailable. "
            "Please try again in a moment."
        )
    }

    return messages.get(status, messages["unavailable"])


# =========================================================
# BUYER AI SUPPORT CHAT
# =========================================================

@app.route(
    "/buyer/ai-support/chat",
    methods=["POST"]
)
def buyer_ai_support_chat():
    if not buyer_required():
        return {"error": "Login required."}, 401

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return {"error": "A JSON object is required."}, 400

    message = str(data.get("message", "")).strip()

    if not message:
        return {"error": "Message is required."}, 400

    if len(message) > 2000:
        return {
            "error": "Message must be 2,000 characters or fewer."
        }, 400

    cursor = None
    started = datetime.now()

    try:
        ensure_db_connection()
        cursor = db.cursor()

        buyer_id = session["user_id"]

        cursor.execute("""
            INSERT INTO ai_support_messages (
                buyer_id,
                sender_type,
                message
            )
            VALUES (%s, 'buyer', %s)
        """, (buyer_id, message))

        # Save the buyer message before calling the AI service.
        db.commit()

        answer, response_status = local_ai_answer(
            message,
            (
                "You are the SheRise buyer support assistant. "
                "Help with products, orders, payments, returns, "
                "reviews and custom product requests."
            )
        )

        if not answer:
            answer = offline_support_answer(message)
            response_status = "faq_fallback"

        response_time_ms = max(
            0,
            int(
                (datetime.now() - started).total_seconds() * 1000
            )
        )

        cursor.execute("""
            INSERT INTO ai_support_messages (
                buyer_id,
                sender_type,
                message
            )
            VALUES (%s, 'assistant', %s)
        """, (buyer_id, answer))

        cursor.execute("""
            INSERT INTO ai_usage_logs (
                user_id,
                user_role,
                feature,
                request_text,
                response_status,
                response_time_ms,
                response_text
            )
            VALUES (
                %s,
                'buyer',
                'buyer_support',
                %s,
                %s,
                %s,
                %s
            )
        """, (
            buyer_id,
            message,
            response_status,
            response_time_ms,
            answer
        ))

        db.commit()

        return {
            "response": answer,
            "mode": (
                "local"
                if response_status == "success"
                else "offline_faq"
            )
        }

    except Exception:
        db.rollback()

        current_app.logger.exception(
            "Buyer AI support request failed."
        )

        return {
            "error": "AI support could not complete the request."
        }, 500

    finally:
        if cursor:
            cursor.close()


# =========================================================
# BUYER COMPLAINTS
# =========================================================

@app.route(
    "/buyer/complaints",
    methods=["GET", "POST"]
)
def buyer_complaints():
    if not buyer_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        buyer_id = session["user_id"]
        message = None

        if request.method == "POST":
            title = request.form.get(
                "title", ""
            ).strip()

            description = request.form.get(
                "description", ""
            ).strip()

            complaint_type = request.form.get(
                "complaint_type",
                "general"
            ).strip().lower()

            order_id = request.form.get(
                "order_id",
                type=int
            )

            if not title or len(title) > 255:
                return (
                    "Title is required and must be 255 characters or fewer.",
                    400
                )

            if not description or len(description) > 10000:
                return (
                    "Description is required and must be 10,000 characters or fewer.",
                    400
                )

            if complaint_type not in {
                "order",
                "product",
                "payment",
                "delivery",
                "account",
                "general"
            }:
                return "Select a valid complaint type.", 400

            if order_id is not None:
                cursor.execute("""
                    SELECT id
                    FROM orders
                    WHERE id = %s
                    AND buyer_id = %s
                """, (order_id, buyer_id))

                if not cursor.fetchone():
                    return (
                        "The selected order does not belong to your account.",
                        400
                    )

            cursor.execute("""
                INSERT INTO complaints (
                    user_id,
                    order_id,
                    title,
                    description,
                    complaint_type,
                    priority,
                    status
                )
                VALUES (
                    %s, %s, %s, %s, %s, 'medium', 'open'
                )
            """, (
                buyer_id,
                order_id,
                title,
                description,
                complaint_type
            ))

            db.commit()

            message = "Your complaint has been submitted."

            flash(message, "success")

        cursor.execute("""
            SELECT
                id,
                order_id,
                title,
                description,
                complaint_type,
                status,
                admin_response,
                created_at,
                updated_at
            FROM complaints
            WHERE user_id = %s
            ORDER BY created_at DESC, id DESC
        """, (buyer_id,))

        complaints = cursor.fetchall()

        cursor.execute("""
            SELECT
                id,
                created_at
            FROM orders
            WHERE buyer_id = %s
            ORDER BY created_at DESC
        """, (buyer_id,))

        orders = cursor.fetchall()

        return render_template(
            "buyer/complaints.html",
            complaints=complaints,
            orders=orders,
            message=message
        )

    except Exception:
        db.rollback()

        current_app.logger.exception(
            "Unable to load or submit buyer complaint."
        )

        return "Unable to load or submit your complaint.", 500

    finally:
        if cursor:
            cursor.close()


# =========================================================
# MENTOR PORTAL
# =========================================================

@app.route("/mentor")
@app.route("/mentor/dashboard")
def mentor_dashboard():
    if not mentor_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_mentor_tables()
        cursor = db.cursor(dictionary=True)

        mentor_id = session["user_id"]

        cursor.execute("""
            SELECT
                mp.*,
                u.full_name,
                u.email,
                u.mobile
            FROM mentor_profiles mp
            INNER JOIN users u
                ON u.id = mp.user_id
            WHERE mp.user_id = %s
            LIMIT 1
        """, (mentor_id,))

        mentor = cursor.fetchone()

        if not mentor:
            cursor.execute("""
                INSERT INTO mentor_profiles (user_id, status)
                VALUES (%s, 'pending')
                ON CONFLICT (user_id) DO NOTHING
            """, (mentor_id,))

            db.commit()

            cursor.execute("""
                SELECT
                    mp.*,
                    u.full_name,
                    u.email,
                    u.mobile
                FROM mentor_profiles mp
                INNER JOIN users u
                    ON u.id = mp.user_id
                WHERE mp.user_id = %s
                LIMIT 1
            """, (mentor_id,))

            mentor = cursor.fetchone()

        if not mentor:
            return "Mentor profile not found.", 404

        cursor.execute("""
            SELECT COUNT(*) AS total
            FROM mentorship_requests
            WHERE mentor_id = %s
        """, (mentor_id,))

        total_requests = cursor.fetchone()["total"] or 0

        cursor.execute("""
            SELECT COUNT(*) AS total
            FROM mentorship_requests
            WHERE mentor_id = %s
            AND status = 'pending'
        """, (mentor_id,))

        pending_requests = cursor.fetchone()["total"] or 0

        cursor.execute("""
            SELECT COUNT(*) AS total
            FROM mentorship_sessions
            WHERE mentor_id = %s
            AND status IN ('scheduled', 'upcoming', 'active')
        """, (mentor_id,))

        active_sessions = cursor.fetchone()["total"] or 0

        cursor.execute("""
            SELECT COUNT(*) AS total
            FROM mentorship_sessions
            WHERE mentor_id = %s
            AND status IN ('completed', 'closed')
        """, (mentor_id,))

        completed_sessions = cursor.fetchone()["total"] or 0

        cursor.execute("""
            SELECT COUNT(*) AS total
            FROM mentorship_feedback
            WHERE mentor_id = %s
        """, (mentor_id,))

        total_feedback = cursor.fetchone()["total"] or 0

        cursor.execute("""
            SELECT COALESCE(AVG(rating), 0) AS average_rating
            FROM mentorship_feedback
            WHERE mentor_id = %s
        """, (mentor_id,))

        average_rating = float(
            cursor.fetchone()["average_rating"] or 0
        )

        cursor.execute("""
            SELECT
                mr.id,
                mr.subject,
                mr.message,
                mr.status,
                mr.mentor_response,
                mr.scheduled_at,
                mr.created_at,
                u.full_name AS entrepreneur_name,
                u.email AS entrepreneur_email
            FROM mentorship_requests mr
            INNER JOIN users u
                ON u.id = mr.entrepreneur_id
            WHERE mr.mentor_id = %s
            ORDER BY mr.created_at DESC, mr.id DESC
            LIMIT 8
        """, (mentor_id,))

        mentorship_requests = cursor.fetchall()

        cursor.execute("""
            SELECT
                ms.id,
                ms.scheduled_at,
                ms.duration_minutes,
                ms.notes,
                ms.status,
                u.full_name AS entrepreneur_name,
                u.email AS entrepreneur_email,
                mr.subject
            FROM mentorship_sessions ms
            INNER JOIN users u
                ON u.id = ms.entrepreneur_id
            INNER JOIN mentorship_requests mr
                ON mr.id = ms.request_id
            WHERE ms.mentor_id = %s
            AND ms.status IN ('scheduled', 'upcoming', 'active')
            ORDER BY ms.scheduled_at ASC NULLS LAST, ms.id DESC
            LIMIT 5
        """, (mentor_id,))

        upcoming_sessions = cursor.fetchall()

        cursor.execute("""
            SELECT
                mf.rating,
                mf.feedback_text,
                mf.created_at,
                u.full_name AS entrepreneur_name
            FROM mentorship_feedback mf
            INNER JOIN users u
                ON u.id = mf.entrepreneur_id
            WHERE mf.mentor_id = %s
            ORDER BY mf.created_at DESC, mf.id DESC
            LIMIT 5
        """, (mentor_id,))

        latest_feedback = cursor.fetchall()

        return render_template(
            "mentor/dashboard.html",
            mentor=mentor,
            mentor_approved=mentor["status"] == "approved",
            mentor_pending=mentor["status"] == "pending",
            total_requests=total_requests,
            pending_requests=pending_requests,
            active_sessions=active_sessions,
            completed_sessions=completed_sessions,
            total_feedback=total_feedback,
            average_rating=average_rating,
            mentorship_requests=mentorship_requests,
            upcoming_sessions=upcoming_sessions,
            latest_feedback=latest_feedback
        )

    except Exception as e:
        db.rollback()

        return _internal_error_response(
            e,
            "Unable to load the mentor dashboard."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# MENTOR PROFILE
# =========================================================

@app.route("/mentor/profile", methods=["GET", "POST"])
def mentor_profile():
    if not mentor_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_mentor_tables()
        cursor = db.cursor(dictionary=True)

        mentor_id = session["user_id"]

        if request.method == "POST":
            expertise = request.form.get(
                "expertise", ""
            ).strip()

            bio = request.form.get(
                "bio", ""
            ).strip()

            availability = request.form.get(
                "availability", ""
            ).strip()

            experience_years = request.form.get(
                "experience_years", "0"
            ).strip()

            try:
                experience_value = int(
                    experience_years or 0
                )
            except ValueError:
                return "Experience must be a valid number.", 400

            if experience_value < 0:
                return "Experience cannot be negative.", 400

            if experience_value > 100:
                return "Please enter a valid experience value.", 400

            if len(expertise) > 255:
                return "Expertise must be 255 characters or fewer.", 400

            if len(bio) > 5000:
                return "Bio must be 5,000 characters or fewer.", 400

            if len(availability) > 500:
                return "Availability must be 500 characters or fewer.", 400

            cursor.execute("""
                INSERT INTO mentor_profiles (
                    user_id,
                    expertise,
                    bio,
                    experience_years,
                    availability,
                    status
                )
                VALUES (%s, %s, %s, %s, %s, 'pending')
                ON CONFLICT (user_id) DO UPDATE SET
                    expertise = EXCLUDED.expertise,
                    bio = EXCLUDED.bio,
                    experience_years = EXCLUDED.experience_years,
                    availability = EXCLUDED.availability,
                    updated_at = CURRENT_TIMESTAMP
            """, (
                mentor_id,
                expertise,
                bio,
                experience_value,
                availability
            ))

            db.commit()

            flash(
                "Mentor profile updated successfully.",
                "success"
            )

            return redirect(url_for("mentor_profile"))

        cursor.execute("""
            SELECT
                mp.*,
                u.full_name,
                u.email,
                u.mobile
            FROM mentor_profiles mp
            INNER JOIN users u
                ON u.id = mp.user_id
            WHERE mp.user_id = %s
            LIMIT 1
        """, (mentor_id,))

        mentor = cursor.fetchone()

        if not mentor:
            cursor.execute("""
                INSERT INTO mentor_profiles (user_id, status)
                VALUES (%s, 'pending')
                ON CONFLICT (user_id) DO NOTHING
            """, (mentor_id,))

            db.commit()

            cursor.execute("""
                SELECT
                    mp.*,
                    u.full_name,
                    u.email,
                    u.mobile
                FROM mentor_profiles mp
                INNER JOIN users u
                    ON u.id = mp.user_id
                WHERE mp.user_id = %s
                LIMIT 1
            """, (mentor_id,))

            mentor = cursor.fetchone()

        if not mentor:
            return "Mentor profile not found.", 404

        return render_template(
            "mentor/profile.html",
            mentor=mentor
        )

    except Exception as e:
        db.rollback()

        return _internal_error_response(
            e,
            "Unable to load the mentor profile."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# MENTOR REQUESTS
# =========================================================

@app.route("/mentor/requests")
def mentor_requests():
    if not mentor_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_mentor_tables()
        cursor = db.cursor(dictionary=True)

        mentor_id = session["user_id"]

        status_filter = request.args.get(
            "status", ""
        ).strip().lower()

        query = """
            SELECT
                mr.*,
                u.id AS entrepreneur_id,
                u.full_name AS entrepreneur_name,
                u.email AS entrepreneur_email,
                u.mobile AS entrepreneur_mobile
            FROM mentorship_requests mr
            INNER JOIN users u
                ON u.id = mr.entrepreneur_id
            WHERE mr.mentor_id = %s
        """

        params = [mentor_id]

        allowed_statuses = {
            "pending",
            "accepted",
            "rejected",
            "completed",
            "cancelled"
        }

        if status_filter in allowed_statuses:
            query += " AND mr.status = %s"
            params.append(status_filter)

        query += " ORDER BY mr.created_at DESC, mr.id DESC"

        cursor.execute(query, tuple(params))

        requests_list = cursor.fetchall()

        return render_template(
            "mentor/requests.html",
            mentorship_requests=requests_list,
            requests=requests_list,
            total_requests=len(requests_list),
            pending_requests=sum(
                1 for item in requests_list
                if item["status"] == "pending"
            ),
            accepted_requests=sum(
                1 for item in requests_list
                if item["status"] == "accepted"
            ),
            rejected_requests=sum(
                1 for item in requests_list
                if item["status"] == "rejected"
            ),
            selected_status=status_filter
        )

    except Exception as e:
        return _internal_error_response(
            e,
            "Unable to load mentorship requests."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# MENTOR REQUEST ACTION
# =========================================================

@app.route("/mentor/requests/<int:request_id>/action", methods=["POST"])
def mentor_request_action(request_id):
    if not mentor_required():
        return redirect(url_for("login"))

    action = request.form.get("action", "").strip().lower()
    response_text = request.form.get("mentor_response", "").strip()

    if action not in ("accept", "reject"):
        return "Invalid mentorship action.", 400

    if len(response_text) > 5000:
        return "Mentor response must be 5,000 characters or fewer.", 400

    scheduled_at = None

    if action == "accept":
        scheduled_at_text = request.form.get(
            "scheduled_at", ""
        ).strip()

        if scheduled_at_text:
            try:
                scheduled_at = datetime.fromisoformat(
                    scheduled_at_text
                )

                if scheduled_at.tzinfo is not None:
                    scheduled_at = scheduled_at.astimezone().replace(
                        tzinfo=None
                    )

            except ValueError:
                return "Invalid session date/time.", 400

    cursor = None

    try:
        ensure_mentor_tables()
        cursor = db.cursor(dictionary=True)

        mentor_id = session["user_id"]

        cursor.execute("""
            SELECT id, entrepreneur_id, status
            FROM mentorship_requests
            WHERE id = %s
              AND mentor_id = %s
            FOR UPDATE
        """, (request_id, mentor_id))

        item = cursor.fetchone()

        if not item:
            return "Mentorship request not found.", 404

        if item["status"] != "pending":
            return "This request has already been processed.", 400

        new_status = (
            "accepted" if action == "accept"
            else "rejected"
        )

        cursor.execute("""
            UPDATE mentorship_requests
            SET
                status = %s,
                mentor_response = %s,
                scheduled_at = %s
            WHERE id = %s
              AND mentor_id = %s
        """, (
            new_status,
            response_text or None,
            scheduled_at,
            request_id,
            mentor_id
        ))

        if action == "accept":
            cursor.execute("""
                INSERT INTO mentorship_sessions (
                    request_id,
                    mentor_id,
                    entrepreneur_id,
                    scheduled_at,
                    duration_minutes,
                    status
                )
                VALUES (%s, %s, %s, %s, 60, 'scheduled')
            """, (
                request_id,
                mentor_id,
                item["entrepreneur_id"],
                scheduled_at
            ))

        db.commit()

        flash(
            "Mentorship request " + new_status + " successfully.",
            "success"
        )

        return redirect(url_for("mentor_requests"))

    except Exception as e:
        db.rollback()

        return _internal_error_response(
            e,
            "Unable to process the mentorship request."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# MENTOR SESSIONS
# =========================================================

@app.route("/mentor/sessions")
def mentor_sessions():
    if not mentor_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_mentor_tables()
        cursor = db.cursor(dictionary=True)

        mentor_id = session["user_id"]

        status_filter = request.args.get(
            "status", ""
        ).strip().lower()

        query = """
            SELECT
                ms.*,
                u.id AS entrepreneur_id,
                u.full_name AS entrepreneur_name,
                u.email AS entrepreneur_email,
                mr.subject
            FROM mentorship_sessions ms
            INNER JOIN users u
                ON u.id = ms.entrepreneur_id
            INNER JOIN mentorship_requests mr
                ON mr.id = ms.request_id
            WHERE ms.mentor_id = %s
        """

        params = [mentor_id]

        allowed_statuses = (
            "scheduled",
            "upcoming",
            "active",
            "completed",
            "cancelled",
            "closed"
        )

        if status_filter in allowed_statuses:
            query += " AND ms.status = %s"
            params.append(status_filter)

        query += """
            ORDER BY ms.scheduled_at ASC NULLS LAST, ms.id DESC
        """

        cursor.execute(query, tuple(params))

        sessions = cursor.fetchall()

        return render_template(
            "mentor/sessions.html",
            sessions=sessions,
            mentorship_sessions=sessions,
            total_sessions=len(sessions),
            upcoming_sessions=sum(
                1 for item in sessions
                if item["status"] in (
                    "scheduled",
                    "upcoming",
                    "active"
                )
            ),
            completed_sessions=sum(
                1 for item in sessions
                if item["status"] in (
                    "completed",
                    "closed"
                )
            ),
            selected_status=status_filter
        )

    except Exception as e:
        return _internal_error_response(
            e,
            "Unable to load mentor sessions."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# MENTOR SESSION UPDATE
# =========================================================

@app.route(
    "/mentor/sessions/<int:session_id>/update",
    methods=["POST"]
)
def mentor_session_update(session_id):
    if not mentor_required():
        return redirect(url_for("login"))

    status = request.form.get(
        "status", "completed"
    ).strip().lower()

    notes = request.form.get(
        "notes", ""
    ).strip()

    allowed_statuses = (
        "scheduled",
        "upcoming",
        "active",
        "completed",
        "cancelled",
        "closed"
    )

    if status not in allowed_statuses:
        return "Invalid session status.", 400

    if len(notes) > 5000:
        return "Session notes must be 5,000 characters or fewer.", 400

    cursor = None

    try:
        ensure_mentor_tables()
        cursor = db.cursor(dictionary=True)

        mentor_id = session["user_id"]

        cursor.execute("""
            SELECT id, request_id, status
            FROM mentorship_sessions
            WHERE id = %s
              AND mentor_id = %s
            FOR UPDATE
        """, (session_id, mentor_id))

        session_item = cursor.fetchone()

        if not session_item:
            return "Mentorship session not found.", 404

        cursor.execute("""
            UPDATE mentorship_sessions
            SET
                status = %s,
                notes = %s
            WHERE id = %s
              AND mentor_id = %s
        """, (
            status,
            notes or None,
            session_id,
            mentor_id
        ))

        if status in ("completed", "closed"):
            cursor.execute("""
                UPDATE mentorship_requests
                SET status = 'completed'
                WHERE id = %s
                  AND mentor_id = %s
                  AND status = 'accepted'
            """, (
                session_item["request_id"],
                mentor_id
            ))

        db.commit()

        flash(
            "Mentorship session updated successfully.",
            "success"
        )

        return redirect(url_for("mentor_sessions"))

    except Exception as e:
        db.rollback()

        return _internal_error_response(
            e,
            "Unable to update the mentorship session."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# MENTOR FEEDBACK
# =========================================================

@app.route("/mentor/feedback")
def mentor_feedback():
    if not mentor_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_mentor_tables()
        cursor = db.cursor(dictionary=True)

        mentor_id = session["user_id"]

        cursor.execute("""
            SELECT
                mf.id,
                mf.rating,
                mf.feedback_text,
                mf.created_at,
                ms.id AS session_id,
                u.full_name AS entrepreneur_name,
                u.email AS entrepreneur_email
            FROM mentorship_feedback mf
            INNER JOIN mentorship_sessions ms
                ON ms.id = mf.session_id
            INNER JOIN users u
                ON u.id = mf.entrepreneur_id
            WHERE mf.mentor_id = %s
            ORDER BY mf.created_at DESC, mf.id DESC
        """, (mentor_id,))

        feedback = cursor.fetchall()

        total_feedback = len(feedback)

        average_rating = (
            sum(
                float(item["rating"] or 0)
                for item in feedback
            ) / total_feedback
            if total_feedback else 0
        )

        rating_distribution = {
            1: 0,
            2: 0,
            3: 0,
            4: 0,
            5: 0
        }

        for item in feedback:
            rating = int(item["rating"] or 0)

            if rating in rating_distribution:
                rating_distribution[rating] += 1

        rating_percentages = {
            rating: (
                round(
                    rating_distribution[rating]
                    / total_feedback * 100
                )
                if total_feedback else 0
            )
            for rating in rating_distribution
        }

        return render_template(
            "mentor/feedback.html",
            feedback=feedback,
            feedback_list=feedback,
            total_feedback=total_feedback,
            average_rating=average_rating,
            rating_distribution=rating_distribution,
            rating_percentages=rating_percentages
        )

    except Exception as e:
        return _internal_error_response(
            e,
            "Unable to load mentor feedback."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# SELLER - MENTORSHIP
# =========================================================

@app.route("/seller/mentor")
def seller_mentor():
    if not seller_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_mentor_tables()
        cursor = db.cursor(dictionary=True)

        seller_id = session["user_id"]

        search = request.args.get(
            "search", ""
        ).strip()

        expertise_filter = request.args.get(
            "expertise", ""
        ).strip()

        query = """
            SELECT
                mp.id AS mentor_profile_id,
                mp.user_id AS mentor_id,
                mp.expertise,
                mp.bio,
                mp.experience_years,
                mp.availability,
                mp.status,
                u.full_name,
                u.email
            FROM mentor_profiles mp
            INNER JOIN users u
                ON u.id = mp.user_id
            WHERE mp.status = 'approved'
              AND u.role = 'mentor'
        """

        params = []

        if search:
            query += """
                AND (
                    u.full_name ILIKE %s
                    OR mp.expertise ILIKE %s
                    OR mp.bio ILIKE %s
                )
            """

            value = f"%{search}%"

            params.extend([
                value,
                value,
                value
            ])

        if expertise_filter:
            query += " AND mp.expertise = %s"
            params.append(expertise_filter)

        query += """
            ORDER BY u.full_name ASC, mp.id DESC
        """

        cursor.execute(query, tuple(params))

        mentors = cursor.fetchall()

        cursor.execute("""
            SELECT DISTINCT expertise
            FROM mentor_profiles
            WHERE status = 'approved'
              AND expertise IS NOT NULL
              AND TRIM(expertise) <> ''
            ORDER BY expertise
        """)

        expertise_options = [
            row["expertise"]
            for row in cursor.fetchall()
        ]

        cursor.execute("""
            SELECT
                mr.id,
                mr.mentor_id,
                mr.subject,
                mr.message,
                mr.status,
                mr.mentor_response,
                mr.scheduled_at,
                mr.created_at,
                u.full_name AS mentor_name,
                mp.expertise
            FROM mentorship_requests mr
            INNER JOIN users u
                ON u.id = mr.mentor_id
            LEFT JOIN mentor_profiles mp
                ON mp.user_id = mr.mentor_id
            WHERE mr.entrepreneur_id = %s
              AND mr.status = 'pending'
            ORDER BY mr.created_at DESC, mr.id DESC
        """, (seller_id,))

        pending_mentorships = cursor.fetchall()

        cursor.execute("""
            SELECT
                mr.id AS request_id,
                mr.subject,
                mr.message,
                mr.status AS request_status,
                mr.scheduled_at AS request_scheduled_at,
                ms.id AS session_id,
                ms.scheduled_at,
                ms.duration_minutes,
                ms.notes,
                ms.status AS session_status,
                ms.mentor_id,
                u.full_name AS mentor_name,
                mp.expertise,
                CASE
                    WHEN mf.id IS NULL THEN 0
                    ELSE 1
                END AS has_feedback
            FROM mentorship_requests mr
            INNER JOIN users u
                ON u.id = mr.mentor_id
            LEFT JOIN mentor_profiles mp
                ON mp.user_id = mr.mentor_id
            LEFT JOIN mentorship_sessions ms
                ON ms.request_id = mr.id
                AND ms.entrepreneur_id = %s
            LEFT JOIN mentorship_feedback mf
                ON mf.session_id = ms.id
                AND mf.entrepreneur_id = %s
            WHERE mr.entrepreneur_id = %s
              AND mr.status IN ('accepted', 'completed')
            ORDER BY ms.scheduled_at DESC NULLS LAST, mr.id DESC
        """, (
            seller_id,
            seller_id,
            seller_id
        ))

        active_mentorships = cursor.fetchall()

        return render_template(
            "seller/mentor.html",
            mentors=mentors,
            search=search,
            selected_expertise=expertise_filter,
            expertise_options=expertise_options,
            pending_mentorships=pending_mentorships,
            active_mentorships=active_mentorships
        )

    except Exception as e:
        return _internal_error_response(
            e,
            "Unable to load seller mentorship."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# SELLER - MENTORSHIP REQUEST
# =========================================================

@app.route("/seller/mentor/request", methods=["POST"])
def seller_mentor_request():
    if not seller_required():
        return redirect(url_for("login"))

    mentor_id = request.form.get("mentor_id", "").strip()
    subject = request.form.get("subject", "").strip()
    message = request.form.get("message", "").strip()
    preferred_date = request.form.get("preferred_date", "").strip()

    if not mentor_id.isdigit():
        return "Invalid mentor selected.", 400

    if not subject:
        return "Please enter a mentorship subject.", 400

    if len(subject) > 255:
        return "Subject is too long.", 400

    if not message:
        return "Please describe what you need help with.", 400

    if len(message) > 5000:
        return "Message is too long.", 400

    scheduled_at = None

    if preferred_date:
        try:
            scheduled_at = datetime.fromisoformat(
                preferred_date.replace("Z", "+00:00")
            )

            if scheduled_at.tzinfo is not None:
                scheduled_at = scheduled_at.astimezone().replace(
                    tzinfo=None
                )

        except ValueError:
            return "Invalid preferred session date/time.", 400

    cursor = None

    try:
        ensure_mentor_tables()
        cursor = db.cursor(dictionary=True)

        seller_id = session["user_id"]
        mentor_id_value = int(mentor_id)

        cursor.execute("""
            SELECT
                u.id,
                u.full_name
            FROM users u
            INNER JOIN mentor_profiles mp
                ON mp.user_id = u.id
            WHERE u.id = %s
              AND u.role = 'mentor'
              AND mp.status = 'approved'
            LIMIT 1
        """, (mentor_id_value,))

        mentor = cursor.fetchone()

        if not mentor:
            return "The selected mentor is not currently available.", 404

        cursor.execute("""
            SELECT id
            FROM mentorship_requests
            WHERE mentor_id = %s
              AND entrepreneur_id = %s
              AND status = 'pending'
            LIMIT 1
        """, (mentor_id_value, seller_id))

        if cursor.fetchone():
            return "You already have a pending request with this mentor.", 400

        cursor.execute("""
            INSERT INTO mentorship_requests (
                mentor_id,
                entrepreneur_id,
                subject,
                message,
                status,
                scheduled_at
            )
            VALUES (%s, %s, %s, %s, 'pending', %s)
        """, (
            mentor_id_value,
            seller_id,
            subject,
            message,
            scheduled_at
        ))

        db.commit()

        flash("Mentorship request sent successfully.", "success")

        return redirect(url_for("seller_mentor"))

    except Exception as e:
        db.rollback()

        return _internal_error_response(
            e,
            "Unable to send the mentorship request."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# SELLER - MENTORSHIP SESSIONS
# =========================================================

@app.route("/seller/mentor/sessions")
def seller_mentor_sessions():
    if not seller_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_mentor_tables()
        cursor = db.cursor(dictionary=True)

        seller_id = session["user_id"]

        cursor.execute("""
            SELECT
                ms.id,
                ms.request_id,
                ms.mentor_id,
                ms.entrepreneur_id,
                ms.scheduled_at,
                ms.duration_minutes,
                ms.notes,
                ms.status,
                ms.created_at,
                mr.subject,
                mr.message,
                u.full_name AS mentor_name,
                u.email AS mentor_email,
                mp.expertise,
                CASE
                    WHEN mf.id IS NULL THEN 0
                    ELSE 1
                END AS has_feedback
            FROM mentorship_sessions ms
            INNER JOIN mentorship_requests mr
                ON mr.id = ms.request_id
            INNER JOIN users u
                ON u.id = ms.mentor_id
            LEFT JOIN mentor_profiles mp
                ON mp.user_id = ms.mentor_id
            LEFT JOIN mentorship_feedback mf
                ON mf.session_id = ms.id
                AND mf.entrepreneur_id = %s
            WHERE ms.entrepreneur_id = %s
            ORDER BY ms.scheduled_at DESC NULLS LAST, ms.id DESC
        """, (seller_id, seller_id))

        sessions = cursor.fetchall()

        return render_template(
            "seller/mentor_sessions.html",
            sessions=sessions,
            mentorship_sessions=sessions,
            total_sessions=len(sessions),
            upcoming_sessions=sum(
                1 for item in sessions
                if item["status"] in (
                    "scheduled",
                    "upcoming",
                    "active"
                )
            ),
            completed_sessions=sum(
                1 for item in sessions
                if item["status"] in (
                    "completed",
                    "closed"
                )
            )
        )

    except Exception as e:
        return _internal_error_response(
            e,
            "Unable to load seller mentorship sessions."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# SELLER - MENTORSHIP FEEDBACK
# =========================================================

@app.route(
    "/seller/mentor/sessions/<int:session_id>/feedback",
    methods=["POST"]
)
def seller_mentor_feedback(session_id):
    if not seller_required():
        return redirect(url_for("login"))

    rating_text = request.form.get("rating", "").strip()

    feedback_text = request.form.get(
        "feedback_text", ""
    ).strip()

    try:
        rating = int(rating_text)
    except (TypeError, ValueError):
        return "Rating must be a number from 1 to 5.", 400

    if rating < 1 or rating > 5:
        return "Rating must be between 1 and 5.", 400

    if len(feedback_text) > 5000:
        return "Feedback is too long.", 400

    cursor = None

    try:
        ensure_mentor_tables()
        cursor = db.cursor(dictionary=True)

        seller_id = session["user_id"]

        cursor.execute("""
            SELECT
                id,
                mentor_id,
                entrepreneur_id,
                status
            FROM mentorship_sessions
            WHERE id = %s
              AND entrepreneur_id = %s
            FOR UPDATE
        """, (session_id, seller_id))

        mentorship_session = cursor.fetchone()

        if not mentorship_session:
            return "Mentorship session not found.", 404

        if mentorship_session["status"] not in (
            "completed",
            "closed"
        ):
            return (
                "Feedback can be submitted only after "
                "the session is completed."
            ), 400

        cursor.execute("""
            SELECT id
            FROM mentorship_feedback
            WHERE session_id = %s
              AND entrepreneur_id = %s
            LIMIT 1
        """, (session_id, seller_id))

        if cursor.fetchone():
            return (
                "Feedback has already been submitted "
                "for this session."
            ), 400

        cursor.execute("""
            INSERT INTO mentorship_feedback (
                session_id,
                mentor_id,
                entrepreneur_id,
                rating,
                feedback_text
            )
            VALUES (%s, %s, %s, %s, %s)
        """, (
            session_id,
            mentorship_session["mentor_id"],
            seller_id,
            rating,
            feedback_text or None
        ))

        db.commit()

        flash("Feedback submitted successfully.", "success")

        return redirect(url_for("seller_mentor_sessions"))

    except Exception as e:
        db.rollback()

        return _internal_error_response(
            e,
            "Unable to submit mentorship feedback."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# ADMIN PORTAL
# =========================================================

# =========================================================
# ADMIN DASHBOARD
# =========================================================

@app.route("/admin/dashboard")
def admin_dashboard():
    if not admin_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        cursor.execute("""
            SELECT COUNT(*) AS total_users
            FROM users
        """)
        total_users = cursor.fetchone()["total_users"] or 0

        cursor.execute("""
            SELECT COUNT(*) AS total_sellers
            FROM users
            WHERE role = 'seller'
        """)
        total_sellers = cursor.fetchone()["total_sellers"] or 0

        cursor.execute("""
            SELECT COUNT(*) AS total_buyers
            FROM users
            WHERE role = 'buyer'
        """)
        total_buyers = cursor.fetchone()["total_buyers"] or 0

        cursor.execute("""
            SELECT COUNT(*) AS total_mentors
            FROM users
            WHERE role = 'mentor'
        """)
        total_mentors = cursor.fetchone()["total_mentors"] or 0

        cursor.execute("""
            SELECT COUNT(*) AS total_products
            FROM products
        """)
        total_products = cursor.fetchone()["total_products"] or 0

        cursor.execute("""
            SELECT COUNT(*) AS active_products
            FROM products
            WHERE status = 'active'
        """)
        active_products = cursor.fetchone()["active_products"] or 0

        cursor.execute("""
            SELECT COUNT(*) AS total_orders
            FROM orders
        """)
        total_orders = cursor.fetchone()["total_orders"] or 0

        cursor.execute("""
            SELECT COUNT(*) AS pending_orders
            FROM orders
            WHERE status = 'pending'
        """)
        pending_orders = cursor.fetchone()["pending_orders"] or 0

        cursor.execute("""
            SELECT COUNT(*) AS open_complaints
            FROM complaints
            WHERE status IN ('open', 'in_progress')
        """)
        open_complaints = cursor.fetchone()["open_complaints"] or 0

        cursor.execute("""
            SELECT COUNT(*) AS pending_sellers
            FROM seller_approvals
            WHERE status = 'pending'
        """)
        pending_sellers = cursor.fetchone()["pending_sellers"] or 0

        # Count pending mentors separately.
        pending_mentors = 0

        try:
            ensure_mentor_tables()

            cursor.execute("""
                SELECT COUNT(*) AS pending_mentors
                FROM mentor_profiles
                WHERE status = 'pending'
            """)

            pending_mentors = (
                cursor.fetchone()["pending_mentors"] or 0
            )

        except Exception:
            db.rollback()

            current_app.logger.exception(
                "Unable to load pending mentor count."
            )

        cursor.execute("""
            SELECT COALESCE(SUM(oi.subtotal), 0) AS total_revenue
            FROM order_items oi
            INNER JOIN orders o
                ON o.id = oi.order_id
            INNER JOIN payments pay
                ON pay.order_id = o.id
            WHERE pay.payment_status = 'paid'
              AND o.status NOT IN ('cancelled', 'returned')
        """)

        total_revenue = float(
            cursor.fetchone()["total_revenue"] or 0
        )

        cursor.execute("""
            SELECT
                sa.seller_id,
                u.full_name,
                u.email,
                sa.status,
                sa.created_at,
                sa.reviewed_at
            FROM seller_approvals sa
            INNER JOIN users u
                ON u.id = sa.seller_id
            ORDER BY
                CASE
                    WHEN sa.status = 'pending' THEN 1
                    WHEN sa.status = 'rejected' THEN 2
                    ELSE 3
                END,
                sa.created_at DESC
            LIMIT 10
        """)

        seller_approvals = cursor.fetchall()

        return render_template(
            "admin/dashboard.html",
            total_users=total_users,
            total_sellers=total_sellers,
            total_buyers=total_buyers,
            total_mentors=total_mentors,
            total_products=total_products,
            active_products=active_products,
            total_orders=total_orders,
            pending_orders=pending_orders,
            open_complaints=open_complaints,
            pending_sellers=pending_sellers,
            pending_mentors=pending_mentors,
            total_revenue=total_revenue,
            seller_approvals=seller_approvals
        )

    except Exception as e:
        db.rollback()

        return _internal_error_response(
            e,
            "Unable to load the admin dashboard."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# ADMIN USERS
# =========================================================

@app.route("/admin/users")
def admin_users():
    if not admin_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        ensure_mentor_tables()

        cursor = db.cursor(dictionary=True)

        search = request.args.get(
            "search", ""
        ).strip()

        role_filter = request.args.get(
            "role", ""
        ).strip().lower()

        query = """
            SELECT
                u.id,
                u.full_name,
                u.email,
                u.mobile,
                u.role,
                CASE
                    WHEN u.role = 'seller'
                        THEN COALESCE(sa.status, 'pending')
                    WHEN u.role = 'mentor'
                        THEN COALESCE(mp.status, 'pending')
                    ELSE 'active'
                END AS account_status,
                COALESCE(
                    sa.reviewed_at,
                    mp.reviewed_at
                ) AS reviewed_at
            FROM users u
            LEFT JOIN seller_approvals sa
                ON sa.seller_id = u.id
                AND u.role = 'seller'
            LEFT JOIN mentor_profiles mp
                ON mp.user_id = u.id
                AND u.role = 'mentor'
            WHERE 1 = 1
        """

        params = []

        if search:
            query += """
                AND (
                    u.full_name ILIKE %s
                    OR u.email ILIKE %s
                    OR u.mobile ILIKE %s
                )
            """

            value = f"%{search}%"

            params.extend([
                value,
                value,
                value
            ])

        if role_filter in (
            "admin",
            "seller",
            "buyer",
            "mentor"
        ):
            query += " AND u.role = %s"
            params.append(role_filter)

        query += " ORDER BY u.id DESC"

        cursor.execute(query, tuple(params))

        users = cursor.fetchall()

        for user in users:
            user["status"] = (
                user.get("account_status") or "active"
            )

        cursor.execute("""
            SELECT COUNT(*) AS total
            FROM users
        """)
        total_users = cursor.fetchone()["total"] or 0

        cursor.execute("""
            SELECT COUNT(*) AS total
            FROM users
            WHERE role = 'seller'
        """)
        total_sellers = cursor.fetchone()["total"] or 0

        cursor.execute("""
            SELECT COUNT(*) AS total
            FROM users
            WHERE role = 'buyer'
        """)
        total_buyers = cursor.fetchone()["total"] or 0

        cursor.execute("""
            SELECT COUNT(*) AS total
            FROM users
            WHERE role = 'mentor'
        """)
        total_mentors = cursor.fetchone()["total"] or 0

        return render_template(
            "admin/users.html",
            users=users,
            total_users=total_users,
            total_sellers=total_sellers,
            total_buyers=total_buyers,
            total_mentors=total_mentors,
            search=search,
            selected_role=role_filter
        )

    except Exception as e:
        return _internal_error_response(
            e,
            "Unable to load admin user records."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# ADMIN USER DETAILS
# =========================================================

@app.route("/admin/users/<int:user_id>")
def admin_user_details(user_id):
    if not admin_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        ensure_mentor_tables()

        cursor = db.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                u.id,
                u.full_name,
                u.email,
                u.mobile,
                u.role,
                CASE
                    WHEN u.role = 'seller'
                        THEN COALESCE(sa.status, 'pending')
                    WHEN u.role = 'mentor'
                        THEN COALESCE(mp.status, 'pending')
                    ELSE 'active'
                END AS account_status,
                COALESCE(
                    sa.review_note,
                    mp.review_note
                ) AS review_note,
                COALESCE(
                    sa.reviewed_at,
                    mp.reviewed_at
                ) AS reviewed_at
            FROM users u
            LEFT JOIN seller_approvals sa
                ON sa.seller_id = u.id
                AND u.role = 'seller'
            LEFT JOIN mentor_profiles mp
                ON mp.user_id = u.id
                AND u.role = 'mentor'
            WHERE u.id = %s
        """, (user_id,))

        user = cursor.fetchone()

        if not user:
            return "User not found.", 404

        user["status"] = user.get("account_status") or "active"

        return render_template(
            "admin/users.html",
            users=[user],
            total_users=1,
            total_sellers=(
                1 if user["role"] == "seller" else 0
            ),
            total_buyers=(
                1 if user["role"] == "buyer" else 0
            ),
            total_mentors=(
                1 if user["role"] == "mentor" else 0
            ),
            search="",
            selected_role=user["role"],
            selected_user=user
        )

    except Exception as e:
        return _internal_error_response(
            e,
            "Unable to load the selected user."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# ADMIN USER STATUS
# =========================================================

@app.route(
    "/admin/users/<int:user_id>/status",
    methods=["POST"]
)
def admin_user_status(user_id):
    if not admin_required():
        return redirect(url_for("login"))

    new_status = request.form.get(
        "status", ""
    ).strip().lower()

    allowed_statuses = (
        "active",
        "suspended",
        "rejected",
        "approved",
        "pending"
    )

    if new_status not in allowed_statuses:
        return "Invalid user status.", 400

    cursor = None

    try:
        ensure_db_connection()
        ensure_mentor_tables()

        cursor = db.cursor(dictionary=True)

        cursor.execute("""
            SELECT id, role
            FROM users
            WHERE id = %s
            FOR UPDATE
        """, (user_id,))

        user = cursor.fetchone()

        if not user:
            return "User not found.", 404

        if user["role"] == "seller":

            if new_status in ("active", "suspended"):

                cursor.execute("""
                    INSERT INTO seller_approvals (
                        seller_id,
                        status,
                        account_status,
                        reviewed_by,
                        reviewed_at
                    )
                    VALUES (%s, 'pending', %s, %s, NOW())
                    ON CONFLICT (seller_id) DO UPDATE SET
                        account_status = EXCLUDED.account_status,
                        reviewed_by = EXCLUDED.reviewed_by,
                        reviewed_at = NOW(),
                        updated_at = CURRENT_TIMESTAMP
                """, (
                    user_id,
                    new_status,
                    session["user_id"]
                ))

                description = (
                    f"Seller account status changed to {new_status}"
                )

            else:

                cursor.execute("""
                    INSERT INTO seller_approvals (
                        seller_id,
                        status,
                        reviewed_by,
                        reviewed_at
                    )
                    VALUES (%s, %s, %s, NOW())
                    ON CONFLICT (seller_id) DO UPDATE SET
                        status = EXCLUDED.status,
                        reviewed_by = EXCLUDED.reviewed_by,
                        reviewed_at = NOW(),
                        updated_at = CURRENT_TIMESTAMP
                """, (
                    user_id,
                    new_status,
                    session["user_id"]
                ))

                description = (
                    f"Seller approval status changed to {new_status}"
                )

        elif user["role"] == "mentor":

            if new_status not in (
                "pending",
                "approved",
                "rejected"
            ):
                return "Invalid mentor status.", 400

            cursor.execute("""
                INSERT INTO mentor_profiles (
                    user_id,
                    status,
                    reviewed_by,
                    reviewed_at
                )
                VALUES (%s, %s, %s, NOW())
                ON CONFLICT (user_id) DO UPDATE SET
                    status = EXCLUDED.status,
                    reviewed_by = EXCLUDED.reviewed_by,
                    reviewed_at = NOW(),
                    updated_at = CURRENT_TIMESTAMP
            """, (
                user_id,
                new_status,
                session["user_id"]
            ))

            description = (
                f"Mentor approval status changed to {new_status}"
            )

        else:
            return (
                "Only seller and mentor approval status "
                "can be managed from this page."
            ), 400

        cursor.execute("""
            INSERT INTO admin_activity_logs (
                admin_id,
                action,
                target_type,
                target_id,
                description
            )
            VALUES (
                %s,
                'user_status_update',
                'user',
                %s,
                %s
            )
        """, (
            session["user_id"],
            user_id,
            description
        ))

        db.commit()

        flash("User status updated successfully.", "success")

        return redirect(url_for("admin_users"))

    except Exception as e:
        db.rollback()

        return _internal_error_response(
            e,
            "Unable to update user approval status."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# ADMIN SELLERS
# =========================================================

@app.route("/admin/sellers")
def admin_sellers():
    if not admin_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        status_filter = request.args.get(
            "status", ""
        ).strip().lower()

        account_status_filter = request.args.get(
            "account_status", ""
        ).strip().lower()

        search = request.args.get(
            "search", ""
        ).strip()

        query = """
            SELECT
                u.id,
                u.full_name,
                u.email,
                u.mobile,
                COALESCE(sa.status, 'pending') AS approval_status,
                COALESCE(sa.account_status, 'active') AS account_status,
                sa.review_note,
                sa.reviewed_at,
                sa.created_at AS application_date,
                COUNT(DISTINCT p.id) AS product_count,
                COALESCE(seller_stats.order_count, 0) AS order_count,
                COALESCE(seller_stats.revenue, 0) AS revenue
            FROM users u
            LEFT JOIN seller_approvals sa
                ON sa.seller_id = u.id
            LEFT JOIN products p
                ON p.seller_id = u.id
            LEFT JOIN (
                SELECT
                    oi.seller_id,
                    COUNT(DISTINCT oi.order_id) AS order_count,
                    SUM(oi.subtotal) AS revenue
                FROM order_items oi
                INNER JOIN orders o
                    ON o.id = oi.order_id
                INNER JOIN payments pay
                    ON pay.order_id = o.id
                WHERE pay.payment_status = 'paid'
                  AND o.status NOT IN ('cancelled', 'returned')
                GROUP BY oi.seller_id
            ) seller_stats
                ON seller_stats.seller_id = u.id
            WHERE u.role = 'seller'
        """

        params = []

        if search:
            query += """
                AND (
                    u.full_name ILIKE %s
                    OR u.email ILIKE %s
                    OR u.mobile ILIKE %s
                )
            """

            value = f"%{search}%"

            params.extend([
                value,
                value,
                value
            ])

        if status_filter in (
            "pending",
            "approved",
            "rejected"
        ):
            query += """
                AND COALESCE(sa.status, 'pending') = %s
            """

            params.append(status_filter)

        if account_status_filter in (
            "active",
            "suspended"
        ):
            query += """
                AND COALESCE(sa.account_status, 'active') = %s
            """

            params.append(account_status_filter)

        query += """
            GROUP BY
                u.id,
                u.full_name,
                u.email,
                u.mobile,
                sa.status,
                sa.account_status,
                sa.review_note,
                sa.reviewed_at,
                sa.created_at,
                seller_stats.order_count,
                seller_stats.revenue
            ORDER BY
                CASE COALESCE(sa.status, 'pending')
                    WHEN 'pending' THEN 1
                    WHEN 'approved' THEN 2
                    WHEN 'rejected' THEN 3
                    ELSE 4
                END,
                u.id DESC
        """

        cursor.execute(query, tuple(params))

        sellers = cursor.fetchall()

        return render_template(
            "admin/sellers.html",
            sellers=sellers,
            search=search,
            selected_status=status_filter,
            selected_account_status=account_status_filter,
            total_sellers=len(sellers),
            pending_sellers=sum(
                1 for x in sellers
                if x["approval_status"] == "pending"
            ),
            approved_sellers=sum(
                1 for x in sellers
                if x["approval_status"] == "approved"
            ),
            rejected_sellers=sum(
                1 for x in sellers
                if x["approval_status"] == "rejected"
            )
        )

    except Exception as e:
        return _internal_error_response(
            e,
            "Unable to load seller records."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# ADMIN SELLER DETAILS
# =========================================================

@app.route("/admin/sellers/<int:user_id>")
def admin_seller_details(user_id):
    if not admin_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                u.id,
                u.full_name,
                u.email,
                u.mobile,
                u.created_at,
                COALESCE(sa.status, 'pending') AS approval_status,
                COALESCE(sa.account_status, 'active') AS account_status,
                sa.review_note,
                sa.reviewed_at,
                COUNT(DISTINCT p.id) AS product_count,
                COALESCE(seller_stats.order_count, 0) AS order_count,
                COALESCE(seller_stats.revenue, 0) AS revenue
            FROM users u
            LEFT JOIN seller_approvals sa
                ON sa.seller_id = u.id
            LEFT JOIN products p
                ON p.seller_id = u.id
            LEFT JOIN (
                SELECT
                    oi.seller_id,
                    COUNT(DISTINCT oi.order_id) AS order_count,
                    SUM(oi.subtotal) AS revenue
                FROM order_items oi
                INNER JOIN orders o
                    ON o.id = oi.order_id
                INNER JOIN payments pay
                    ON pay.order_id = o.id
                WHERE pay.payment_status = 'paid'
                  AND o.status NOT IN ('cancelled', 'returned')
                GROUP BY oi.seller_id
            ) seller_stats
                ON seller_stats.seller_id = u.id
            WHERE u.id = %s
              AND u.role = 'seller'
            GROUP BY
                u.id,
                u.full_name,
                u.email,
                u.mobile,
                u.created_at,
                sa.status,
                sa.account_status,
                sa.review_note,
                sa.reviewed_at,
                seller_stats.order_count,
                seller_stats.revenue
        """, (user_id,))

        seller = cursor.fetchone()

        if not seller:
            return "Seller not found.", 404

        cursor.execute("""
            SELECT
                id,
                name,
                price,
                stock,
                status,
                created_at
            FROM products
            WHERE seller_id = %s
            ORDER BY created_at DESC, id DESC
        """, (user_id,))

        products = cursor.fetchall()

        return render_template(
            "admin/seller_details.html",
            seller=seller,
            products=products
        )

    except Exception as e:
        return _internal_error_response(
            e,
            "Unable to load seller details."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# ADMIN SELLER APPROVE
# =========================================================

@app.route(
    "/admin/sellers/<int:user_id>/approve",
    methods=["POST"]
)
def admin_seller_approve(user_id):
    if not admin_required():
        return redirect(url_for("login"))

    return admin_update_seller_approval(
        user_id,
        "approved"
    )


# =========================================================
# ADMIN SELLER REJECT
# =========================================================

@app.route(
    "/admin/sellers/<int:user_id>/reject",
    methods=["POST"]
)
def admin_seller_reject(user_id):
    if not admin_required():
        return redirect(url_for("login"))

    return admin_update_seller_approval(
        user_id,
        "rejected"
    )


# =========================================================
# ADMIN SELLER ACCOUNT STATUS
# =========================================================

@app.route(
    "/admin/sellers/<int:user_id>/status",
    methods=["POST"]
)
def admin_seller_status(user_id):
    if not admin_required():
        return redirect(url_for("login"))

    new_status = request.form.get(
        "status", ""
    ).strip().lower()

    if new_status not in ("active", "suspended"):
        return "Account status must be active or suspended.", 400

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        cursor.execute("""
            SELECT id
            FROM users
            WHERE id = %s
              AND role = 'seller'
            FOR UPDATE
        """, (user_id,))

        if not cursor.fetchone():
            return "Seller not found.", 404

        cursor.execute("""
            INSERT INTO seller_approvals (
                seller_id,
                status,
                account_status,
                reviewed_by,
                reviewed_at
            )
            VALUES (%s, 'pending', %s, %s, NOW())
            ON CONFLICT (seller_id) DO UPDATE SET
                account_status = EXCLUDED.account_status,
                reviewed_by = EXCLUDED.reviewed_by,
                reviewed_at = NOW(),
                updated_at = CURRENT_TIMESTAMP
        """, (
            user_id,
            new_status,
            session["user_id"]
        ))

        cursor.execute("""
            INSERT INTO admin_activity_logs (
                admin_id,
                action,
                target_type,
                target_id,
                description
            )
            VALUES (%s, 'seller_account_status', 'seller', %s, %s)
        """, (
            session["user_id"],
            user_id,
            f"Seller account status changed to {new_status}"
        ))

        db.commit()

        flash("Seller account status updated successfully.", "success")

        return redirect(url_for("admin_sellers"))

    except Exception as e:
        db.rollback()

        return _internal_error_response(
            e,
            "Unable to update seller account status."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# ADMIN SELLER APPROVAL HELPER
# =========================================================

def admin_update_seller_approval(user_id, status):
    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        cursor.execute("""
            SELECT id, role
            FROM users
            WHERE id = %s
            FOR UPDATE
        """, (user_id,))

        seller = cursor.fetchone()

        if not seller or seller["role"] != "seller":
            return "Seller not found.", 404

        review_note = request.form.get(
            "review_note", ""
        ).strip()

        if len(review_note) > 5000:
            return "Review note is too long.", 400

        cursor.execute("""
            INSERT INTO seller_approvals (
                seller_id,
                status,
                reviewed_by,
                review_note,
                reviewed_at
            )
            VALUES (%s, %s, %s, %s, NOW())
            ON CONFLICT (seller_id) DO UPDATE SET
                status = EXCLUDED.status,
                reviewed_by = EXCLUDED.reviewed_by,
                review_note = EXCLUDED.review_note,
                reviewed_at = NOW(),
                updated_at = CURRENT_TIMESTAMP
        """, (
            user_id,
            status,
            session["user_id"],
            review_note or None
        ))

        cursor.execute("""
            INSERT INTO admin_activity_logs (
                admin_id,
                action,
                target_type,
                target_id,
                description
            )
            VALUES (%s, %s, 'seller', %s, %s)
        """, (
            session["user_id"],
            f"seller_{status}",
            user_id,
            f"Seller registration {status}"
        ))

        db.commit()

        flash(
            f"Seller registration {status} successfully.",
            "success"
        )

        return redirect(url_for("admin_sellers"))

    except Exception as e:
        db.rollback()

        return _internal_error_response(
            e,
            "Unable to update seller approval."
        )

    finally:
        if cursor:
            cursor.close()



# =========================================================
# ADMIN - MENTOR APPROVAL
# =========================================================

@app.route("/admin/mentors")
def admin_mentors():
    if not admin_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        ensure_mentor_tables()
        cursor = db.cursor(dictionary=True)

        status_filter = request.args.get("status", "").strip().lower()
        search = request.args.get("search", "").strip()

        query = """
            SELECT
                u.id,
                u.full_name,
                u.email,
                u.mobile,
                mp.id AS profile_id,
                mp.expertise,
                mp.bio,
                mp.experience_years,
                mp.availability,
                mp.status,
                mp.review_note,
                mp.reviewed_at,
                mp.created_at AS application_date,
                reviewer.full_name AS reviewed_by_name
            FROM users u
            INNER JOIN mentor_profiles mp
                ON mp.user_id = u.id
            LEFT JOIN users reviewer
                ON reviewer.id = mp.reviewed_by
            WHERE u.role = 'mentor'
        """

        params = []

        if search:
            query += """
                AND (
                    u.full_name ILIKE %s
                    OR u.email ILIKE %s
                    OR mp.expertise ILIKE %s
                )
            """

            value = f"%{search}%"
            params.extend([value, value, value])

        if status_filter in ("pending", "approved", "rejected"):
            query += " AND mp.status = %s"
            params.append(status_filter)

        query += """
            ORDER BY
                CASE mp.status
                    WHEN 'pending' THEN 1
                    WHEN 'approved' THEN 2
                    WHEN 'rejected' THEN 3
                    ELSE 4
                END,
                u.id DESC
        """

        cursor.execute(query, tuple(params))
        mentors = cursor.fetchall()

        return render_template(
            "admin/mentors.html",
            mentors=mentors,
            search=search,
            selected_status=status_filter,
            total_mentors=len(mentors),
            pending_mentors=sum(
                1 for mentor in mentors
                if mentor["status"] == "pending"
            ),
            approved_mentors=sum(
                1 for mentor in mentors
                if mentor["status"] == "approved"
            ),
            rejected_mentors=sum(
                1 for mentor in mentors
                if mentor["status"] == "rejected"
            ),
        )

    except Exception as e:
        return _internal_error_response(
            e,
            "Unable to load mentor records."
        )

    finally:
        if cursor:
            cursor.close()


@app.route("/admin/mentors/<int:user_id>/approve", methods=["POST"])
def admin_mentor_approve(user_id):
    if not admin_required():
        return redirect(url_for("login"))

    return admin_update_mentor_approval(user_id, "approved")


@app.route("/admin/mentors/<int:user_id>/reject", methods=["POST"])
def admin_mentor_reject(user_id):
    if not admin_required():
        return redirect(url_for("login"))

    return admin_update_mentor_approval(user_id, "rejected")


def admin_update_mentor_approval(user_id, status):
    if status not in ("approved", "rejected"):
        return "Invalid mentor approval status.", 400

    cursor = None

    try:
        ensure_db_connection()
        ensure_mentor_tables()
        cursor = db.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT id, role
            FROM users
            WHERE id = %s
            FOR UPDATE
            """,
            (user_id,)
        )

        mentor = cursor.fetchone()

        if not mentor or mentor["role"] != "mentor":
            return "Mentor not found.", 404

        review_note = request.form.get("review_note", "").strip()

        if len(review_note) > 5000:
            return "Review note must be 5,000 characters or fewer.", 400

        cursor.execute(
            """
            INSERT INTO mentor_profiles (
                user_id,
                status,
                reviewed_by,
                review_note,
                reviewed_at
            )
            VALUES (%s, %s, %s, %s, NOW())
            ON CONFLICT (user_id)
            DO UPDATE SET
                status = EXCLUDED.status,
                reviewed_by = EXCLUDED.reviewed_by,
                review_note = EXCLUDED.review_note,
                reviewed_at = NOW()
            """,
            (
                user_id,
                status,
                session["user_id"],
                review_note or None
            )
        )

        cursor.execute(
            """
            INSERT INTO admin_activity_logs (
                admin_id,
                action,
                target_type,
                target_id,
                description
            )
            VALUES (%s, %s, 'mentor', %s, %s)
            """,
            (
                session["user_id"],
                f"mentor_{status}",
                user_id,
                f"Mentor profile {status}"
            )
        )

        db.commit()

        flash(f"Mentor application {status} successfully.", "success")
        return redirect(url_for("admin_mentors"))

    except Exception as e:
        db.rollback()
        return _internal_error_response(
            e,
            "Unable to update mentor approval."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# ADMIN - PRODUCTS
# =========================================================

@app.route("/admin/products")
def admin_products():
    if not admin_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        search = request.args.get("search", "").strip()
        category = request.args.get("category", "").strip()
        status_filter = request.args.get("status", "").strip().lower()
        stock_filter = request.args.get("stock", "").strip().lower()

        query = """
            SELECT
                p.id,
                p.name,
                p.description,
                p.price,
                p.stock,
                p.image_url,
                p.status,
                p.created_at,
                u.id AS seller_id,
                u.full_name AS seller_name,
                u.email AS seller_email,
                c.name AS category_name
            FROM products p
            INNER JOIN users u ON p.seller_id = u.id
            LEFT JOIN categories c ON p.category_id = c.id
            WHERE 1 = 1
        """

        params = []

        if search:
            query += """
                AND (
                    p.name ILIKE %s
                    OR p.description ILIKE %s
                    OR u.full_name ILIKE %s
                )
            """

            value = f"%{search}%"
            params.extend([value, value, value])

        if category:
            query += " AND c.name = %s"
            params.append(category)

        if status_filter in ("active", "inactive"):
            query += " AND p.status = %s"
            params.append(status_filter)

        if stock_filter == "low":
            query += " AND p.stock > 0 AND p.stock <= 5"
        elif stock_filter == "out":
            query += " AND p.stock <= 0"
        elif stock_filter == "available":
            query += " AND p.stock > 0"

        query += " ORDER BY p.created_at DESC, p.id DESC"

        cursor.execute(query, tuple(params))
        products = cursor.fetchall()

        cursor.execute("SELECT COUNT(*) AS total FROM products")
        total_products = cursor.fetchone()["total"] or 0

        cursor.execute(
            "SELECT COUNT(*) AS total FROM products WHERE status = 'active'"
        )
        active_products = cursor.fetchone()["total"] or 0

        cursor.execute(
            "SELECT COUNT(*) AS total FROM products WHERE status <> 'active'"
        )
        inactive_products = cursor.fetchone()["total"] or 0

        cursor.execute(
            "SELECT COUNT(*) AS total FROM products WHERE stock <= 5"
        )
        low_stock_products = cursor.fetchone()["total"] or 0

        cursor.execute(
            "SELECT id, name FROM categories ORDER BY name"
        )
        categories = cursor.fetchall()

        return render_template(
            "admin/products.html",
            products=products,
            categories=categories,
            total_products=total_products,
            active_products=active_products,
            inactive_products=inactive_products,
            low_stock_products=low_stock_products,
            search=search,
            selected_category=category,
            selected_status=status_filter,
            selected_stock=stock_filter,
        )

    except Exception as e:
        return _internal_error_response(
            e,
            "Unable to load admin products."
        )

    finally:
        if cursor:
            cursor.close()


@app.route("/admin/products/<int:product_id>")
def admin_product_details(product_id):
    if not admin_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT
                p.*,
                u.full_name AS seller_name,
                u.email AS seller_email,
                c.name AS category_name
            FROM products p
            INNER JOIN users u ON p.seller_id = u.id
            LEFT JOIN categories c ON p.category_id = c.id
            WHERE p.id = %s
            """,
            (product_id,)
        )

        product = cursor.fetchone()

        if not product:
            return "Product not found.", 404

        return render_template(
            "admin/products.html",
            products=[product],
            categories=[],
            total_products=1,
            active_products=1 if product.get("status") == "active" else 0,
            inactive_products=1 if product.get("status") != "active" else 0,
            low_stock_products=(
                1 if (product.get("stock") or 0) <= 5 else 0
            ),
            search="",
            selected_category=product.get("category_name") or "",
            selected_status=product.get("status") or "",
            selected_stock="",
            selected_product=product,
        )

    except Exception as e:
        return _internal_error_response(
            e,
            "Unable to load the selected product."
        )

    finally:
        if cursor:
            cursor.close()


@app.route("/admin/products/<int:product_id>/status", methods=["POST"])
def admin_product_status(product_id):
    if not admin_required():
        return redirect(url_for("login"))

    status = request.form.get("status", "").strip().lower()

    if status not in ("active", "inactive"):
        return "Invalid product status.", 400

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        cursor.execute(
            "SELECT id, name FROM products WHERE id = %s",
            (product_id,)
        )

        product = cursor.fetchone()

        if not product:
            return "Product not found.", 404

        cursor.execute(
            "UPDATE products SET status = %s WHERE id = %s",
            (status, product_id)
        )

        cursor.execute(
            """
            INSERT INTO admin_activity_logs (
                admin_id,
                action,
                target_type,
                target_id,
                description
            )
            VALUES (%s, 'product_status_update', 'product', %s, %s)
            """,
            (
                session["user_id"],
                product_id,
                f"Product '{product['name']}' status changed to {status}"
            )
        )

        db.commit()

        flash("Product status updated successfully.", "success")
        return redirect(url_for("admin_products"))

    except Exception as e:
        db.rollback()
        return _internal_error_response(
            e,
            "Unable to update product status."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# ADMIN - COMPLAINTS
# =========================================================

@app.route("/admin/complaints")
def admin_complaints():
    if not admin_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        search = request.args.get("search", "").strip()
        status_filter = request.args.get("status", "").strip().lower()
        priority_filter = request.args.get("priority", "").strip().lower()
        type_filter = request.args.get("complaint_type", "").strip().lower()

        query = """
            SELECT
                c.id,
                c.title,
                c.description,
                c.complaint_type,
                c.priority,
                c.status,
                c.admin_response,
                c.created_at,
                c.updated_at,
                c.resolved_at,
                c.order_id,
                u.full_name AS user_name,
                u.email AS user_email,
                a.full_name AS admin_name
            FROM complaints c
            INNER JOIN users u ON c.user_id = u.id
            LEFT JOIN users a ON c.assigned_admin = a.id
            WHERE 1 = 1
        """

        params = []

        if search:
            query += """
                AND (
                    c.title ILIKE %s
                    OR c.description ILIKE %s
                    OR u.full_name ILIKE %s
                    OR u.email ILIKE %s
                )
            """

            value = f"%{search}%"
            params.extend([value, value, value, value])

        if status_filter in (
            "open", "in_progress", "resolved", "closed"
        ):
            query += " AND c.status = %s"
            params.append(status_filter)

        if priority_filter in ("low", "medium", "high", "urgent"):
            query += " AND c.priority = %s"
            params.append(priority_filter)

        allowed_types = {
            "order", "product", "payment",
            "delivery", "account", "general"
        }

        if type_filter in allowed_types:
            query += " AND c.complaint_type = %s"
            params.append(type_filter)

        query += " ORDER BY c.created_at DESC, c.id DESC"

        cursor.execute(query, tuple(params))
        complaints = cursor.fetchall()

        cursor.execute("SELECT COUNT(*) AS total FROM complaints")
        total_complaints = cursor.fetchone()["total"] or 0

        cursor.execute(
            "SELECT COUNT(*) AS total FROM complaints WHERE status = 'open'"
        )
        open_complaints = cursor.fetchone()["total"] or 0

        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM complaints
            WHERE status = 'in_progress'
            """
        )
        in_progress_complaints = cursor.fetchone()["total"] or 0

        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM complaints
            WHERE status = 'resolved'
            """
        )
        resolved_complaints = cursor.fetchone()["total"] or 0

        return render_template(
            "admin/complaints.html",
            complaints=complaints,
            total_complaints=total_complaints,
            open_complaints=open_complaints,
            in_progress_complaints=in_progress_complaints,
            resolved_complaints=resolved_complaints,
            search=search,
            selected_status=status_filter,
            selected_priority=priority_filter,
            selected_complaint_type=type_filter,
            page=1,
            total_pages=1,
        )

    except Exception as e:
        return _internal_error_response(
            e,
            "Unable to load admin complaints."
        )

    finally:
        if cursor:
            cursor.close()


@app.route("/admin/complaints/<int:complaint_id>")
def admin_complaint_details(complaint_id):
    if not admin_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT
                c.*,
                u.full_name AS user_name,
                u.email AS user_email,
                a.full_name AS admin_name
            FROM complaints c
            INNER JOIN users u ON c.user_id = u.id
            LEFT JOIN users a ON c.assigned_admin = a.id
            WHERE c.id = %s
            """,
            (complaint_id,)
        )

        complaint = cursor.fetchone()

        if not complaint:
            return "Complaint not found.", 404

        return render_template(
            "admin/complaints.html",
            complaints=[complaint],
            total_complaints=1,
            open_complaints=(
                1 if complaint["status"] == "open" else 0
            ),
            in_progress_complaints=(
                1 if complaint["status"] == "in_progress" else 0
            ),
            resolved_complaints=(
                1 if complaint["status"] == "resolved" else 0
            ),
            search="",
            selected_status=complaint["status"],
            selected_priority=complaint["priority"],
            selected_complaint_type=complaint["complaint_type"],
            selected_complaint=complaint,
            page=1,
            total_pages=1,
        )

    except Exception as e:
        return _internal_error_response(
            e,
            "Unable to load the selected complaint."
        )

    finally:
        if cursor:
            cursor.close()


@app.route(
    "/admin/complaints/<int:complaint_id>/status",
    methods=["POST"]
)
def admin_complaint_status(complaint_id):
    if not admin_required():
        return redirect(url_for("login"))

    status = request.form.get("status", "").strip().lower()
    response_text = request.form.get("admin_response", "").strip()

    allowed_statuses = {
        "open", "in_progress", "resolved", "closed"
    }

    if status not in allowed_statuses:
        return "Invalid complaint status.", 400

    if len(response_text) > 5000:
        return "Admin response must be 5,000 characters or fewer.", 400

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT id
            FROM complaints
            WHERE id = %s
            FOR UPDATE
            """,
            (complaint_id,)
        )

        complaint = cursor.fetchone()

        if not complaint:
            return "Complaint not found.", 404

        cursor.execute(
            """
            UPDATE complaints
            SET
                status = %s,
                admin_response = COALESCE(
                    NULLIF(%s, ''),
                    admin_response
                ),
                assigned_admin = %s,
                resolved_at = CASE
                    WHEN %s IN ('resolved', 'closed') THEN NOW()
                    ELSE NULL
                END,
                updated_at = NOW()
            WHERE id = %s
            """,
            (
                status,
                response_text,
                session["user_id"],
                status,
                complaint_id
            )
        )

        cursor.execute(
            """
            INSERT INTO admin_activity_logs (
                admin_id,
                action,
                target_type,
                target_id,
                description
            )
            VALUES (
                %s,
                'complaint_status_update',
                'complaint',
                %s,
                %s
            )
            """,
            (
                session["user_id"],
                complaint_id,
                f"Complaint status changed to {status}"
            )
        )

        db.commit()

        flash("Complaint updated successfully.", "success")
        return redirect(url_for("admin_complaints"))

    except Exception as e:
        db.rollback()
        return _internal_error_response(
            e,
            "Unable to update complaint status."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# ADMIN - RETURNS
# =========================================================

@app.route("/admin/returns")
def admin_returns():
    if not admin_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT
                rr.id,
                rr.order_id,
                rr.buyer_id,
                rr.reason,
                rr.status,
                rr.seller_response AS decision_note,
                rr.created_at,
                u.full_name AS buyer_name,
                u.email AS buyer_email,
                o.total_amount,
                p.payment_status
            FROM return_requests rr
            INNER JOIN users u ON u.id = rr.buyer_id
            INNER JOIN orders o ON o.id = rr.order_id
            LEFT JOIN payments p ON p.order_id = rr.order_id
            ORDER BY
                CASE
                    WHEN rr.status = 'requested' THEN 0
                    ELSE 1
                END,
                rr.created_at DESC,
                rr.id DESC
            """
        )

        return_requests = cursor.fetchall()

        return render_template(
            "admin/returns.html",
            return_requests=return_requests
        )

    except Exception as e:
        return _internal_error_response(
            e,
            "Unable to load return requests."
        )

    finally:
        if cursor:
            cursor.close()


@app.route(
    "/admin/returns/<int:return_id>/status",
    methods=["POST"]
)
def admin_return_status(return_id):
    if not admin_required():
        return redirect(url_for("login"))

    status = request.form.get("status", "").strip().lower()
    decision_note = request.form.get("decision_note", "").strip()

    if status not in {"approved", "rejected"}:
        return "Return status must be approved or rejected.", 400

    if len(decision_note) > 1000:
        return "Decision note must be 1,000 characters or fewer.", 400

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT order_id, status
            FROM return_requests
            WHERE id = %s
            FOR UPDATE
            """,
            (return_id,)
        )

        return_request = cursor.fetchone()

        if not return_request:
            return "Return request not found.", 404

        if return_request["status"] != "requested":
            return "This return request has already been reviewed.", 409

        cursor.execute(
            """
            UPDATE return_requests
            SET
                status = %s,
                seller_response = NULLIF(%s, '')
            WHERE id = %s
              AND status = 'requested'
            """,
            (status, decision_note, return_id)
        )

        if cursor.rowcount != 1:
            db.rollback()
            return "This return request has already been reviewed.", 409

        cursor.execute(
            """
            INSERT INTO order_status_history (
                order_id,
                status,
                note
            )
            VALUES (%s, %s, %s)
            """,
            (
                return_request["order_id"],
                f"return_{status}",
                f"Return request {status} by administrator"
            )
        )

        cursor.execute(
            """
            INSERT INTO admin_activity_logs (
                admin_id,
                action,
                target_type,
                target_id,
                description
            )
            VALUES (
                %s,
                'return_request_review',
                'return_request',
                %s,
                %s
            )
            """,
            (
                session["user_id"],
                return_id,
                f"Return request {status}"
            )
        )

        db.commit()

        flash(f"Return request {status} successfully.", "success")
        return redirect(url_for("admin_returns"))

    except Exception as e:
        db.rollback()
        return _internal_error_response(
            e,
            "Unable to review return request."
        )

    finally:
        if cursor:
            cursor.close()


# =========================================================
# ADMIN - ANALYTICS
# =========================================================

@app.route("/admin/analytics")
def admin_analytics():
    if not admin_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        period = request.args.get("period", "30d").strip().lower()

        if period not in ("7d", "30d", "90d", "1y"):
            period = "30d"

        days_map = {
            "7d": 7,
            "30d": 30,
            "90d": 90,
            "1y": 365
        }

        days = days_map[period]

        cursor.execute("SELECT COUNT(*) AS total_users FROM users")
        total_users = cursor.fetchone()["total_users"] or 0

        cursor.execute(
            "SELECT COUNT(*) AS total_sellers FROM users WHERE role = 'seller'"
        )
        total_sellers = cursor.fetchone()["total_sellers"] or 0

        cursor.execute(
            "SELECT COUNT(*) AS total_buyers FROM users WHERE role = 'buyer'"
        )
        total_buyers = cursor.fetchone()["total_buyers"] or 0

        cursor.execute(
            "SELECT COUNT(*) AS total_products FROM products"
        )
        total_products = cursor.fetchone()["total_products"] or 0

        cursor.execute(
            "SELECT COUNT(*) AS total_orders FROM orders"
        )
        total_orders = cursor.fetchone()["total_orders"] or 0

        cursor.execute(
            """
            SELECT COALESCE(SUM(oi.subtotal), 0) AS revenue
            FROM order_items oi
            INNER JOIN orders o ON o.id = oi.order_id
            WHERE o.created_at >= NOW() - MAKE_INTERVAL(days => %s)
              AND o.status NOT IN ('cancelled', 'returned')
              AND EXISTS (
                  SELECT 1
                  FROM payments pay
                  WHERE pay.order_id = o.id
                    AND pay.payment_status = 'paid'
              )
            """,
            (days,)
        )

        revenue = float(cursor.fetchone()["revenue"] or 0)

        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM orders
            WHERE status IN ('pending', 'processing')
            """
        )
        pending_orders = cursor.fetchone()["total"] or 0

        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM seller_approvals
            WHERE status = 'approved'
            """
        )
        active_sellers = cursor.fetchone()["total"] or 0

        cursor.execute(
            """
            SELECT
                DATE(o.created_at) AS sale_date,
                COUNT(DISTINCT o.id) AS order_count,
                COALESCE(SUM(oi.subtotal), 0) AS revenue
            FROM orders o
            INNER JOIN order_items oi ON oi.order_id = o.id
            WHERE o.created_at >= NOW() - MAKE_INTERVAL(days => %s)
              AND o.status NOT IN ('cancelled', 'returned')
              AND EXISTS (
                  SELECT 1
                  FROM payments pay
                  WHERE pay.order_id = o.id
                    AND pay.payment_status = 'paid'
              )
            GROUP BY DATE(o.created_at)
            ORDER BY sale_date DESC
            """,
            (days,)
        )

        sales_data = cursor.fetchall()

        for row in sales_data:
            row["revenue"] = float(row["revenue"] or 0)

        cursor.execute(
            """
            SELECT
                status,
                COUNT(*) AS count
            FROM orders
            GROUP BY status
            ORDER BY count DESC
            """
        )

        order_status_data = cursor.fetchall()

        cursor.execute(
            """
            SELECT
                p.id,
                p.name,
                u.full_name AS seller_name,
                COALESCE(
                    SUM(
                        CASE
                            WHEN o.status NOT IN ('cancelled', 'returned')
                                 AND pay.order_id IS NOT NULL
                            THEN oi.quantity
                            ELSE 0
                        END
                    ),
                    0
                ) AS units_sold,
                COALESCE(
                    SUM(
                        CASE
                            WHEN o.status NOT IN ('cancelled', 'returned')
                                 AND pay.order_id IS NOT NULL
                            THEN oi.subtotal
                            ELSE 0
                        END
                    ),
                    0
                ) AS revenue
            FROM products p
            INNER JOIN users u ON u.id = p.seller_id
            LEFT JOIN order_items oi ON oi.product_id = p.id
            LEFT JOIN orders o ON o.id = oi.order_id
            LEFT JOIN (
                SELECT DISTINCT order_id
                FROM payments
                WHERE payment_status = 'paid'
            ) pay ON pay.order_id = o.id
            GROUP BY p.id, p.name, u.full_name
            ORDER BY revenue DESC
            LIMIT 10
            """
        )

        top_products = cursor.fetchall()

        for row in top_products:
            row["revenue"] = float(row["revenue"] or 0)

        cursor.execute(
            """
            SELECT
                u.id,
                u.full_name,
                u.email,
                COUNT(DISTINCT p.id) AS product_count,
                COALESCE(seller_revenue.order_count, 0) AS order_count,
                COALESCE(seller_revenue.revenue, 0) AS revenue
            FROM users u
            LEFT JOIN products p ON p.seller_id = u.id
            LEFT JOIN (
                SELECT
                    oi.seller_id,
                    COUNT(DISTINCT oi.order_id) AS order_count,
                    SUM(oi.subtotal) AS revenue
                FROM order_items oi
                INNER JOIN orders o ON o.id = oi.order_id
                WHERE o.status NOT IN ('cancelled', 'returned')
                  AND EXISTS (
                      SELECT 1
                      FROM payments pay
                      WHERE pay.order_id = o.id
                        AND pay.payment_status = 'paid'
                  )
                GROUP BY oi.seller_id
            ) seller_revenue
                ON seller_revenue.seller_id = u.id
            WHERE u.role = 'seller'
            GROUP BY
                u.id,
                u.full_name,
                u.email,
                seller_revenue.order_count,
                seller_revenue.revenue
            ORDER BY revenue DESC
            LIMIT 10
            """
        )

        seller_performance = cursor.fetchall()

        for row in seller_performance:
            row["revenue"] = float(row["revenue"] or 0)

        cursor.execute(
            """
            SELECT
                COUNT(*) AS total_orders,
                SUM(
                    CASE WHEN status = 'delivered'
                    THEN 1 ELSE 0 END
                ) AS delivered_orders,
                SUM(
                    CASE WHEN status = 'cancelled'
                    THEN 1 ELSE 0 END
                ) AS cancelled_orders,
                SUM(
                    CASE WHEN status = 'pending'
                    THEN 1 ELSE 0 END
                ) AS pending_orders
            FROM orders
            """
        )

        order_metrics = cursor.fetchone() or {}

        cursor.execute(
            """
            SELECT
                COUNT(*) AS total_users,
                COUNT(
                    DISTINCT CASE WHEN role = 'buyer' THEN id END
                ) AS buyer_count,
                COUNT(
                    DISTINCT CASE WHEN role = 'seller' THEN id END
                ) AS seller_count,
                COUNT(
                    DISTINCT CASE WHEN role = 'mentor' THEN id END
                ) AS mentor_count
            FROM users
            """
        )

        user_metrics = cursor.fetchone() or {}

        # Your original code ends here.
        # Send the remaining part of admin_analytics() so I can
        # complete its calculations and render_template() call.

    except Exception as e:
        return _internal_error_response(
            e,
            "Unable to load admin analytics."
        )

    finally:
        if cursor:
            cursor.close()

  
@app.route("/admin/analytics")
def admin_analytics():
    if not admin_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        period = request.args.get("period", "30d").strip().lower()

        if period not in ("7d", "30d", "90d", "1y"):
            period = "30d"

        days_map = {"7d": 7, "30d": 30, "90d": 90, "1y": 365}
        days = days_map[period]

        cursor.execute("SELECT COUNT(*) AS total_users FROM users")
        total_users = cursor.fetchone()["total_users"] or 0

        cursor.execute(
            "SELECT COUNT(*) AS total_sellers FROM users WHERE role = 'seller'"
        )
        total_sellers = cursor.fetchone()["total_sellers"] or 0

        cursor.execute(
            "SELECT COUNT(*) AS total_buyers FROM users WHERE role = 'buyer'"
        )
        total_buyers = cursor.fetchone()["total_buyers"] or 0

        cursor.execute("SELECT COUNT(*) AS total_products FROM products")
        total_products = cursor.fetchone()["total_products"] or 0

        cursor.execute("SELECT COUNT(*) AS total_orders FROM orders")
        total_orders = cursor.fetchone()["total_orders"] or 0

        cursor.execute("""
            SELECT COALESCE(SUM(oi.subtotal), 0) AS revenue
            FROM order_items oi
            INNER JOIN orders o ON o.id = oi.order_id
            WHERE o.created_at >= NOW() - MAKE_INTERVAL(days => %s)
              AND o.status NOT IN ('cancelled', 'returned')
              AND EXISTS (
                  SELECT 1
                  FROM payments pay
                  WHERE pay.order_id = o.id
                    AND pay.payment_status = 'paid'
              )
        """, (days,))

        revenue = float(cursor.fetchone()["revenue"] or 0)

        cursor.execute("""
            SELECT COUNT(*) AS total
            FROM orders
            WHERE status IN ('pending', 'processing')
        """)
        pending_orders = cursor.fetchone()["total"] or 0

        cursor.execute("""
            SELECT COUNT(*) AS total
            FROM seller_approvals
            WHERE status = 'approved'
        """)
        active_sellers = cursor.fetchone()["total"] or 0

        cursor.execute("""
            SELECT
                DATE(o.created_at) AS sale_date,
                COUNT(DISTINCT o.id) AS order_count,
                COALESCE(SUM(oi.subtotal), 0) AS revenue
            FROM orders o
            INNER JOIN order_items oi ON oi.order_id = o.id
            WHERE o.created_at >= NOW() - MAKE_INTERVAL(days => %s)
              AND o.status NOT IN ('cancelled', 'returned')
              AND EXISTS (
                  SELECT 1
                  FROM payments pay
                  WHERE pay.order_id = o.id
                    AND pay.payment_status = 'paid'
              )
            GROUP BY DATE(o.created_at)
            ORDER BY sale_date DESC
        """, (days,))

        sales_data = cursor.fetchall()

        for row in sales_data:
            row["revenue"] = float(row["revenue"] or 0)

        cursor.execute("""
            SELECT status, COUNT(*) AS count
            FROM orders
            GROUP BY status
            ORDER BY count DESC
        """)

        order_status_data = cursor.fetchall()

        cursor.execute("""
            SELECT
                p.id,
                p.name,
                u.full_name AS seller_name,
                COALESCE(SUM(
                    CASE
                        WHEN o.status NOT IN ('cancelled', 'returned')
                             AND pay.order_id IS NOT NULL
                        THEN oi.quantity
                        ELSE 0
                    END
                ), 0) AS units_sold,
                COALESCE(SUM(
                    CASE
                        WHEN o.status NOT IN ('cancelled', 'returned')
                             AND pay.order_id IS NOT NULL
                        THEN oi.subtotal
                        ELSE 0
                    END
                ), 0) AS revenue
            FROM products p
            INNER JOIN users u ON u.id = p.seller_id
            LEFT JOIN order_items oi ON oi.product_id = p.id
            LEFT JOIN orders o ON o.id = oi.order_id
            LEFT JOIN (
                SELECT DISTINCT order_id
                FROM payments
                WHERE payment_status = 'paid'
            ) pay ON pay.order_id = o.id
            GROUP BY p.id, p.name, u.full_name
            ORDER BY revenue DESC
            LIMIT 10
        """)

        top_products = cursor.fetchall()

        for row in top_products:
            row["revenue"] = float(row["revenue"] or 0)

        cursor.execute("""
            SELECT
                u.id,
                u.full_name,
                u.email,
                COUNT(DISTINCT p.id) AS product_count,
                COALESCE(sr.order_count, 0) AS order_count,
                COALESCE(sr.revenue, 0) AS revenue
            FROM users u
            LEFT JOIN products p ON p.seller_id = u.id
            LEFT JOIN (
                SELECT
                    oi.seller_id,
                    COUNT(DISTINCT oi.order_id) AS order_count,
                    SUM(oi.subtotal) AS revenue
                FROM order_items oi
                INNER JOIN orders o ON o.id = oi.order_id
                WHERE o.status NOT IN ('cancelled', 'returned')
                  AND EXISTS (
                      SELECT 1
                      FROM payments pay
                      WHERE pay.order_id = o.id
                        AND pay.payment_status = 'paid'
                  )
                GROUP BY oi.seller_id
            ) sr ON sr.seller_id = u.id
            WHERE u.role = 'seller'
            GROUP BY
                u.id, u.full_name, u.email,
                sr.order_count, sr.revenue
            ORDER BY revenue DESC
            LIMIT 10
        """)

        seller_performance = cursor.fetchall()

        for row in seller_performance:
            row["revenue"] = float(row["revenue"] or 0)

        cursor.execute("""
            SELECT
                COUNT(*) AS total_orders,
                SUM(CASE WHEN status = 'delivered' THEN 1 ELSE 0 END)
                    AS delivered_orders,
                SUM(CASE WHEN status = 'cancelled' THEN 1 ELSE 0 END)
                    AS cancelled_orders,
                SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END)
                    AS pending_orders
            FROM orders
        """)

        order_metrics = cursor.fetchone() or {}

        cursor.execute("""
            SELECT
                COUNT(*) AS total_users,
                COUNT(DISTINCT CASE WHEN role = 'buyer' THEN id END)
                    AS buyer_count,
                COUNT(DISTINCT CASE WHEN role = 'seller' THEN id END)
                    AS seller_count,
                COUNT(DISTINCT CASE WHEN role = 'mentor' THEN id END)
                    AS mentor_count
            FROM users
        """)

        user_metrics = cursor.fetchone() or {}

        return render_template(
            "admin/analytics.html",
            period=period,
            total_users=total_users,
            total_sellers=total_sellers,
            total_buyers=total_buyers,
            total_products=total_products,
            total_orders=total_orders,
            revenue=revenue,
            total_revenue=revenue,
            pending_orders=pending_orders,
            active_sellers=active_sellers,
            sales_data=sales_data,
            revenue_data=sales_data,
            order_status_data=order_status_data,
            order_status=order_status_data,
            top_products=top_products,
            seller_performance=seller_performance,
            user_metrics=user_metrics,
            order_metrics=order_metrics,
        )

    except Exception as e:
        return _internal_error_response(
            e,
            "Unable to load admin analytics."
        )

    finally:
        if cursor:
            cursor.close()

@app.route("/admin/ai-usage")
def admin_ai_usage():
    if not admin_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        period = request.args.get("period", "30d").strip().lower()
        feature = request.args.get("feature", "").strip()

        if period not in ("7d", "30d", "90d", "1y"):
            period = "30d"

        days_map = {"7d": 7, "30d": 30, "90d": 90, "1y": 365}
        days = days_map[period]

        conditions = [
            "created_at >= NOW() - MAKE_INTERVAL(days => %s)"
        ]
        params = [days]

        if feature:
            conditions.append("feature = %s")
            params.append(feature)

        where_clause = " AND ".join(conditions)

        cursor.execute(
            f"""
            SELECT COUNT(*) AS total
            FROM ai_usage_logs
            WHERE {where_clause}
            """,
            tuple(params)
        )
        total_requests = cursor.fetchone()["total"] or 0

        cursor.execute(
            f"""
            SELECT COUNT(DISTINCT user_id) AS total
            FROM ai_usage_logs
            WHERE {where_clause}
              AND user_id IS NOT NULL
            """,
            tuple(params)
        )
        active_ai_users = cursor.fetchone()["total"] or 0

        cursor.execute(
            f"""
            SELECT COUNT(*) AS total
            FROM ai_usage_logs
            WHERE {where_clause}
              AND response_status = 'success'
            """,
            tuple(params)
        )
        successful_requests = cursor.fetchone()["total"] or 0

        cursor.execute(
            f"""
            SELECT COUNT(*) AS total
            FROM ai_usage_logs
            WHERE {where_clause}
              AND response_status <> 'success'
            """,
            tuple(params)
        )
        failed_requests = cursor.fetchone()["total"] or 0

        cursor.execute(
            f"""
            SELECT
                feature,
                COUNT(*) AS request_count
            FROM ai_usage_logs
            WHERE {where_clause}
            GROUP BY feature
            ORDER BY request_count DESC
            """,
            tuple(params)
        )

        feature_usage = cursor.fetchall()

        for row in feature_usage:
            row["percentage"] = (
                row["request_count"] / total_requests * 100
                if total_requests else 0
            )

        cursor.execute(
            f"""
            SELECT
                COUNT(*) AS total_requests,
                COALESCE(AVG(response_time_ms), 0) AS avg_response_time,
                SUM(
                    CASE WHEN feature = 'business_assistant'
                    THEN 1 ELSE 0 END
                ) AS business_assistant_requests,
                SUM(
                    CASE WHEN feature IN ('marketing', 'marketing_tool')
                    THEN 1 ELSE 0 END
                ) AS marketing_requests
            FROM ai_usage_logs
            WHERE {where_clause}
            """,
            tuple(params)
        )

        performance = cursor.fetchone() or {}

        cursor.execute(
            f"""
            SELECT
                DATE(created_at) AS usage_date,
                COUNT(*) AS request_count,
                SUM(
                    CASE WHEN response_status = 'success'
                    THEN 1 ELSE 0 END
                ) AS success_count,
                SUM(
                    CASE WHEN response_status <> 'success'
                    THEN 1 ELSE 0 END
                ) AS failure_count
            FROM ai_usage_logs
            WHERE {where_clause}
            GROUP BY DATE(created_at)
            ORDER BY usage_date DESC
            """,
            tuple(params)
        )

        daily_usage = cursor.fetchall()

        recent_conditions = [
            "l.created_at >= NOW() - MAKE_INTERVAL(days => %s)"
        ]
        recent_params = [days]

        if feature:
            recent_conditions.append("l.feature = %s")
            recent_params.append(feature)

        recent_where = " AND ".join(recent_conditions)

        cursor.execute(
            f"""
            SELECT
                l.id,
                l.user_id,
                COALESCE(u.full_name, 'Deleted user') AS user_name,
                COALESCE(l.user_role, u.role, 'unknown') AS user_role,
                l.feature,
                l.request_text,
                l.response_status,
                l.response_time_ms,
                l.created_at
            FROM ai_usage_logs l
            LEFT JOIN users u ON u.id = l.user_id
            WHERE {recent_where}
            ORDER BY l.created_at DESC
            LIMIT 100
            """,
            tuple(recent_params)
        )

        recent_activity = cursor.fetchall()

        success_rate = (
            successful_requests / total_requests * 100
            if total_requests else 0
        )

        failure_rate = (
            failed_requests / total_requests * 100
            if total_requests else 0
        )

        return render_template(
            "admin/ai_usage.html",
            period=period,
            feature=feature,
            total_requests=total_requests,
            active_ai_users=active_ai_users,
            successful_requests=successful_requests,
            failed_requests=failed_requests,
            feature_usage=feature_usage,
            performance=performance,
            daily_usage=daily_usage,
            recent_activity=recent_activity,
            success_rate=success_rate,
            failure_rate=failure_rate,
            avg_response_time=(
                performance.get("avg_response_time", 0) or 0
            ),
            business_assistant_requests=(
                performance.get("business_assistant_requests", 0) or 0
            ),
            marketing_requests=(
                performance.get("marketing_requests", 0) or 0
            ),
        )

    except Exception as e:
        return _internal_error_response(
            e,
            "Unable to load AI usage records."
        )

    finally:
        if cursor:
            cursor.close()

# =========================================================
# SELLER DASHBOARD
# =========================================================

@app.route("/seller/dashboard")
def seller_dashboard():
    if not seller_required():
        return redirect(url_for("login"))

    cursor = None

    total_products = 0
    total_revenue = 0
    total_orders = 0
    total_sales = 0

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        seller_id = session["user_id"]

        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM products
            WHERE seller_id = %s
            """,
            (seller_id,)
        )

        result = cursor.fetchone()
        total_products = int(result["total"] or 0) if result else 0

        cursor.execute(
            """
            SELECT
                COUNT(DISTINCT oi.order_id) AS total_orders,
                COALESCE(SUM(oi.quantity), 0) AS total_sales,
                COALESCE(SUM(oi.subtotal), 0) AS total_revenue
            FROM order_items oi
            INNER JOIN orders o ON oi.order_id = o.id
            WHERE oi.seller_id = %s
              AND o.status NOT IN ('cancelled', 'returned')
              AND EXISTS (
                  SELECT 1
                  FROM payments pay
                  WHERE pay.order_id = o.id
                    AND pay.payment_status = 'paid'
              )
            """,
            (seller_id,)
        )

        result = cursor.fetchone()

        if result:
            total_orders = int(result["total_orders"] or 0)
            total_sales = int(result["total_sales"] or 0)
            total_revenue = float(result["total_revenue"] or 0)

    except Exception as e:
        current_app.logger.exception("Seller dashboard error.")

    finally:
        if cursor:
            cursor.close()

    return render_template(
        "seller/dashboard.html",
        seller_name=session.get("full_name", "Seller"),
        total_products=total_products,
        total_revenue=total_revenue,
        total_orders=total_orders,
        total_sales=total_sales
    )


# =========================================================
# SELLER PROFILE
# =========================================================

@app.route("/seller/profile", methods=["GET", "POST"])
def seller_profile():
    if not seller_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        seller_id = session["user_id"]

        if request.method == "POST":
            full_name = request.form.get("full_name", "").strip()
            mobile = request.form.get("mobile", "").strip()

            if not full_name or len(full_name) > 150:
                return (
                    "Full name is required and must be 150 characters or fewer.",
                    400
                )

            if not re.fullmatch(r"\d{10}", mobile):
                return "Mobile number must contain exactly 10 digits.", 400

            cursor.execute(
                """
                UPDATE users
                SET full_name = %s, mobile = %s
                WHERE id = %s AND role = 'seller'
                """,
                (full_name, mobile, seller_id)
            )

            db.commit()
            session["full_name"] = full_name

            flash("Profile updated successfully.", "success")
            return redirect(url_for("seller_profile"))

        cursor.execute(
            """
            SELECT id, full_name, email, mobile
            FROM users
            WHERE id = %s AND role = 'seller'
            """,
            (seller_id,)
        )

        user = cursor.fetchone()

        if not user:
            return "Seller account not found.", 404

        return render_template("seller/profile.html", user=user)

    except Exception as e:
        db.rollback()
        return _internal_error_response(
            e,
            "Unable to load or update the seller profile."
        )

    finally:
        if cursor:
            cursor.close()

# =========================================================
# SELLER AI ASSISTANT
# =========================================================

@app.route("/seller/ai-assistant")
def seller_ai_assistant():
    if not seller_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT id, name, description, price, stock
            FROM products
            WHERE seller_id = %s
            ORDER BY name
            """,
            (session["user_id"],)
        )

        products = cursor.fetchall()

        return render_template(
            "seller/ai_assistant.html",
            products=products
        )

    except Exception as e:
        return _internal_error_response(
            e,
            "Unable to load seller business assistant."
        )

    finally:
        if cursor:
            cursor.close()


@app.route("/seller/ai-assistant/chat", methods=["POST"])
def seller_ai_assistant_chat():
    if not seller_required():
        return {"error": "Login required."}, 401

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return {"error": "A JSON object is required."}, 400

    message = data.get("message", "")

    if not isinstance(message, str):
        return {"error": "Message must be text."}, 400

    message = message.strip()

    if not message:
        return {"error": "Message is required."}, 400

    if len(message) > 2000:
        return {"error": "Message must be 2,000 characters or fewer."}, 400

    capabilities = {
        "pricing": "Pricing strategies: calculate illustrative prices.",
        "inventory": "Inventory tips: recommend stock and restock planning.",
        "customer_service": "Customer handling: provide polite replies.",
        "government_schemes": "Government schemes: state live verification is unavailable.",
        "roadmap": "Business roadmap: give phases and milestones.",
        "finance": "Financial guidance: show clear arithmetic.",
        "business_plan": "Business planning: structure ideas.",
        "marketing": "Marketing advice: suggest relevant audiences."
    }

    category = data.get("category", "business_plan")

    if not isinstance(category, str) or category not in capabilities:
        return {"error": "Choose a supported business-assistant category."}, 400

    context = data.get("context", "")

    if not isinstance(context, str):
        return {"error": "Business context must be text."}, 400

    if len(context) > 3000:
        return {"error": "Business context must be 3,000 characters or fewer."}, 400

    cursor = None
    started = datetime.now()

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        product_context = ""
        product_id = data.get("product_id")

        if product_id not in (None, ""):
            try:
                product_id = int(product_id)
            except (TypeError, ValueError):
                return {"error": "Select a valid product."}, 400

            cursor.execute(
                """
                SELECT name, description, price, stock
                FROM products
                WHERE id = %s AND seller_id = %s
                """,
                (product_id, session["user_id"])
            )

            product = cursor.fetchone()

            if not product:
                return {
                    "error": "That product is not available in your seller account."
                }, 404

            product_context = (
                "\nAuthorized product record:\n"
                f"Name: {product['name']}\n"
                f"Description: {product['description']}\n"
                f"Price: {product['price']}\n"
                f"Current stock: {product['stock']}"
            )

        prompt = (
            f"BUSINESS TASK: {category}\n\n"
            f"SELLER QUESTION:\n{message}\n\n"
            f"ADDITIONAL BUSINESS CONTEXT:\n"
            f"{context or 'Not provided.'}\n\n"
            f"AUTHORIZED PRODUCT INFORMATION:\n"
            f"{product_context or 'No product selected.'}\n\n"
            "Provide helpful, practical business advice."
        )

        answer, response_status = gemini_ai_answer(
            prompt,
            (
                "You are SheRise Business Assistant, "
                "a practical business adviser. "
                + capabilities[category]
            ),
            temperature=0.4,
            max_output_tokens=1600,
        )

        elapsed_ms = max(
            0,
            int((datetime.now() - started).total_seconds() * 1000)
        )

        cursor.execute(
            """
            INSERT INTO ai_usage_logs (
                user_id,
                user_role,
                feature,
                request_text,
                response_status,
                response_time_ms,
                response_text,
                error_message
            )
            VALUES (%s, 'seller', 'business_assistant', %s, %s, %s, %s, %s)
            """,
            (
                session["user_id"],
                message,
                response_status,
                elapsed_ms,
                answer,
                None if answer else gemini_error_message(response_status)
            )
        )

        db.commit()

        if response_status != "success" or not answer:
            return {"error": gemini_error_message(response_status)}, 503

        return {
            "response": answer,
            "mode": "gemini"
        }

    except Exception:
        db.rollback()
        current_app.logger.exception(
            "Seller business assistant request failed."
        )
        return {
            "error": "The business assistant could not complete the request."
        }, 500

    finally:
        if cursor:
            cursor.close()

# =========================================================
# SELLER MARKETING
# =========================================================

MARKETING_OUTPUT_GUIDANCE = {
    "festival_poster": "Festival offer poster",
    "social_caption": "Social media caption",
    "instagram_post": "Instagram post",
    "whatsapp_message": "WhatsApp message",
    "facebook_ad": "Facebook advertisement",
    "product_description": "Product description",
    "hashtags": "Relevant hashtags",
    "promotional_poster": "Promotional poster",
    "product_banner": "Product banner"
}


@app.route("/seller/marketing")
def seller_marketing():
    if not seller_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT id, name, description, price
            FROM products
            WHERE seller_id = %s
            ORDER BY name
            """,
            (session["user_id"],)
        )

        products = cursor.fetchall()

        return render_template(
            "seller/marketing.html",
            products=products
        )

    except Exception as e:
        return _internal_error_response(
            e,
            "Unable to load seller marketing tool."
        )

    finally:
        if cursor:
            cursor.close()


@app.route("/seller/marketing/generate", methods=["POST"])
def seller_marketing_generate():
    if not seller_required():
        return {"error": "Login required."}, 401

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return {"error": "A JSON object is required."}, 400

    output_type = data.get("output_type", "")

    if (
        not isinstance(output_type, str)
        or output_type not in MARKETING_OUTPUT_GUIDANCE
    ):
        return {
            "error": "Choose one of the supported marketing output types."
        }, 400

    fields = {}

    for key, limit in (
        ("product_name", 150),
        ("description", 3000),
        ("target_audience", 500),
        ("offer", 500),
        ("festival", 150),
        ("platform", 100),
        ("tone", 100),
        ("language", 100),
        ("placement", 150)
    ):
        value = data.get(key, "")

        if not isinstance(value, str):
            return {
                "error": f"{key.replace('_', ' ').title()} must be text."
            }, 400

        value = value.strip()

        if len(value) > limit:
            return {
                "error": (
                    f"{key.replace('_', ' ').title()} "
                    f"must be {limit} characters or fewer."
                )
            }, 400

        fields[key] = value

    cursor = None
    started = datetime.now()

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        product_id = data.get("product_id")

        if product_id not in (None, ""):
            try:
                product_id = int(product_id)
            except (TypeError, ValueError):
                return {"error": "Select a valid product."}, 400

            cursor.execute(
                """
                SELECT name, description, price
                FROM products
                WHERE id = %s AND seller_id = %s
                """,
                (product_id, session["user_id"])
            )

            product = cursor.fetchone()

            if not product:
                return {
                    "error": "That product is not available in your seller account."
                }, 404

            fields["product_name"] = product["name"]
            fields["description"] = product["description"]
            fields["price"] = str(product["price"])

        else:
            price = data.get("price", "")

            if not isinstance(price, str):
                return {"error": "Price must be text."}, 400

            fields["price"] = price.strip()

            if len(fields["price"]) > 30:
                return {"error": "Price value is too long."}, 400

        if not fields["product_name"] or not fields["description"]:
            return {
                "error": (
                    "Enter a product name and description "
                    "or choose a product."
                )
            }, 400

        prompt = f"""
Create marketing content for the following product.

Output type: {MARKETING_OUTPUT_GUIDANCE[output_type]}
Product name: {fields['product_name']}
Description: {fields['description']}
Price: {fields['price'] or 'Not provided'}
Target audience: {fields['target_audience'] or 'Not specified'}
Offer: {fields['offer'] or 'No offer specified'}
Festival: {fields['festival'] or 'Not applicable'}
Platform: {fields['platform'] or 'Not specified'}
Tone: {fields['tone'] or 'Professional and engaging'}
Language: {fields['language'] or 'English'}
Placement: {fields['placement'] or 'Not specified'}

Create clear, attractive and useful marketing content.
Do not invent product claims, discounts or guarantees.
"""

        answer, response_status = gemini_ai_answer(
            prompt,
            "You are SheRise Marketing Assistant.",
            temperature=0.75,
            max_output_tokens=1600,
        )

        elapsed_ms = max(
            0,
            int((datetime.now() - started).total_seconds() * 1000)
        )

        cursor.execute(
            """
            INSERT INTO ai_usage_logs (
                user_id,
                user_role,
                feature,
                request_text,
                response_status,
                response_time_ms,
                response_text,
                error_message
            )
            VALUES (%s, 'seller', 'marketing_tool', %s, %s, %s, %s, %s)
            """,
            (
                session["user_id"],
                output_type,
                response_status,
                elapsed_ms,
                answer,
                None if answer else gemini_error_message(response_status)
            )
        )

        db.commit()

        if response_status != "success" or not answer:
            return {"error": gemini_error_message(response_status)}, 503

        return {
            "content": answer,
            "output_type": output_type,
            "mode": "gemini"
        }

    except Exception:
        db.rollback()
        current_app.logger.exception(
            "Seller marketing generation failed."
        )
        return {
            "error": "Marketing content could not be generated."
        }, 500

    finally:
        if cursor:
            cursor.close()
    
# =========================================================
# SELLER - CUSTOMER ORDERS
# =========================================================

@app.route("/seller/orders")
def seller_orders():
    if not seller_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        seller_id = session["user_id"]
        status_filter = request.args.get("status", "").strip().lower()

        allowed_statuses = {
            "pending",
            "processing",
            "shipped",
            "out_for_delivery",
            "delivered",
            "cancelled",
            "returned"
        }

        query = """
            SELECT
                o.id,
                o.created_at,
                o.status,
                o.shipping_address,
                u.full_name AS customer_name,
                u.email AS customer_email,
                u.mobile AS customer_mobile,
                (
                    SELECT pay.payment_method
                    FROM payments pay
                    WHERE pay.order_id = o.id
                    ORDER BY pay.id DESC
                    LIMIT 1
                ) AS payment_method,
                (
                    SELECT pay.payment_status
                    FROM payments pay
                    WHERE pay.order_id = o.id
                    ORDER BY pay.id DESC
                    LIMIT 1
                ) AS payment_status,
                COALESCE(SUM(oi.subtotal), 0) AS seller_order_total
            FROM orders o
            INNER JOIN order_items oi ON o.id = oi.order_id
            INNER JOIN users u ON o.buyer_id = u.id
            WHERE oi.seller_id = %s
        """

        params = [seller_id]

        if status_filter in allowed_statuses:
            query += " AND o.status = %s"
            params.append(status_filter)

        query += """
            GROUP BY
                o.id,
                o.created_at,
                o.status,
                o.shipping_address,
                u.full_name,
                u.email,
                u.mobile
            ORDER BY o.created_at DESC
        """

        cursor.execute(query, tuple(params))
        orders = cursor.fetchall()

        for order in orders:
            cursor.execute(
                """
                SELECT
                    oi.id,
                    oi.quantity,
                    oi.unit_price,
                    oi.subtotal,
                    oi.fulfillment_status,
                    p.name AS product_name,
                    p.image_url
                FROM order_items oi
                INNER JOIN products p ON oi.product_id = p.id
                WHERE oi.order_id = %s
                  AND oi.seller_id = %s
                ORDER BY oi.id
                """,
                (order["id"], seller_id)
            )

            order["items"] = cursor.fetchall()
            order["total_amount"] = float(
                order["seller_order_total"] or 0
            )

        total_orders = len(orders)

        pending_orders = sum(
            1 for order in orders
            if order["status"] == "pending"
        )

        shipped_orders = sum(
            1 for order in orders
            if order["status"] == "shipped"
        )

        delivered_orders = sum(
            1 for order in orders
            if order["status"] == "delivered"
        )

        return render_template(
            "seller/orders.html",
            orders=orders,
            total_orders=total_orders,
            pending_orders=pending_orders,
            shipped_orders=shipped_orders,
            delivered_orders=delivered_orders,
            selected_status=status_filter
        )

    except Exception as e:
        return _internal_error_response(
            e,
            "Unable to load seller orders."
        )

    finally:
        if cursor:
            cursor.close()


@app.route(
    "/seller/orders/<int:order_id>/items/<int:item_id>/fulfillment",
    methods=["POST"]
)
def seller_update_fulfillment(order_id, item_id):
    if not seller_required():
        return redirect(url_for("login"))

    new_status = request.form.get("status", "").strip().lower()

    allowed_transitions = {
        "pending": {"processing"},
        "processing": {"shipped"},
        "shipped": {"out_for_delivery", "delivered"},
        "out_for_delivery": {"delivered"},
    }

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT id, status
            FROM orders
            WHERE id = %s
            FOR UPDATE
            """,
            (order_id,)
        )

        order = cursor.fetchone()

        if not order:
            return "Order not found.", 404

        if order["status"] in {
            "cancelled", "canceled", "returned"
        }:
            return "This order can no longer be fulfilled.", 409

        cursor.execute(
            """
            SELECT id, fulfillment_status
            FROM order_items
            WHERE id = %s
              AND order_id = %s
              AND seller_id = %s
            FOR UPDATE
            """,
            (item_id, order_id, session["user_id"])
        )

        item = cursor.fetchone()

        if not item:
            return "Order item not found.", 404

        current_status = item["fulfillment_status"] or "pending"

        if new_status not in allowed_transitions.get(current_status, set()):
            return "That fulfillment status transition is not allowed.", 400

        cursor.execute(
            """
            UPDATE order_items
            SET fulfillment_status = %s
            WHERE id = %s
              AND order_id = %s
              AND seller_id = %s
            """,
            (
                new_status,
                item_id,
                order_id,
                session["user_id"]
            )
        )

        cursor.execute(
            """
            SELECT fulfillment_status
            FROM order_items
            WHERE order_id = %s
            """,
            (order_id,)
        )

        item_statuses = [
            row["fulfillment_status"] or "pending"
            for row in cursor.fetchall()
        ]

        status_priority = {
            "pending": 0,
            "processing": 1,
            "shipped": 2,
            "out_for_delivery": 3,
            "delivered": 4
        }

        if item_statuses and all(
            status == "delivered" for status in item_statuses
        ):
            aggregate_status = "delivered"
        else:
            aggregate_status = min(
                (
                    status for status in item_statuses
                    if status != "delivered"
                ),
                key=lambda status: status_priority.get(status, 0),
                default="pending"
            )

        if aggregate_status != order["status"]:
            cursor.execute(
                """
                UPDATE orders
                SET status = %s
                WHERE id = %s
                """,
                (aggregate_status, order_id)
            )

            cursor.execute(
                """
                INSERT INTO order_status_history (
                    order_id,
                    status,
                    note
                )
                VALUES (%s, %s, %s)
                """,
                (
                    order_id,
                    aggregate_status,
                    f"Seller updated an item to {new_status}"
                )
            )

        if aggregate_status == "delivered":
            cursor.execute(
                """
                UPDATE payments
                SET
                    payment_status = 'paid',
                    paid_at = COALESCE(paid_at, NOW())
                WHERE order_id = %s
                  AND payment_method IN ('Cash on Delivery', 'cod')
                  AND payment_status = 'pending'
                """,
                (order_id,)
            )

        db.commit()

        flash("Order fulfillment updated successfully.", "success")
        return redirect(url_for("seller_orders"))

    except Exception as e:
        db.rollback()
        return _internal_error_response(
            e,
            "Unable to update fulfillment status."
        )

    finally:
        if cursor:
            cursor.close()

# =========================================================
# SELLER - CUSTOM PRODUCT REQUESTS
# =========================================================

@app.route("/seller/custom-requests")
def seller_custom_requests():
    if not seller_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        seller_id = session["user_id"]
        status_filter = request.args.get("status", "").strip().lower()

        allowed_statuses = {
            "pending", "quoted", "accepted",
            "rejected", "completed", "cancelled"
        }

        query = """
            SELECT
                cr.id,
                cr.seller_id,
                cr.product_name,
                cr.description,
                cr.budget,
                cr.quotation_amount,
                cr.seller_response,
                cr.status,
                cr.created_at,
                u.full_name AS customer_name,
                u.email AS email,
                u.mobile AS mobile
            FROM custom_requests cr
            INNER JOIN users u ON cr.buyer_id = u.id
            WHERE (
                cr.seller_id = %s
                OR cr.seller_id IS NULL
            )
        """

        params = [seller_id]

        if status_filter in allowed_statuses:
            query += " AND cr.status = %s"
            params.append(status_filter)

        query += " ORDER BY cr.created_at DESC"

        cursor.execute(query, tuple(params))
        custom_requests = cursor.fetchall()

        total_requests = len(custom_requests)

        pending_requests = sum(
            1 for item in custom_requests
            if item["status"] == "pending"
        )

        quoted_requests = sum(
            1 for item in custom_requests
            if item["status"] == "quoted"
        )

        accepted_requests = sum(
            1 for item in custom_requests
            if item["status"] == "accepted"
        )

        return render_template(
            "seller/custom_requests.html",
            custom_requests=custom_requests,
            total_requests=total_requests,
            pending_requests=pending_requests,
            quoted_requests=quoted_requests,
            accepted_requests=accepted_requests,
            selected_status=status_filter
        )

    except Exception as e:
        return _internal_error_response(
            e,
            "Unable to load seller custom requests."
        )

    finally:
        if cursor:
            cursor.close()


@app.route(
    "/seller/custom-requests/<int:request_id>/respond",
    methods=["POST"]
)
def seller_custom_request_response(request_id):
    if not seller_required():
        return redirect(url_for("login"))

    quotation_amount = request.form.get(
        "quotation_amount", ""
    ).strip()

    seller_response = request.form.get(
        "seller_response", ""
    ).strip()

    status = request.form.get(
        "status", "quoted"
    ).strip().lower()

    if not seller_response or len(seller_response) > 5000:
        return "Please enter a response of 1 to 5,000 characters.", 400

    if status not in {"quoted", "rejected"}:
        return "Choose either Send Quote or Reject Request.", 400

    quotation_value = None

    if quotation_amount:
        try:
            quotation_value = Decimal(quotation_amount)

        except (ValueError, InvalidOperation):
            return "Quotation amount must be a valid number.", 400

        if (
            not quotation_value.is_finite()
            or quotation_value <= 0
            or quotation_value > Decimal("99999999.99")
        ):
            return "Quotation must be a valid positive amount.", 400

        if quotation_value.as_tuple().exponent < -2:
            return "Quotation can have a maximum of two decimal places.", 400

    if status == "quoted" and quotation_value is None:
        return "Enter a quotation amount before sending a quote.", 400

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        seller_id = session["user_id"]

        cursor.execute(
            """
            SELECT id, seller_id, status
            FROM custom_requests
            WHERE id = %s
            FOR UPDATE
            """,
            (request_id,)
        )

        custom_request = cursor.fetchone()

        if not custom_request:
            return "Custom request not found.", 404

        if (
            custom_request["seller_id"] is not None
            and custom_request["seller_id"] != seller_id
        ):
            return "This request is assigned to another seller.", 403

        if custom_request["status"] != "pending":
            return "This custom request is no longer available.", 409

        cursor.execute(
            """
            UPDATE custom_requests
            SET
                seller_id = %s,
                quotation_amount = %s,
                seller_response = %s,
                status = %s
            WHERE id = %s
              AND (
                  seller_id = %s
                  OR seller_id IS NULL
              )
              AND status = 'pending'
            """,
            (
                seller_id,
                quotation_value,
                seller_response,
                status,
                request_id,
                seller_id
            )
        )

        if cursor.rowcount != 1:
            db.rollback()
            return "This custom request was updated by another seller.", 409

        db.commit()

        flash("Your response was submitted successfully.", "success")
        return redirect(url_for("seller_custom_requests"))

    except Exception as e:
        db.rollback()
        return _internal_error_response(
            e,
            "Unable to respond to the seller custom request."
        )

    finally:
        if cursor:
            cursor.close()



# =========================================================
# SELLER - SALES REPORT
# =========================================================

@app.route("/seller/sales")
def seller_sales():
    if not seller_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)
        seller_id = session["user_id"]

        start_date = request.args.get("start_date", "").strip()
        end_date = request.args.get("end_date", "").strip()
        status_filter = request.args.get("status", "").strip().lower()

        allowed_statuses = {
            "pending", "processing", "shipped",
            "out_for_delivery", "delivered",
            "completed", "cancelled", "returned"
        }

        if status_filter and status_filter not in allowed_statuses:
            return "Invalid order status.", 400

        try:
            start_value = datetime.strptime(start_date, "%Y-%m-%d").date() if start_date else None
            end_value = datetime.strptime(end_date, "%Y-%m-%d").date() if end_date else None
        except ValueError:
            return "Dates must be in YYYY-MM-DD format.", 400

        if start_value and end_value and start_value > end_value:
            return "Start date cannot be after end date.", 400

        query = """
            SELECT
                orders.id AS order_id,
                orders.created_at,
                orders.status,
                products.name AS product_name,
                order_items.quantity,
                order_items.unit_price,
                order_items.subtotal,
                (
                    SELECT payments.payment_status
                    FROM payments
                    WHERE payments.order_id = orders.id
                    ORDER BY payments.id DESC
                    LIMIT 1
                ) AS payment_status
            FROM order_items
            INNER JOIN orders
                ON order_items.order_id = orders.id
            INNER JOIN products
                ON order_items.product_id = products.id
            WHERE order_items.seller_id = %s
        """
        params = [seller_id]

        if not status_filter:
            query += " AND orders.status NOT IN ('cancelled', 'returned')"

        if start_value:
            query += " AND DATE(orders.created_at) >= %s"
            params.append(start_value)

        if end_value:
            query += " AND DATE(orders.created_at) <= %s"
            params.append(end_value)

        if status_filter:
            query += " AND orders.status = %s"
            params.append(status_filter)

        query += " ORDER BY orders.created_at DESC, orders.id DESC"

        cursor.execute(query, tuple(params))
        sales = cursor.fetchall()

        paid_sales = [
            item for item in sales
            if item["payment_status"] == "paid"
        ]

        total_sales = sum(
            (Decimal(str(item["subtotal"] or 0)) for item in paid_sales),
            Decimal("0.00")
        )

        total_orders = len({
            item["order_id"] for item in paid_sales
        })

        total_units = sum(
            int(item["quantity"] or 0)
            for item in paid_sales
        )

        average_order_value = (
            total_sales / total_orders
            if total_orders else Decimal("0.00")
        )

        product_summary = {}

        for item in paid_sales:
            product_name = item["product_name"]

            if product_name not in product_summary:
                product_summary[product_name] = {
                    "product_name": product_name,
                    "quantity_sold": 0,
                    "revenue": Decimal("0.00")
                }

            product_summary[product_name]["quantity_sold"] += int(
                item["quantity"] or 0
            )
            product_summary[product_name]["revenue"] += Decimal(
                str(item["subtotal"] or 0)
            )

        product_sales = sorted(
            product_summary.values(),
            key=lambda item: item["revenue"],
            reverse=True
        )

        best_selling_product = (
            product_sales[0]["product_name"]
            if product_sales else "No sales yet"
        )

        highest_product_sales = (
            product_sales[0]["revenue"]
            if product_sales else Decimal("0.00")
        )

        completed_orders = len({
            item["order_id"]
            for item in paid_sales
            if item["status"] in ("delivered", "completed")
        })

        return render_template(
            "seller/sales.html",
            sales=sales,
            product_sales=product_sales,
            total_sales=total_sales,
            total_orders=total_orders,
            total_units=total_units,
            average_order_value=average_order_value,
            best_selling_product=best_selling_product,
            highest_product_sales=highest_product_sales,
            completed_orders=completed_orders,
            start_date=start_date,
            end_date=end_date,
            selected_status=status_filter
        )

    except Exception as e:
        return _internal_error_response(
            e, "Unable to load the seller sales report."
        )
    finally:
        if cursor:
            cursor.close()


# =========================================================
# SELLER - REVENUE ANALYTICS
# =========================================================

@app.route("/seller/revenue")
def seller_revenue():
    if not seller_required():
        return redirect(url_for("login"))

    cursor = None

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)
        seller_id = session["user_id"]

        start_date = request.args.get("start_date", "").strip()
        end_date = request.args.get("end_date", "").strip()
        period = request.args.get("period", "monthly").strip().lower()

        if period not in ("daily", "weekly", "monthly", "yearly"):
            period = "monthly"

        try:
            start_value = datetime.strptime(start_date, "%Y-%m-%d").date() if start_date else None
            end_value = datetime.strptime(end_date, "%Y-%m-%d").date() if end_date else None
        except ValueError:
            return "Dates must be in YYYY-MM-DD format.", 400

        if start_value and end_value and start_value > end_value:
            return "Start date cannot be after end date.", 400

        date_condition = """
            AND orders.status NOT IN ('cancelled', 'returned')
            AND EXISTS (
                SELECT 1
                FROM payments
                WHERE payments.order_id = orders.id
                  AND payments.payment_status = 'paid'
            )
        """
        date_params = [seller_id]

        if start_value:
            date_condition += " AND DATE(orders.created_at) >= %s"
            date_params.append(start_value)

        if end_value:
            date_condition += " AND DATE(orders.created_at) <= %s"
            date_params.append(end_value)

        summary_query = f"""
            SELECT
                COALESCE(SUM(order_items.subtotal), 0) AS gross_revenue,
                COUNT(DISTINCT orders.id) AS total_orders,
                COALESCE(SUM(order_items.quantity), 0) AS total_units
            FROM order_items
            INNER JOIN orders
                ON order_items.order_id = orders.id
            WHERE order_items.seller_id = %s
            {date_condition}
        """

        cursor.execute(summary_query, tuple(date_params))
        revenue_summary = cursor.fetchone() or {}

        total_revenue = Decimal(
            str(revenue_summary.get("gross_revenue") or 0)
        )
        total_orders = int(revenue_summary.get("total_orders") or 0)
        total_units = int(revenue_summary.get("total_units") or 0)

        average_order_value = (
            total_revenue / total_orders
            if total_orders else Decimal("0.00")
        )

        cursor.execute(f"""
            SELECT
                DATE_TRUNC(%s, orders.created_at) AS revenue_period,
                COALESCE(SUM(order_items.subtotal), 0) AS revenue,
                COUNT(DISTINCT orders.id) AS order_count
            FROM order_items
            INNER JOIN orders
                ON order_items.order_id = orders.id
            WHERE order_items.seller_id = %s
            {date_condition}
            GROUP BY DATE_TRUNC(%s, orders.created_at)
            ORDER BY revenue_period
        """, (period, *date_params, period))

        revenue_data = cursor.fetchall()

        for row in revenue_data:
            row["revenue"] = float(row["revenue"] or 0)

        cursor.execute(f"""
            SELECT
                products.id,
                products.name,
                COALESCE(SUM(order_items.quantity), 0) AS units_sold,
                COALESCE(SUM(order_items.subtotal), 0) AS revenue
            FROM order_items
            INNER JOIN orders
                ON order_items.order_id = orders.id
            INNER JOIN products
                ON order_items.product_id = products.id
            WHERE order_items.seller_id = %s
            {date_condition}
            GROUP BY products.id, products.name
            ORDER BY revenue DESC
            LIMIT 10
        """, tuple(date_params))

        top_products = cursor.fetchall()

        for product in top_products:
            product["revenue"] = float(product["revenue"] or 0)

        return render_template(
            "seller/revenue.html",
            total_revenue=float(total_revenue),
            net_revenue=float(total_revenue),
            total_orders=total_orders,
            total_units=total_units,
            average_order_value=float(average_order_value),
            product_revenue=float(total_revenue),
            custom_request_revenue=0,
            other_revenue=0,
            refund_amount=0,
            product_percentage=100 if total_revenue > 0 else 0,
            custom_percentage=0,
            other_percentage=0,
            refund_percentage=0,
            gross_revenue=float(total_revenue),
            deductions=0,
            revenue_growth=0,
            revenue_data=revenue_data,
            top_products=top_products,
            start_date=start_date,
            end_date=end_date,
            period=period
        )

    except Exception as e:
        return _internal_error_response(
            e, "Unable to load revenue analytics."
        )
    finally:
        if cursor:
            cursor.close()


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout", methods=["GET", "POST"])
def logout():
    if request.method == "GET":
        return render_template("auth/logout.html")

    session.clear()
    return redirect(url_for("login"))


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":
    app.run(
        debug=os.getenv("FLASK_DEBUG", "false").strip().lower()
        in {"1", "true", "yes", "on"}
    )
