import os
import secrets
import csv
import io
import json
import math
import hashlib
import re
import smtplib

from email.message import EmailMessage
from functools import wraps
from decimal import Decimal, InvalidOperation
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request as UrlRequest, urlopen

import pymysql
from flask import (
    Flask,
    Response,
    abort,
    flash,
    g,
    redirect,
    render_template,
    send_from_directory,
    request,
    session,
    url_for,
)
from werkzeug.security import (
    check_password_hash,
    generate_password_hash,
)

from collections import defaultdict
from sklearn.ensemble import RandomForestRegressor

BASE_DIR = Path(__file__).resolve().parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static",
)

# Load saved HTML changes while developing the system.
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Store a private session-signing key locally.
instance_dir = BASE_DIR / "instance"
instance_dir.mkdir(exist_ok=True)

key_file = instance_dir / "secret-key.txt"

if not key_file.exists():
    key_file.write_text(
        secrets.token_hex(32),
        encoding="utf-8",
    )

app.config.update(
    SECRET_KEY=key_file.read_text(encoding="utf-8").strip(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)


def get_db():
    if "db" not in g:
        g.db = pymysql.connect(
            host="127.0.0.1",
            user="root",
            password=os.environ.get("MYSQL_PASSWORD", ""),
            database="ai_sales_system",
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=True,
        )

    return g.db


@app.teardown_appcontext
def close_db(error=None):
    database = g.pop("db", None)

    if database is not None:
        database.close()


@app.before_request
def load_user():
    g.user = None

    user_id = session.get("user_id")

    if user_id is not None:
        with get_db().cursor() as cursor:
            cursor.execute(
                """
                SELECT user_id, username, role
                FROM users
                WHERE user_id = %s
                """,
                (user_id,),
            )

            g.user = cursor.fetchone()

        if g.user is None:
            session.clear()


def admin_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login"))

        if g.user["role"] != "Admin":
            abort(403)

        return view(*args, **kwargs)

    return wrapped_view

def business_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login"))

        if g.user["role"] != "Business":
            abort(403)

        return view(*args, **kwargs)

    return wrapped_view

def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)

    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


def validate_csrf():
    expected = session.get("csrf_token", "")
    received = request.form.get("csrf_token", "")

    if not expected or not secrets.compare_digest(expected, received):
        abort(
            400,
            description="The form expired. Reload the page and try again.",
        )

TRUSTED_DEVICE_COOKIE = "foodcast_trusted_device"
TRUSTED_DEVICE_DAYS = 30


def hash_device_token(token):
    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


def device_is_trusted(user_id):
    token = request.cookies.get(
        TRUSTED_DEVICE_COOKIE,
        "",
    )

    if not token or len(token) > 200:
        return False

    token_hash = hash_device_token(token)

    with get_db().cursor() as cursor:
        cursor.execute(
            """
            DELETE FROM trusted_devices
            WHERE expires_at <= UTC_TIMESTAMP()
            """
        )

        cursor.execute(
            """
            SELECT trusted_device_id
            FROM trusted_devices
            WHERE user_id = %s
              AND token_hash = %s
              AND expires_at > UTC_TIMESTAMP()
            LIMIT 1
            """,
            (
                user_id,
                token_hash,
            ),
        )

        trusted_device = cursor.fetchone()

        if trusted_device:
            cursor.execute(
                """
                UPDATE trusted_devices
                SET last_used_at = UTC_TIMESTAMP()
                WHERE trusted_device_id = %s
                """,
                (
                    trusted_device[
                        "trusted_device_id"
                    ],
                ),
            )

    return trusted_device is not None


def create_trusted_device(user_id):
    token = secrets.token_urlsafe(48)
    token_hash = hash_device_token(token)

    with get_db().cursor() as cursor:
        cursor.execute(
            """
            INSERT INTO trusted_devices (
                user_id,
                token_hash,
                expires_at
            )
            VALUES (
                %s,
                %s,
                DATE_ADD(
                    UTC_TIMESTAMP(),
                    INTERVAL 30 DAY
                )
            )
            """,
            (
                user_id,
                token_hash,
            ),
        )

    return token


def add_trusted_device_cookie(response, token):
    response.set_cookie(
        TRUSTED_DEVICE_COOKIE,
        token,
        max_age=TRUSTED_DEVICE_DAYS * 24 * 60 * 60,
        httponly=True,
        samesite="Lax",
        secure=False,
    )

    return response

@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user is not None:
        if g.user["role"] == "Admin":
            return redirect(
                url_for("admin_dashboard")
            )

        return redirect(
            url_for("business_dashboard")
        )

    error = None

    if request.method == "POST":
        validate_csrf()

        username = request.form.get(
            "username",
            "",
        ).strip()

        password = request.form.get(
            "password",
            "",
        )

        with get_db().cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    user_id,
                    username,
                    email,
                    password_hash,
                    role
                FROM users
                WHERE username = %s
                LIMIT 1
                """,
                (username,),
            )

            user = cursor.fetchone()

        if (
            not user
            or not check_password_hash(
                user["password_hash"],
                password,
            )
        ):
            error = "Incorrect username or password."

        elif user["role"] not in (
            "Admin",
            "Business",
        ):
            error = (
                "This account does not have access "
                "to the system."
            )

        elif (
            not user["email"]
            or device_is_trusted(user["user_id"])
        ):
            session.clear()
            session["user_id"] = user["user_id"]

            if user["role"] == "Admin":
                return redirect(
                    url_for("admin_dashboard")
                )

            return redirect(
                url_for("business_dashboard")
            )

        else:
            login_code = (
                f"{secrets.randbelow(1000000):06d}"
            )

            try:
                send_verification_code(
                    user["email"],
                    login_code,
                    "login",
                )

            except RuntimeError:
                app.logger.exception(
                    "FoodCast email settings are missing."
                )

                error = (
                    "The email verification service "
                    "is not configured."
                )

            except smtplib.SMTPAuthenticationError:
                app.logger.exception(
                    "FoodCast could not authenticate "
                    "with the sender email account."
                )

                error = (
                    "The email verification service "
                    "could not sign in."
                )

            except (OSError, smtplib.SMTPException):
                app.logger.exception(
                    "The login verification code "
                    "could not be sent."
                )

                error = (
                    "The verification code could not "
                    "be sent. Please try again later."
                )

            else:
                session.clear()

                session["pending_login"] = {
                    "user_id": user["user_id"],
                    "role": user["role"],
                    "email": user["email"],
                    "code_hash": generate_password_hash(
                        login_code
                    ),
                    "expires_at": (
                        datetime.now(timezone.utc)
                        + timedelta(minutes=10)
                    ).isoformat(),
                    "attempts": 0,
                }

                return redirect(
                    url_for("verify_login_mfa")
                )

    return render_template(
        "auth/login.html",
        error=error,
    )


@app.route("/login/verify", methods=["GET", "POST"])
def verify_login_mfa():
    pending = session.get("pending_login")

    if not pending:
        return redirect(url_for("login"))

    error = None

    try:
        expires_at = datetime.fromisoformat(
            pending["expires_at"]
        )
    except (KeyError, TypeError, ValueError):
        session.clear()
        return redirect(url_for("login"))

    if datetime.now(timezone.utc) >= expires_at:
        session.clear()

        flash(
            "Your sign-in code expired. Please sign in again.",
            "login_error",
        )

        return redirect(url_for("login"))

    if request.method == "POST":
        validate_csrf()

        code = request.form.get("verification_code", "").strip()

        if not re.fullmatch(r"\d{6}", code):
            error = "Enter the six-digit code sent to your email."

        elif pending.get("attempts", 0) >= 5:
            session.clear()

            flash(
                "Too many incorrect attempts. Please sign in again.",
                "login_error",
            )

            return redirect(url_for("login"))

        elif not check_password_hash(
            pending["code_hash"],
            code,
        ):
            pending["attempts"] = (
                pending.get("attempts", 0) + 1
            )

            session["pending_login"] = pending
            session.modified = True

            error = "That verification code is incorrect."

        else:
            user_id = pending["user_id"]
            role = pending["role"]

            device_token = create_trusted_device(
                user_id
            )

            session.clear()
            session["user_id"] = user_id

            if role == "Admin":
                response = redirect(
                    url_for("admin_dashboard")
                )
            else:
                response = redirect(
                    url_for("business_dashboard")
                )

            return add_trusted_device_cookie(
                response,
                device_token,
            )

    return render_template(
        "auth/verify_login.html",
        email=pending["email"],
        error=error,
    )

EMAIL_PATTERN = re.compile(
    r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,63}$"
)


def is_valid_email(email):
    return bool(
        3 <= len(email) <= 254
        and EMAIL_PATTERN.fullmatch(email)
    )


def password_is_strong(password):
    return (
        12 <= len(password) <= 128
        and any(character.islower() for character in password)
        and any(character.isupper() for character in password)
        and any(character.isdigit() for character in password)
        and any(not character.isalnum() for character in password)
    )


def send_verification_code(recipient, code, purpose):
    sender = os.environ.get("FOODCAST_EMAIL", "").strip()
    app_password = os.environ.get(
        "FOODCAST_EMAIL_APP_PASSWORD", ""
    ).replace(" ", "")

    if not sender or not app_password:
        raise RuntimeError(
            "FoodCast email settings have not been configured."
        )

    if purpose == "login":
        subject = "Your FoodCast sign-in code"
        introduction = (
            "A sign-in attempt was made for your "
            "FoodCast account."
        )

    elif purpose == "password-reset":
        subject = "Your FoodCast password-reset code"
        introduction = (
            "A password reset was requested for your "
            "FoodCast account."
        )

    elif purpose == "email-change":
        subject = "Verify your new FoodCast email address"
        introduction = (
            "Use this code to confirm your new email address."
        )

    else:
        subject = "Your FoodCast account verification code"
        introduction = (
            "Use this code to finish creating your "
            "FoodCast account."
        )
        
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = recipient

    message.set_content(
        f"""{introduction}

Your verification code is: {code}

This code expires in 10 minutes.

If you did not request this code, you can ignore this email.
"""
    )

    with smtplib.SMTP("smtp.gmail.com", 587, timeout=15) as smtp:
        smtp.starttls()
        smtp.login(sender, app_password)
        smtp.send_message(message)

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if g.user is not None:
        return redirect(url_for("home"))

    error = None
    values = {
        "username": "",
        "email": "",
    }

    if request.method == "POST":
        validate_csrf()

        values["username"] = request.form.get(
            "username", ""
        ).strip()

        values["email"] = request.form.get(
            "email", ""
        ).strip().lower()

        if not values["username"]:
            error = "Enter your username."

        elif not is_valid_email(values["email"]):
            error = "Enter a valid email address."

        else:
            with get_db().cursor() as cursor:
                cursor.execute(
                    """
                    SELECT user_id, username, email
                    FROM users
                    WHERE username = %s
                      AND email = %s
                    LIMIT 1
                    """,
                    (
                        values["username"],
                        values["email"],
                    ),
                )

                user = cursor.fetchone()

            if not user:
                error = (
                    "The username and email address do not match "
                    "an account."
                )

        if error is None:
            reset_code = f"{secrets.randbelow(1000000):06d}"

            try:
                send_verification_code(
                    user["email"],
                    reset_code,
                    "password-reset",
                )

            except RuntimeError:
                app.logger.exception(
                    "FoodCast email settings are missing."
                )
                error = (
                    "The email service is not configured."
                )

            except smtplib.SMTPAuthenticationError:
                app.logger.exception(
                    "FoodCast could not authenticate with email."
                )
                error = (
                    "The email service could not sign in."
                )

            except (OSError, smtplib.SMTPException):
                app.logger.exception(
                    "Password-reset email could not be sent."
                )
                error = (
                    "The reset code could not be sent. "
                    "Please try again later."
                )

            else:
                session.clear()

                session["pending_password_reset"] = {
                    "user_id": user["user_id"],
                    "email": user["email"],
                    "code_hash": generate_password_hash(
                        reset_code
                    ),
                    "expires_at": (
                        datetime.now(timezone.utc)
                        + timedelta(minutes=10)
                    ).isoformat(),
                    "attempts": 0,
                }

                return redirect(
                    url_for("verify_password_reset")
                )

    return render_template(
        "auth/forgot_password.html",
        error=error,
        values=values,
    )


@app.route(
    "/forgot-password/verify",
    methods=["GET", "POST"],
)
def verify_password_reset():
    pending = session.get("pending_password_reset")

    if not pending:
        return redirect(url_for("forgot_password"))

    error = None

    try:
        expires_at = datetime.fromisoformat(
            pending["expires_at"]
        )
    except (KeyError, TypeError, ValueError):
        session.clear()
        return redirect(url_for("forgot_password"))

    if datetime.now(timezone.utc) >= expires_at:
        session.clear()
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        validate_csrf()

        code = request.form.get(
            "verification_code", ""
        ).strip()

        if not re.fullmatch(r"\d{6}", code):
            error = "Enter the six-digit code from your email."

        elif pending.get("attempts", 0) >= 5:
            session.clear()
            return redirect(url_for("forgot_password"))

        elif not check_password_hash(
            pending["code_hash"],
            code,
        ):
            pending["attempts"] = (
                pending.get("attempts", 0) + 1
            )

            session["pending_password_reset"] = pending
            session.modified = True

            error = "That verification code is incorrect."

        else:
            user_id = pending["user_id"]

            session.clear()

            session["authorized_password_reset"] = {
                "user_id": user_id,
                "expires_at": (
                    datetime.now(timezone.utc)
                    + timedelta(minutes=10)
                ).isoformat(),
            }

            return redirect(url_for("reset_password"))

    return render_template(
        "auth/verify_password_reset.html",
        email=pending["email"],
        error=error,
    )


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    authorization = session.get(
        "authorized_password_reset"
    )

    if not authorization:
        return redirect(url_for("forgot_password"))

    try:
        expires_at = datetime.fromisoformat(
            authorization["expires_at"]
        )
    except (KeyError, TypeError, ValueError):
        session.clear()
        return redirect(url_for("forgot_password"))

    if datetime.now(timezone.utc) >= expires_at:
        session.clear()
        return redirect(url_for("forgot_password"))

    error = None

    if request.method == "POST":
        validate_csrf()

        password = request.form.get("password", "")
        confirmation = request.form.get(
            "confirm_password", ""
        )

        if not password_is_strong(password):
            error = (
                "Use at least 12 characters with an uppercase letter, "
                "lowercase letter, number, and symbol."
            )

        elif password != confirmation:
            error = "Your passwords do not match."

        else:
            with get_db().cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE users
                    SET password_hash = %s
                    WHERE user_id = %s
                    """,
                    (
                        generate_password_hash(password),
                        authorization["user_id"],
                    ),
                )

                cursor.execute(
                    """
                    DELETE FROM trusted_devices
                    WHERE user_id = %s
                    """,
                    (authorization["user_id"],),
                )
                

            session.clear()

            flash(
                "Your password was changed. You can now sign in.",
                "password_reset_success",
            )

            return redirect(url_for("login"))

    return render_template(
        "auth/reset_password.html",
        error=error,
    )

@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user is not None:
        if g.user["role"] == "Admin":
            return redirect(url_for("admin_dashboard"))

        return redirect(url_for("business_dashboard"))

    error = None

    values = {
        "business_name": "",
        "business_type": "",
        "username": "",
        "email": "",
    }

    if request.method == "POST":
        validate_csrf()

        values = {
            field: request.form.get(field, "").strip()
            for field in values
        }

        values["email"] = values["email"].lower()

        password = request.form.get("password", "")
        confirmation = request.form.get("confirm_password", "")

        if not 1 <= len(values["business_name"]) <= 100:
            error = (
                "Enter your business name using up to 100 characters."
            )

        elif values["business_type"] not in (
            "Bakery",
            "Carinderia",
            "Food Stall",
        ):
            error = "Please choose your type of business."

        elif not 1 <= len(values["username"]) <= 50:
            error = "Choose a username using up to 50 characters."

        elif any(
            character.isspace()
            for character in values["username"]
        ):
            error = "Your username cannot contain spaces."

        elif not is_valid_email(values["email"]):
            error = "Enter a valid email address."

        elif not password_is_strong(password):
            error = (
                "Use at least 12 characters with an uppercase letter, "
                "lowercase letter, number, and symbol."
            )

        elif password != confirmation:
            error = "Your passwords do not match."

        if error is None:
            with get_db().cursor() as cursor:
                cursor.execute(
                    """
                    SELECT user_id
                    FROM users
                    WHERE username = %s
                    LIMIT 1
                    """,
                    (values["username"],),
                )

                existing_user = cursor.fetchone()

            if existing_user:
                error = (
                    "This username is already taken. "
                    "Please choose another username."
                )

        if error is None:
            verification_code = (
                f"{secrets.randbelow(1000000):06d}"
            )

            try:
                send_verification_code(
                    values["email"],
                    verification_code,
                    "registration",
                )

            except RuntimeError:
                app.logger.exception(
                    "FoodCast email settings are missing."
                )

                error = (
                    "The FoodCast email service is not configured yet. "
                    "Please contact the administrator."
                )

            except smtplib.SMTPAuthenticationError:
                app.logger.exception(
                    "FoodCast could not sign in to the sender "
                    "email account."
                )

                error = (
                    "The FoodCast email service could not sign in. "
                    "Please contact the administrator."
                )

            except smtplib.SMTPRecipientsRefused:
                app.logger.exception(
                    "The recipient email address was refused."
                )

                error = (
                    "The verification email could not be delivered. "
                    "Check your email address and try again."
                )

            except (OSError, smtplib.SMTPException):
                app.logger.exception(
                    "The verification email could not be sent."
                )

                error = (
                    "The email service is temporarily unavailable. "
                    "Please try again later."
                )

            else:
                session["pending_registration"] = {
                    "business_name": values["business_name"],
                    "business_type": values["business_type"],
                    "username": values["username"],
                    "email": values["email"],
                    "password_hash": generate_password_hash(
                        password
                    ),
                    "code_hash": generate_password_hash(
                        verification_code
                    ),
                    "expires_at": (
                        datetime.now(timezone.utc)
                        + timedelta(minutes=10)
                    ).isoformat(),
                    "attempts": 0,
                }

                return redirect(
                    url_for("verify_registration_email")
                )
            
    return render_template(
    "auth/register.html",
    error=error,
    values=values,
)

@app.route("/register/verify", methods=["GET", "POST"])
def verify_registration_email():
    pending = session.get("pending_registration")

    if not pending:
        return redirect(url_for("register"))

    error = None

    try:
        expires_at = datetime.fromisoformat(
            pending["expires_at"]
        )
    except (KeyError, TypeError, ValueError):
        session.pop("pending_registration", None)
        return redirect(url_for("register"))

    if datetime.now(timezone.utc) >= expires_at:
        session.pop("pending_registration", None)
        flash(
            "Your verification code expired. Please register again.",
            "registration_error",
        )
        return redirect(url_for("register"))

    if request.method == "POST":
        validate_csrf()

        code = request.form.get("verification_code", "").strip()

        if not re.fullmatch(r"\d{6}", code):
            error = "Enter the six-digit code from your email."

        elif pending.get("attempts", 0) >= 5:
            session.pop("pending_registration", None)
            flash(
                "Too many incorrect attempts. Please register again.",
                "registration_error",
            )
            return redirect(url_for("register"))

        elif not check_password_hash(pending["code_hash"], code):
            pending["attempts"] = pending.get("attempts", 0) + 1
            session["pending_registration"] = pending
            session.modified = True
            error = "That verification code is incorrect."

        else:
            database = get_db()

            try:
                database.begin()

                with database.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO users (
                            username,
                            email,
                            password_hash,
                            role
                        )
                        VALUES (%s, %s, %s, 'Business')
                        """,
                        (
                            pending["username"],
                            pending["email"],
                            pending["password_hash"],
                        ),
                    )

                    user_id = cursor.lastrowid

                    cursor.execute(
                        """
                        INSERT INTO businesses (
                            user_id,
                            business_name,
                            business_type
                        )
                        VALUES (%s, %s, %s)
                        """,
                        (
                            user_id,
                            pending["business_name"],
                            pending["business_type"],
                        ),
                    )

                database.commit()

            except pymysql.MySQLError as database_error:
                database.rollback()

                if database_error.args[0] == 1062:
                    error = (
                        "That username or Gmail address is already registered."
                    )
                else:
                    app.logger.exception(
                        "Verified registration could not be saved."
                    )
                    error = (
                        "The account could not be created. "
                        "Please try again."
                    )
            else:
                session.pop("pending_registration", None)

                flash(
                    "Your Gmail address was verified. "
                    "You can now sign in.",
                    "registration_success",
                )

                return redirect(url_for("login"))

    return render_template(
        "auth/verify_email.html",
        email=pending["email"],
        error=error,
    )

@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    with get_db().cursor() as cursor:
        cursor.execute(
    """
    SELECT
        users.user_id,
        users.username,
        users.created_at,
        businesses.business_name,
        businesses.business_type
    FROM users
    LEFT JOIN businesses
        ON businesses.user_id = users.user_id
    WHERE users.role = 'Business'
    ORDER BY users.created_at DESC, users.user_id DESC
    """
)

        business_accounts = cursor.fetchall()

    return render_template(
        "admin/dashboard.html",
        business_accounts=business_accounts,
        business_count=len(business_accounts),
    )


@app.route("/logout", methods=["POST"])
def logout():
    validate_csrf()
    session.clear()

    return redirect(url_for("login"))

@app.route("/admin/businesses/add", methods=["GET", "POST"])
@admin_required
def add_business():
    error = None

    values = {
        "business_name": "",
        "business_type": "",
        "username": "",
    }

    if request.method == "POST":
        validate_csrf()

        values = {
            "business_name": request.form.get(
                "business_name", ""
            ).strip(),
            "business_type": request.form.get(
                "business_type", ""
            ).strip(),
            "username": request.form.get(
                "username", ""
            ).strip(),
        }

        password = request.form.get("password", "")
        confirmation = request.form.get("confirm_password", "")

        allowed_types = ("Bakery", "Carinderia", "Food Stall")

        if not 1 <= len(values["business_name"]) <= 100:
            error = "Enter a business name between 1 and 100 characters."

        elif values["business_type"] not in allowed_types:
            error = "Select a valid business type."

        elif not 1 <= len(values["username"]) <= 50:
            error = "Enter a username between 1 and 50 characters."

        elif any(character.isspace() for character in values["username"]):
            error = "The username cannot contain spaces."

        elif len(password) < 12:
            error = "Use a password of at least 12 characters."

        elif password != confirmation:
            error = "The passwords do not match."

        if error is None:
            password_hash = generate_password_hash(password)
            database = get_db()

            try:
                database.begin()

                with database.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO users (
                            username,
                            password_hash,
                            role
                        )
                        VALUES (%s, %s, 'Business')
                        """,
                        (
                            values["username"],
                            password_hash,
                        ),
                    )

                    user_id = cursor.lastrowid

                    cursor.execute(
                        """
                        INSERT INTO businesses (
                            user_id,
                            business_name,
                            business_type
                        )
                        VALUES (%s, %s, %s)
                        """,
                        (
                            user_id,
                            values["business_name"],
                            values["business_type"],
                        ),
                    )

                database.commit()

                return redirect(url_for("admin_dashboard"))

            except pymysql.err.IntegrityError as database_error:
                database.rollback()

                if database_error.args[0] == 1062:
                    error = "That username is already taken."
                else:
                    app.logger.exception(
                        "Business account creation failed."
                    )
                    error = "The account could not be saved."

            except pymysql.MySQLError:
                database.rollback()

                app.logger.exception(
                    "Database error while creating a business."
                )

                error = (
                    "The account could not be saved. "
                    "Please try again."
                )

    return render_template(
        "admin/add_business.html",
        error=error,
        values=values,
    )

def calculate_available_stock(cursor, product_id):
    cursor.execute(
        """
        SELECT
            COALESCE(
                SUM(
                    CASE
                        WHEN movement_type IN (
                            'Stock In',
                            'Adjustment In'
                        )
                        THEN quantity
                        ELSE -quantity
                    END
                ),
                0
            ) AS available_stock
        FROM stock_movements
        WHERE product_id = %s
        """,
        (product_id,),
    )

    result = cursor.fetchone()

    return max(0, int(result["available_stock"]))


def day_of_week_forecast(history, forecast_date):
    matching_days = []

    for sales_date, quantity in history:
        if sales_date.weekday() == forecast_date.weekday():
            matching_days.append(quantity)

    if not matching_days:
        return 0.0

    weights = list(range(1, len(matching_days) + 1))

    return sum(
        quantity * weight
        for quantity, weight in zip(matching_days, weights)
    ) / sum(weights)

def random_forest_forecast(history, forecast_days):
    quantities = [quantity for _, quantity in history]
    dates = [sales_date for sales_date, _ in history]

    training_features = []
    training_targets = []

    for index in range(28, len(quantities)):
        training_features.append([
            dates[index].weekday(),
            dates[index].month,
            quantities[index - 1],
            quantities[index - 7],
            quantities[index - 14],
            sum(quantities[index - 7:index]) / 7,
            sum(quantities[index - 28:index]) / 28,
        ])

        training_targets.append(quantities[index])

    model = RandomForestRegressor(
        n_estimators=200,
        max_depth=12,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=2,
    )

    model.fit(training_features, training_targets)

    predicted_days = []
    future_quantities = quantities[:]

    for forecast_date in forecast_days:
        features = [[
            forecast_date.weekday(),
            forecast_date.month,
            future_quantities[-1],
            future_quantities[-7],
            future_quantities[-14],
            sum(future_quantities[-7:]) / 7,
            sum(future_quantities[-28:]) / 28,
        ]]

        prediction = max(
            0,
            float(model.predict(features)[0]),
        )

        future_quantities.append(prediction)

        predicted_days.append(round(prediction, 2))

    return predicted_days

def calculate_business_backtest(business_id):
    product_results = []
    all_actual = []
    all_predicted = []

    with get_db().cursor() as cursor:
        cursor.execute(
            """
            SELECT
                product_id,
                product_name
            FROM products
            WHERE business_id = %s
            ORDER BY product_name
            """,
            (business_id,),
        )

        products = cursor.fetchall()

        for product in products:
            cursor.execute(
                """
                SELECT
                    sale_date,
                    quantity_sold
                FROM daily_sales
                WHERE product_id = %s
                ORDER BY sale_date
                """,
                (product["product_id"],),
            )

            saved_sales = cursor.fetchall()

            # Use the same requirement as the live Random Forest.
            if len(saved_sales) < 90:
                continue

            sales_by_date = {
                row["sale_date"]: float(row["quantity_sold"])
                for row in saved_sales
            }

            first_date = saved_sales[0]["sale_date"]
            last_date = saved_sales[-1]["sale_date"]

            dates = []
            quantities = []

            current_date = first_date

            while current_date <= last_date:
                dates.append(current_date)
                quantities.append(
                    sales_by_date.get(current_date, 0.0)
                )

                current_date += timedelta(days=1)

            features = []
            targets = []

            for index in range(28, len(quantities)):
                features.append([
                    dates[index].weekday(),
                    dates[index].month,
                    quantities[index - 1],
                    quantities[index - 7],
                    quantities[index - 14],
                    sum(
                        quantities[index - 7:index]
                    ) / 7,
                    sum(
                        quantities[index - 28:index]
                    ) / 28,
                ])

                targets.append(quantities[index])

            # Keep the final 30 days separate for testing.
            if len(features) < 90:
                continue

            test_days = min(30, len(features) // 3)

            training_features = features[:-test_days]
            training_targets = targets[:-test_days]

            test_features = features[-test_days:]
            test_targets = targets[-test_days:]

            if not training_features or not test_features:
                continue

            model = RandomForestRegressor(
                n_estimators=200,
                max_depth=12,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=2,
            )

            model.fit(
                training_features,
                training_targets,
            )

            predictions = model.predict(test_features)

            absolute_errors = [
                abs(actual - predicted)
                for actual, predicted in zip(
                    test_targets,
                    predictions,
                )
            ]

            squared_errors = [
                (actual - predicted) ** 2
                for actual, predicted in zip(
                    test_targets,
                    predictions,
                )
            ]

            mae = (
                sum(absolute_errors)
                / len(absolute_errors)
            )

            rmse = math.sqrt(
                sum(squared_errors)
                / len(squared_errors)
            )

            average_actual = (
                sum(test_targets)
                / len(test_targets)
            )

            relative_mae = (
                (mae / average_actual) * 100
                if average_actual > 0
                else None
            )

            product_results.append({
                "product_name": product["product_name"],
                "test_days": test_days,
                "mae": round(mae, 2),
                "rmse": round(rmse, 2),
                "relative_mae": (
                    round(relative_mae, 2)
                    if relative_mae is not None
                    else None
                ),
            })

            all_actual.extend(test_targets)
            all_predicted.extend(predictions)

    if not all_actual:
        return {
            "available": False,
            "products_tested": 0,
            "message": (
                "At least 90 recorded sales days are needed "
                "before accuracy can be measured."
            ),
            "products": [],
        }

    all_absolute_errors = [
        abs(actual - predicted)
        for actual, predicted in zip(
            all_actual,
            all_predicted,
        )
    ]

    all_squared_errors = [
        (actual - predicted) ** 2
        for actual, predicted in zip(
            all_actual,
            all_predicted,
        )
    ]

    overall_mae = (
        sum(all_absolute_errors)
        / len(all_absolute_errors)
    )

    overall_rmse = math.sqrt(
        sum(all_squared_errors)
        / len(all_squared_errors)
    )

    overall_average = sum(all_actual) / len(all_actual)

    overall_relative_mae = (
        (overall_mae / overall_average) * 100
        if overall_average > 0
        else None
    )

    if overall_relative_mae is None:
        reliability = "Unavailable"
        reliability_class = "unavailable"
        reliability_message = (
            "Reliability cannot be measured yet."
        )

    elif overall_relative_mae <= 15:
        reliability = "High"
        reliability_class = "high"
        reliability_message = (
            "Past estimates were generally close to actual sales."
        )

    elif overall_relative_mae <= 25:
        reliability = "Moderate"
        reliability_class = "moderate"
        reliability_message = (
            "Use the estimate as a guide and continue recording sales."
        )

    else:
        reliability = "Low"
        reliability_class = "low"
        reliability_message = (
            "Use this estimate carefully because past errors were larger."
        )

    return {
        "available": True,
        "products_tested": len(product_results),
        "predictions_tested": len(all_actual),
        "mae": round(overall_mae, 2),
        "rmse": round(overall_rmse, 2),
        "relative_mae": (
            round(overall_relative_mae, 2)
            if overall_relative_mae is not None
            else None
        ),
        "reliability": reliability,
        "reliability_class": reliability_class,
        "reliability_message": reliability_message,
        "products": product_results,
    }


def generate_business_forecast(business_id, forecast_days):

    def generate_business_forecast(business_id, forecast_days):
     if forecast_days not in (1, 7, 30):
        raise ValueError(
            "Choose the next day, next 7 days, or next 30 days."
        )

    with get_db().cursor() as cursor:
        cursor.execute(
            """
            SELECT
                p.product_id,
                p.product_name,
                p.selling_unit
            FROM products AS p
            WHERE p.business_id = %s
            ORDER BY p.product_name
            """,
            (business_id,),
        )

        products = cursor.fetchall()

        if not products:
            raise ValueError(
                "Add at least one product before generating a forecast."
            )

        cursor.execute(
            """
            SELECT MAX(s.sale_date) AS latest_sale_date
            FROM daily_sales AS s
            INNER JOIN products AS p
                ON p.product_id = s.product_id
            WHERE p.business_id = %s
            """,
            (business_id,),
        )

        latest_sale = cursor.fetchone()["latest_sale_date"]

        if latest_sale is None:
            raise ValueError(
                "Record daily sales before generating a forecast."
            )

        history_end = latest_sale

        cursor.execute(
            """
            INSERT INTO forecast_runs (
                business_id,
                forecast_days,
                sales_history_end_date
            )
            VALUES (%s, %s, %s)
            """,
            (
                business_id,
                forecast_days,
                history_end,
            ),
        )

        forecast_run_id = cursor.lastrowid

        forecast_dates = [
            history_end + timedelta(days=offset)
            for offset in range(1, forecast_days + 1)
        ]

        for product in products:
            cursor.execute(
                """
                SELECT
                    sale_date,
                    quantity_sold
                FROM daily_sales
                WHERE product_id = %s
                  AND sale_date <= %s
                ORDER BY sale_date
                """,
                (
                    product["product_id"],
                    history_end,
                ),
            )

            saved_sales = cursor.fetchall()

            sales_by_date = {
                row["sale_date"]: float(row["quantity_sold"])
                for row in saved_sales
            }

            if saved_sales:
                first_sale_date = saved_sales[0]["sale_date"]

                history = []

                current_date = first_sale_date

                while current_date <= history_end:
                    history.append((
                        current_date,
                        sales_by_date.get(current_date, 0.0),
                    ))

                    current_date += timedelta(days=1)
            else:
                history = []

            recorded_days = len(saved_sales)
            available_stock = calculate_available_stock(
                cursor,
                product["product_id"],
            )

            if recorded_days < 7:
                method_used = "Not enough history"
                predictions = [0.0] * forecast_days

            elif recorded_days < 90:
                method_used = "Day-of-week average"

                predictions = []

                working_history = history[:]

                for forecast_date in forecast_dates:
                    prediction = day_of_week_forecast(
                        working_history,
                        forecast_date,
                    )

                    prediction = round(max(0, prediction), 2)

                    predictions.append(prediction)

                    working_history.append((
                        forecast_date,
                        prediction,
                    ))

            else:
                method_used = "Random Forest"

                predictions = random_forest_forecast(
                    history,
                    forecast_dates,
                )

            remaining_stock = float(available_stock)

            for forecast_date, prediction in zip(
                forecast_dates,
                predictions,
            ):
                prediction = round(max(0, float(prediction)), 2)

                recommended_to_prepare = max(
                    prediction - remaining_stock,
                    0,
                )

                remaining_stock = max(
                    remaining_stock - prediction,
                    0,
                )

                cursor.execute(
                    """
                    INSERT INTO forecast_product_days (
                        forecast_run_id,
                        product_id,
                        forecast_date,
                        method_used,
                        sales_history_days,
                        predicted_quantity,
                        available_stock,
                        recommended_to_prepare
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    """,
                    (
                        forecast_run_id,
                        product["product_id"],
                        forecast_date,
                        method_used,
                        recorded_days,
                        round(prediction, 2),
                        available_stock,
                        round(recommended_to_prepare, 2),
                    ),
                )

    return forecast_run_id

@app.route("/business/forecasting", methods=["GET", "POST"])
@business_required
def business_forecasting():
    with get_db().cursor() as cursor:
        cursor.execute(
            """
        SELECT
            business_id,
            business_name,
            business_type,
            created_at,
            location_latitude,
            location_longitude,
            location_name,
            location_accuracy_m,
            location_updated_at
        FROM businesses
            WHERE user_id = %s
            """,
            (g.user["user_id"],),
        )

        business = cursor.fetchone()

    if business is None:
        abort(403, description="Your account has no linked business.")

    if request.method == "POST":
        validate_csrf()

        try:
            forecast_days = int(
                request.form.get("forecast_days", "")
            )

            generate_business_forecast(
                business["business_id"],
                forecast_days,
            )

            flash(
                "Your sales forecast was generated.",
                "forecast_success",
            )

        except ValueError as error:
            flash(str(error), "forecast_error")

        except Exception:
            app.logger.exception(
                "Could not generate the business forecast."
            )

            flash(
                "The forecast could not be generated. "
                "Please try again later.",
                "forecast_error",
            )

        return redirect(url_for("business_forecasting"))

    results_folder = (
        BASE_DIR
        / "data"
        / "results"
        / "french_bakery"
    )

    weekly_forecast = None
    forecast_error = None
    model_report = None
    model_error = None

    try:
        weekly_file = (
            results_folder
            / "seven_day_forecast.json"
        )

        with weekly_file.open(encoding="utf-8") as file:
            weekly_forecast = json.load(file)

        required_keys = {
            "forecast_start",
            "forecast_end",
            "products",
            "chart",
            "summary",
        }

        if not required_keys.issubset(weekly_forecast):
            raise ValueError(
                "Weekly forecast is missing data."
            )

    except FileNotFoundError:
        weekly_forecast = None
        forecast_error = (
            "No seven-day bakery forecast was found. "
            "Run generate_french_bakery_weekly_forecast.py first."
        )

    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
    ):
        app.logger.exception(
            "Could not load the seven-day bakery forecast."
        )

        weekly_forecast = None
        forecast_error = (
            "The seven-day bakery forecast could not be loaded."
        )
    try:
        report_file = (
            results_folder
            / "traditional_baguette_metrics.json"
        )

        with report_file.open(encoding="utf-8") as file:
            model_report = json.load(file)

        for method in ("baseline", "random_forest"):
            for metric in ("mae", "rmse"):
                model_report[method][metric] = float(
                    model_report[method][metric]
                )

        model_report["test_days"] = int(
            model_report["test_days"]
        )

    except FileNotFoundError:
        model_error = "Model test results are not available yet."

    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
    ):
        app.logger.exception("Could not load bakery model results.")

        model_error = (
            "Model test results could not be loaded."
        )

    next_day_forecast = None
    next_day_forecast_error = None

    try:
        next_day_file = (
            results_folder
            / "traditional_baguette_next_day_forecast.json"
        )

        with next_day_file.open(encoding="utf-8") as file:
            next_day_forecast = json.load(file)

        required_next_day_keys = {
            "product",
            "forecast_date",
            "predicted_quantity",
            "unit",
        }

        if not required_next_day_keys.issubset(next_day_forecast):
            raise ValueError(
                "Next-day forecast is missing data."
            )

    except FileNotFoundError:
        next_day_forecast = None
        next_day_forecast_error = (
            "No next-day bakery forecast was found. "
            "Run generate_french_bakery_forecast.py first."
        )

    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
    ):
        app.logger.exception(
            "Could not load the next-day bakery forecast."
        )

        next_day_forecast = None
        next_day_forecast_error = (
            "The next-day bakery forecast could not be loaded."
        )

    weather = None
    weather_error = None

    if (
        business["location_latitude"] is not None
        and business["location_longitude"] is not None
    ):
        try:
            weather = get_business_weather(
                float(business["location_latitude"]),
                float(business["location_longitude"]),
            )

        except (
            OSError,
            ValueError,
            KeyError,
            TypeError,
        ):
            app.logger.exception(
                "Could not load the business weather."
            )

            weather_error = (
                "The latest weather could not be loaded. "
                "Please refresh the page later."
            )

    business_forecast_run = None
    business_forecast_results = []

    with get_db().cursor() as cursor:
        cursor.execute(
            """
            SELECT
                forecast_run_id,
                forecast_days,
                sales_history_end_date,
                generated_at
            FROM forecast_runs
            WHERE business_id = %s
            ORDER BY generated_at DESC, forecast_run_id DESC
            LIMIT 1
            """,
            (business["business_id"],),
        )

        business_forecast_run = cursor.fetchone()

        if business_forecast_run:
            cursor.execute(
                """
                SELECT
                    fpd.forecast_date,
                    fpd.method_used,
                    fpd.sales_history_days,
                    fpd.predicted_quantity,
                    fpd.available_stock,
                    fpd.recommended_to_prepare,
                    p.product_id,
                    p.product_name,
                    p.selling_unit
                FROM forecast_product_days AS fpd
                INNER JOIN products AS p
                    ON p.product_id = fpd.product_id
                WHERE fpd.forecast_run_id = %s
                ORDER BY
                    p.product_name,
                    fpd.forecast_date
                """,
                (
                    business_forecast_run[
                        "forecast_run_id"
                    ],
                ),
            )

            business_forecast_results = cursor.fetchall()

    business_forecast_chart = {
        "actual_sales": [],
        "forecasted_sales": [],
    }

    business_forecast_products = []

    business_backtest = calculate_business_backtest(
    business["business_id"]
)

    if business_forecast_run:
        history_end = business_forecast_run[
            "sales_history_end_date"
        ]

        history_start = history_end - timedelta(days=6)

        with get_db().cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    s.sale_date,
                    COALESCE(
                        SUM(s.quantity_sold),
                        0
                    ) AS quantity
                FROM daily_sales AS s
                INNER JOIN products AS p
                    ON p.product_id = s.product_id
                WHERE p.business_id = %s
                  AND s.sale_date BETWEEN %s AND %s
                GROUP BY s.sale_date
                ORDER BY s.sale_date
                """,
                (
                    business["business_id"],
                    history_start,
                    history_end,
                ),
            )

            actual_rows = cursor.fetchall()

            actual_by_date = {
                row["sale_date"]: float(row["quantity"])
                for row in actual_rows
            }

            current_date = history_start

            while current_date <= history_end:
                business_forecast_chart[
                    "actual_sales"
                ].append({
                    "date": current_date.isoformat(),
                    "quantity": actual_by_date.get(
                        current_date,
                        0,
                    ),
                })

                current_date += timedelta(days=1)

            cursor.execute(
                """
                SELECT
                    forecast_date,
                    SUM(predicted_quantity) AS quantity
                FROM forecast_product_days
                WHERE forecast_run_id = %s
                  AND method_used != 'Not enough history'
                GROUP BY forecast_date
                ORDER BY forecast_date
                """,
                (
                    business_forecast_run[
                        "forecast_run_id"
                    ],
                ),
            )

            forecast_rows = cursor.fetchall()

            business_forecast_chart[
                "forecasted_sales"
            ] = [
                {
                    "date": row["forecast_date"].isoformat(),
                    "quantity": float(row["quantity"]),
                }
                for row in forecast_rows
            ]

            cursor.execute(
                """
                SELECT
                    p.product_id,
                    p.product_name,
                    p.selling_unit,
                    MAX(fpd.method_used) AS method_used,
                    MAX(fpd.sales_history_days)
                        AS sales_history_days,
                    MAX(fpd.available_stock)
                        AS available_stock,
                    SUM(fpd.predicted_quantity)
                        AS predicted_demand,
                    SUM(fpd.recommended_to_prepare)
                        AS recommended_to_prepare
                FROM forecast_product_days AS fpd
                INNER JOIN products AS p
                    ON p.product_id = fpd.product_id
                WHERE fpd.forecast_run_id = %s
                GROUP BY
                    p.product_id,
                    p.product_name,
                    p.selling_unit
                ORDER BY
                    predicted_demand DESC,
                    p.product_name
                """,
                (
                    business_forecast_run[
                        "forecast_run_id"
                    ],
                ),
            )

            business_forecast_products = cursor.fetchall()

    return render_template(
        "business/forecasting.html",
        business=business,
        forecast_error=forecast_error,
        model_report=model_report,
        model_error=model_error,
        next_day_forecast=next_day_forecast,
        next_day_forecast_error=next_day_forecast_error,
        weather=weather,
        weather_error=weather_error,
        weekly_forecast=weekly_forecast,
        business_forecast_run=business_forecast_run,
        business_forecast_products=business_forecast_products,
        business_forecast_chart=business_forecast_chart,
        business_backtest=business_backtest,
    )

def describe_weather(code):
    if code == 0:
        return {"text": "Clear", "icon": "sun"}

    if code in (1, 2):
        return {"text": "Partly cloudy", "icon": "cloud-sun"}

    if code == 3:
        return {"text": "Cloudy", "icon": "cloud"}

    if code in (45, 48):
        return {"text": "Foggy", "icon": "fog"}

    if code in (51, 53, 55, 56, 57):
        return {"text": "Drizzle", "icon": "drizzle"}

    if code in (61, 63, 66, 80, 81):
        return {"text": "Rain", "icon": "rain"}

    if code in (65, 67, 82, 95, 96, 99):
        return {"text": "Thunderstorm", "icon": "storm"}

    return {
        "text": "Weather unavailable",
        "icon": "cloud",
    }

def find_location_name(latitude, longitude):
    parameters = urlencode({
        "format": "jsonv2",
        "lat": latitude,
        "lon": longitude,
        "zoom": 10,
        "addressdetails": 1,
    })

    url = (
        "https://nominatim.openstreetmap.org/reverse?"
        + parameters
    )

    location_request = UrlRequest(
        url,
        headers={
            "User-Agent": (
                "FoodCastAI-Research/1.0 "
                "(student research project)"
            ),
            "Accept-Language": "en",
        },
    )

    with urlopen(location_request, timeout=6) as response:
        result = json.loads(
            response.read().decode("utf-8")
        )

    address = result.get("address", {})

    locality = (
        address.get("city")
        or address.get("municipality")
        or address.get("town")
        or address.get("village")
        or address.get("county")
    )

    region = (
        address.get("state")
        or address.get("region")
    )

    parts = []

    for part in (locality, region):
        if part and part not in parts:
            parts.append(part)

    if parts:
        return ", ".join(parts)

    return "Saved business location"


def get_business_weather(latitude, longitude):
    parameters = urlencode({
        "latitude": latitude,
        "longitude": longitude,
        "current": (
            "temperature_2m,"
            "relative_humidity_2m,"
            "weather_code,"
            "wind_speed_10m"
        ),
        "daily": (
            "weather_code,"
            "temperature_2m_max,"
            "temperature_2m_min,"
            "precipitation_probability_max,"
            "precipitation_sum,"
            "wind_speed_10m_max"
        ),
        "timezone": "Asia/Manila",
        "forecast_days": 2,
    })

    url = (
        "https://api.open-meteo.com/v1/forecast?"
        + parameters
    )

    weather_request = UrlRequest(
        url,
        headers={
            "User-Agent": (
                "FoodCastAI-Research/1.0 "
                "(student research project)"
            ),
        },
    )

    with urlopen(weather_request, timeout=6) as response:
        result = json.loads(
            response.read().decode("utf-8")
        )

    current = result["current"]
    daily = result["daily"]

    if len(daily["time"]) < 2:
        raise ValueError(
            "Tomorrow's weather is unavailable."
        )

    today_condition = describe_weather(
        int(current["weather_code"])
    )

    tomorrow_code = int(
        daily["weather_code"][1]
    )

    tomorrow_condition = describe_weather(
        tomorrow_code
    )

    tomorrow_rain_chance = float(
        daily["precipitation_probability_max"][1]
    )

    tomorrow_rain_amount = float(
        daily["precipitation_sum"][1]
    )

    severe_codes = {
        65,
        67,
        82,
        95,
        96,
        99,
    }

    if (
        tomorrow_code in severe_codes
        or tomorrow_rain_amount >= 20
    ):
        advice = (
            "Heavy rain may affect customer visits tomorrow. "
            "Consider preparing smaller batches first and "
            "check official class or local announcements."
        )

        advice_level = "high"

    elif (
        tomorrow_rain_chance >= 60
        or tomorrow_rain_amount >= 5
    ):
        advice = (
            "Rain is possible tomorrow. Consider preparing "
            "food in smaller batches so you can adjust "
            "during the day."
        )

        advice_level = "medium"

    else:
        advice = (
            "No high rain risk is currently shown for "
            "tomorrow. Continue checking the forecast "
            "before preparing stock."
        )

        advice_level = "normal"

    updated_time = datetime.fromisoformat(
        current["time"]
    ).strftime("%I:%M %p")

    return {
        "updated_time": updated_time,

        "today": {
            "icon": today_condition["icon"],
            "condition": today_condition["text"],
            "temperature": round(
                float(current["temperature_2m"])
            ),
            "humidity": round(
                float(current["relative_humidity_2m"])
            ),
            "wind": round(
                float(current["wind_speed_10m"])
            ),
            "rain_chance": round(
                float(
                    daily[
                        "precipitation_probability_max"
                    ][0]
                )
            ),
        },

        "tomorrow": {
            "icon": tomorrow_condition["icon"],
            "condition": tomorrow_condition["text"],
            "maximum_temperature": round(
                float(
                    daily["temperature_2m_max"][1]
                )
            ),
            "minimum_temperature": round(
                float(
                    daily["temperature_2m_min"][1]
                )
            ),
            "rain_chance": round(
                tomorrow_rain_chance
            ),
            "rain_amount": round(
                tomorrow_rain_amount,
                1,
            ),
        },

        "advice": advice,
        "advice_level": advice_level,
    }

@app.route("/business/location", methods=["POST"])
@business_required
def save_business_location():
    validate_csrf()

    try:
        latitude = float(request.form.get("latitude", ""))
        longitude = float(request.form.get("longitude", ""))
        accuracy = float(request.form.get("accuracy", ""))
    except ValueError:
        abort(400, description="The location information is invalid.")

    if not -90 <= latitude <= 90:
        abort(400, description="The latitude is invalid.")

    if not -180 <= longitude <= 180:
        abort(400, description="The longitude is invalid.")

    if not 0 <= accuracy <= 100000:
        abort(400, description="The location accuracy is invalid.")

    try:
        location_name = find_location_name(
            latitude,
            longitude,
        )
    except (OSError, ValueError, KeyError, TypeError):
        app.logger.exception(
            "Could not find the readable location name."
        )

        location_name = "Saved business location"

    with get_db().cursor() as cursor:
        cursor.execute(
            """
            UPDATE businesses
            SET
                location_latitude = %s,
                location_longitude = %s,
                location_name = %s,
                location_accuracy_m = %s,
                location_updated_at = NOW()
            WHERE user_id = %s
            """,
            (
                round(latitude, 6),
                round(longitude, 6),
                location_name,
                round(accuracy),
                g.user["user_id"],
            ),
        )

    flash(
        "Your business location was saved.",
        "location_success",
    )

    return_to = request.form.get("return_to", "")

    if return_to == "forecasting":
        return redirect(
            url_for("business_forecasting")
        )

    return redirect(
        url_for("business_dashboard")
    )

@app.route("/business/tips")
@business_required
def business_tips():
    today = datetime.now(
        timezone(timedelta(hours=8))
    ).date()

    recent_start = today - timedelta(days=6)

    with get_db().cursor() as cursor:
        cursor.execute(
            """
            SELECT
                business_id,
                business_name,
                business_type,
                created_at
            FROM businesses
            WHERE user_id = %s
            """,
            (g.user["user_id"],),
        )

        business = cursor.fetchone()

        if business is None:
            abort(
                403,
                description="Your account has no linked business.",
            )

        cursor.execute(
            """
            SELECT COUNT(*) AS product_count
            FROM products
            WHERE business_id = %s
            """,
            (business["business_id"],),
        )

        product_count = cursor.fetchone()["product_count"]

        cursor.execute(
            """
            SELECT COUNT(DISTINCT daily_sales.sale_date) AS recorded_days
            FROM daily_sales
            INNER JOIN products
                ON products.product_id = daily_sales.product_id
            WHERE products.business_id = %s
              AND daily_sales.sale_date BETWEEN %s AND %s
            """,
            (
                business["business_id"],
                recent_start,
                today,
            ),
        )

        recorded_days = cursor.fetchone()["recorded_days"]

        cursor.execute(
            """
            SELECT
                products.product_name,
                products.selling_unit,
                SUM(daily_sales.quantity_sold) AS quantity_sold,
                SUM(daily_sales.sales_amount) AS sales_amount
            FROM daily_sales
            INNER JOIN products
                ON products.product_id = daily_sales.product_id
            WHERE products.business_id = %s
              AND daily_sales.sale_date BETWEEN %s AND %s
            GROUP BY
                products.product_id,
                products.product_name,
                products.selling_unit
            HAVING SUM(daily_sales.quantity_sold) > 0
            ORDER BY quantity_sold DESC
            LIMIT 1
            """,
            (
                business["business_id"],
                recent_start,
                today,
            ),
        )

        top_product = cursor.fetchone()

        cursor.execute(
            """
            SELECT
                products.product_name,
                products.selling_unit,
                COALESCE(
                    SUM(
                        CASE
                            WHEN stock_movements.movement_type IN (
                                'Stock In',
                                'Adjustment In'
                            )
                            THEN stock_movements.quantity
                            ELSE -stock_movements.quantity
                        END
                    ),
                    0
                ) AS available
            FROM products
            LEFT JOIN stock_movements
                ON stock_movements.product_id = products.product_id
            WHERE products.business_id = %s
            GROUP BY
                products.product_id,
                products.product_name,
                products.selling_unit
            HAVING available <= 5
            ORDER BY available, products.product_name
            LIMIT 3
            """,
            (business["business_id"],),
        )

        low_stock_products = cursor.fetchall()

        cursor.execute(
            """
            SELECT
                COALESCE(SUM(stock_movements.quantity), 0) AS wasted_quantity
            FROM stock_movements
            INNER JOIN products
                ON products.product_id = stock_movements.product_id
            WHERE products.business_id = %s
              AND stock_movements.movement_type = 'Waste'
              AND DATE(stock_movements.created_at)
                  BETWEEN %s AND %s
            """,
            (
                business["business_id"],
                recent_start,
                today,
            ),
        )

        wasted_quantity = cursor.fetchone()["wasted_quantity"]

    tips = []

    if product_count == 0:
        tips.append({
            "icon": "products",
            "title": "Add your products",
            "message": (
                "Add the food items you sell before recording sales "
                "and stock."
            ),
            "level": "attention",
            "endpoint": "business_products",
            "link_text": "Add products",
        })

    elif recorded_days == 0:
        tips.append({
            "icon": "sales",
            "title": "Start recording sales",
            "message": (
                "No sales have been recorded during the last seven days. "
                "Daily records help FoodCast understand your business."
            ),
            "level": "attention",
            "endpoint": "business_sales",
            "link_text": "Record sales",
        })

    elif recorded_days < 7:
        tips.append({
            "icon": "records",
            "title": "Complete your daily sales",
            "message": (
                f"You recorded sales on {recorded_days} of the last "
                "7 days. Record every day, including zero-sales days, "
                "to improve future estimates."
            ),
            "level": "info",
            "endpoint": "business_sales",
            "link_text": "View sales",
        })

    else:
        tips.append({
            "icon": "records",
            "title": "Your sales records are up to date",
            "message": (
                "You have sales records for all seven recent days. "
                "Continue recording sales every day."
            ),
            "level": "positive",
            "endpoint": "business_sales",
            "link_text": "View sales",
        })

    if low_stock_products:
        product_names = ", ".join(
            product["product_name"]
            for product in low_stock_products
        )

        tips.append({
            "icon": "stock",
            "title": "Check these low-stock products",
            "message": (
                f"{product_names} currently have five or fewer units "
                "available. Check whether you need to add stock."
            ),
            "level": "attention",
            "endpoint": "business_inventory",
            "link_text": "Check stock",
        })

    if top_product is not None:
        tips.append({
            "icon": "best-seller",
            "title": "Your recent best seller",
            "message": (
                f"{top_product['product_name']} sold the most during "
                f"the last seven days, with "
                f"{top_product['quantity_sold']:,.0f} "
                f"{top_product['selling_unit'].lower()} sold. "
                "Keep enough stock available for this product."
            ),
            "level": "positive",
            "endpoint": "business_sales",
            "link_text": "View sales",
        })

    if wasted_quantity > 0:
        tips.append({
            "icon": "waste",
            "title": "Review recently wasted stock",
            "message": (
                f"{wasted_quantity:,.0f} units were recorded as waste "
                "during the last seven days. Consider preparing smaller "
                "batches and adding more only when needed."
            ),
            "level": "attention",
            "endpoint": "business_inventory",
            "link_text": "View stock updates",
        })

    return render_template(
        "business/tips.html",
        business=business,
        tips=tips,
        today=today,
        recent_start=recent_start,
    )

@app.route("/business/profile/edit", methods=["GET", "POST"])
@business_required
def edit_business_profile():
    error = None

    with get_db().cursor() as cursor:
        cursor.execute(
            """
            SELECT
                businesses.business_id,
                businesses.business_name,
                businesses.business_type,
                businesses.created_at,
                users.username,
                users.email
            FROM businesses
            INNER JOIN users
                ON users.user_id = businesses.user_id
            WHERE businesses.user_id = %s
            LIMIT 1
            """,
            (g.user["user_id"],),
        )

        profile = cursor.fetchone()

    if profile is None:
        abort(404)

    values = {
        "business_name": profile["business_name"],
        "business_type": profile["business_type"],
        "username": profile["username"],
    }

    if request.method == "POST":
        validate_csrf()

        values = {
            "business_name": request.form.get(
                "business_name", ""
            ).strip(),
            "business_type": request.form.get(
                "business_type", ""
            ).strip(),
            "username": request.form.get(
                "username", ""
            ).strip(),
        }

        if not 1 <= len(values["business_name"]) <= 100:
            error = (
                "Enter your business name using up to 100 characters."
            )

        elif values["business_type"] not in (
            "Bakery",
            "Carinderia",
            "Food Stall",
        ):
            error = "Choose a valid business type."

        elif not 1 <= len(values["username"]) <= 50:
            error = "Enter a username using up to 50 characters."

        elif any(
            character.isspace()
            for character in values["username"]
        ):
            error = "Your username cannot contain spaces."

        if error is None:
            with get_db().cursor() as cursor:
                cursor.execute(
                    """
                    SELECT user_id
                    FROM users
                    WHERE username = %s
                      AND user_id <> %s
                    LIMIT 1
                    """,
                    (
                        values["username"],
                        g.user["user_id"],
                    ),
                )

                existing_user = cursor.fetchone()

            if existing_user:
                error = (
                    "This username is already taken. "
                    "Please choose another username."
                )

        if error is None:
            try:
                with get_db().cursor() as cursor:
                    cursor.execute(
                        """
                        UPDATE users
                        INNER JOIN businesses
                            ON businesses.user_id = users.user_id
                        SET
                            users.username = %s,
                            businesses.business_name = %s,
                            businesses.business_type = %s
                        WHERE users.user_id = %s
                        """,
                        (
                            values["username"],
                            values["business_name"],
                            values["business_type"],
                            g.user["user_id"],
                        ),
                    )

            except pymysql.err.IntegrityError:
                error = (
                    "This username is already taken. "
                    "Please choose another username."
                )

            else:
                flash(
                    "Your profile was updated.",
                    "profile_success",
                )

                return redirect(
                    url_for("edit_business_profile")
                )

    profile["business_name"] = values["business_name"]
    profile["business_type"] = values["business_type"]

    return render_template(
        "business/edit_profile.html",
        business=profile,
        values=values,
        error=error,
    )

@app.route("/business/profile/email", methods=["POST"])
@business_required
def change_business_email():
    validate_csrf()

    new_email = request.form.get(
        "email", ""
    ).strip().lower()

    if not is_valid_email(new_email):
        flash(
            "Enter a valid email address.",
            "profile_error",
        )
        return redirect(url_for("edit_business_profile"))

    with get_db().cursor() as cursor:
        cursor.execute(
            """
            SELECT email
            FROM users
            WHERE user_id = %s
            LIMIT 1
            """,
            (g.user["user_id"],),
        )

        user = cursor.fetchone()

    current_email = (
        user["email"].lower()
        if user and user["email"]
        else ""
    )

    if new_email == current_email:
        flash(
            "This is already your current email address.",
            "profile_error",
        )
        return redirect(url_for("edit_business_profile"))

    verification_code = f"{secrets.randbelow(1000000):06d}"

    try:
        send_verification_code(
            new_email,
            verification_code,
            "email-change",
        )

    except RuntimeError:
        app.logger.exception(
            "FoodCast email settings are missing."
        )
        flash(
            "The email service is not configured.",
            "profile_error",
        )
        return redirect(url_for("edit_business_profile"))

    except smtplib.SMTPAuthenticationError:
        app.logger.exception(
            "FoodCast could not authenticate with email."
        )
        flash(
            "The email service could not sign in.",
            "profile_error",
        )
        return redirect(url_for("edit_business_profile"))

    except (OSError, smtplib.SMTPException):
        app.logger.exception(
            "Email-change verification code could not be sent."
        )
        flash(
            "The verification code could not be sent. "
            "Please try again later.",
            "profile_error",
        )
        return redirect(url_for("edit_business_profile"))

    session["pending_email_change"] = {
        "user_id": g.user["user_id"],
        "email": new_email,
        "code_hash": generate_password_hash(
            verification_code
        ),
        "expires_at": (
            datetime.now(timezone.utc)
            + timedelta(minutes=10)
        ).isoformat(),
        "attempts": 0,
    }

    return redirect(url_for("verify_email_change"))


@app.route(
    "/business/profile/email/verify",
    methods=["GET", "POST"],
)
@business_required
def verify_email_change():
    pending = session.get("pending_email_change")

    if (
        not pending
        or pending.get("user_id") != g.user["user_id"]
    ):
        flash(
            "Start the email change again.",
            "profile_error",
        )
        return redirect(url_for("edit_business_profile"))

    error = None

    try:
        expires_at = datetime.fromisoformat(
            pending["expires_at"]
        )

    except (KeyError, TypeError, ValueError):
        session.pop("pending_email_change", None)
        flash(
            "The verification request is invalid.",
            "profile_error",
        )
        return redirect(url_for("edit_business_profile"))

    if datetime.now(timezone.utc) > expires_at:
        session.pop("pending_email_change", None)
        flash(
            "The verification code expired. Try again.",
            "profile_error",
        )
        return redirect(url_for("edit_business_profile"))

    if request.method == "POST":
        validate_csrf()

        entered_code = request.form.get(
            "verification_code", ""
        ).strip()

        if pending.get("attempts", 0) >= 5:
            session.pop("pending_email_change", None)
            flash(
                "Too many incorrect attempts. Try again.",
                "profile_error",
            )
            return redirect(url_for("edit_business_profile"))

        if not check_password_hash(
            pending["code_hash"],
            entered_code,
        ):
            pending["attempts"] = (
                pending.get("attempts", 0) + 1
            )
            session["pending_email_change"] = pending

            error = "The verification code is incorrect."

        else:
            with get_db().cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE users
                    SET email = %s
                    WHERE user_id = %s
                    """,
                    (
                        pending["email"],
                        g.user["user_id"],
                    ),
                )

                cursor.execute(
                    """
                    DELETE FROM trusted_devices
                    WHERE user_id = %s
                    """,
                    (g.user["user_id"],),
                )

            session.pop("pending_email_change", None)

            flash(
                "Your email address was updated.",
                "profile_success",
            )

            return redirect(url_for("edit_business_profile"))

    return render_template(
        "business/verify_email_change.html",
        email=pending["email"],
        error=error,
    )


@app.route("/business/profile/password", methods=["POST"])
@business_required
def change_business_password():
    validate_csrf()

    current_password = request.form.get(
        "current_password", ""
    )
    new_password = request.form.get(
        "new_password", ""
    )
    confirmation = request.form.get(
        "confirm_password", ""
    )

    with get_db().cursor() as cursor:
        cursor.execute(
            """
            SELECT password_hash
            FROM users
            WHERE user_id = %s
            LIMIT 1
            """,
            (g.user["user_id"],),
        )

        user = cursor.fetchone()

    if (
        not user
        or not check_password_hash(
            user["password_hash"],
            current_password,
        )
    ):
        flash(
            "Your current password is incorrect.",
            "profile_error",
        )

    elif not password_is_strong(new_password):
        flash(
            "Use at least 12 characters with an uppercase "
            "letter, lowercase letter, number, and symbol.",
            "profile_error",
        )

    elif new_password != confirmation:
        flash(
            "The new passwords do not match.",
            "profile_error",
        )

    elif check_password_hash(
        user["password_hash"],
        new_password,
    ):
        flash(
            "Your new password must be different from "
            "your current password.",
            "profile_error",
        )
    else:
        with get_db().cursor() as cursor:
            cursor.execute(
                """
                UPDATE users
                SET password_hash = %s
                WHERE user_id = %s
                """,
                (
                    generate_password_hash(new_password),
                    g.user["user_id"],
                ),
            )

            cursor.execute(
                """
                DELETE FROM trusted_devices
                WHERE user_id = %s
                """,
                (g.user["user_id"],),
            )

        flash(
            "Your password was changed.",
            "profile_success",
        )

    return redirect(url_for("edit_business_profile"))

@app.route("/business/dashboard")
@business_required
def business_dashboard():
    today = datetime.now(
        timezone(timedelta(hours=8))
    ).date()

    week_start = today - timedelta(days=today.weekday())
    month_start = today.replace(day=1)

    with get_db().cursor() as cursor:
        cursor.execute(
            """
SELECT
    business_id,
    business_name,
    business_type,
    created_at,
    location_latitude,
    location_longitude,
    location_name,
    location_accuracy_m,
    location_updated_at
FROM businesses

            WHERE user_id = %s
            """,
            (g.user["user_id"],),
        )

        business = cursor.fetchone()

    chart_start = today - timedelta(days=6)

    with get_db().cursor() as cursor:
        cursor.execute(
            """
            SELECT
                COALESCE(
                    SUM(
                        CASE
                            WHEN daily_sales.sale_date = %s
                            THEN daily_sales.sales_amount
                            ELSE 0
                        END
                    ),
                    0
                ) AS today_sales,

                COALESCE(
                    SUM(
                        CASE
                            WHEN daily_sales.sale_date BETWEEN %s AND %s
                            THEN daily_sales.sales_amount
                            ELSE 0
                        END
                    ),
                    0
                ) AS week_sales,

                COALESCE(
                    SUM(
                        CASE
                            WHEN daily_sales.sale_date BETWEEN %s AND %s
                            THEN daily_sales.sales_amount
                            ELSE 0
                        END
                    ),
                    0
                ) AS month_sales

            FROM daily_sales
            INNER JOIN products
                ON products.product_id = daily_sales.product_id

            WHERE products.business_id = %s
              AND daily_sales.sale_date BETWEEN %s AND %s
            """,
            (
                today,
                week_start,
                today,
                month_start,
                today,
                business["business_id"],
                min(week_start, month_start),
                today,
            ),
        )

        totals = cursor.fetchone()

        cursor.execute(
            """
            SELECT
                daily_sales.sale_date,
                SUM(daily_sales.sales_amount) AS amount
            FROM daily_sales
            JOIN products
                ON products.product_id = daily_sales.product_id
            WHERE products.business_id = %s
              AND daily_sales.sale_date BETWEEN %s AND %s
            GROUP BY daily_sales.sale_date
            ORDER BY daily_sales.sale_date
            """,
            (business["business_id"], chart_start, today),
        )

        daily_amounts = {
            row["sale_date"]: row["amount"]
            for row in cursor.fetchall()
        }

    weather = None
    weather_error = None

    if (
        business["location_latitude"] is not None
        and business["location_longitude"] is not None
    ):
        try:
            weather = get_business_weather(
                float(business["location_latitude"]),
                float(business["location_longitude"]),
            )
        except (
            OSError,
            ValueError,
            KeyError,
            TypeError,
        ):
            app.logger.exception(
                "Could not load the business weather for Home."
            )

            weather_error = (
                "The latest weather could not be loaded. "
                "Please refresh the page later."
            )

    # Build all seven days, including days without records.
    chart_days = []

    for offset in range(7):
        sales_day = chart_start + timedelta(days=offset)

        chart_days.append({
            "date": sales_day,
            "amount": daily_amounts.get(sales_day, Decimal("0")),
            "has_records": sales_day in daily_amounts,
        })

    highest_amount = max(day["amount"] for day in chart_days)

    for day in chart_days:
        day["percentage"] = (
            round(day["amount"] / highest_amount * 100, 2)
            if highest_amount > 0
            else 0
        )

    # Rank this business's products by recorded monthly revenue.
    with get_db().cursor() as cursor:
        cursor.execute(
            """
            SELECT
                p.product_id,
                p.product_name,
                p.selling_unit,
                SUM(s.quantity_sold) AS quantity,
                SUM(s.sales_amount) AS revenue
            FROM daily_sales AS s
            JOIN products AS p ON p.product_id = s.product_id
            WHERE p.business_id = %s
              AND s.sale_date BETWEEN %s AND %s
            GROUP BY
                p.product_id,
                p.product_name,
                p.selling_unit
            HAVING SUM(s.sales_amount) > 0
            ORDER BY revenue DESC, p.product_name, p.product_id
            LIMIT 5
            """,
            (business["business_id"], month_start, today),
        )

        top_products = cursor.fetchall()

        # Use the same stock calculation as the Inventory page.
        cursor.execute(
            """
            SELECT
                p.product_id,
                p.product_name,
                p.selling_unit,
                COALESCE(
                    SUM(
                        CASE
                            WHEN m.movement_type IN (
                                'Stock In', 'Adjustment In'
                            )
                            THEN m.quantity
                            ELSE -m.quantity
                        END
                    ),
                    0
                ) AS available
            FROM products AS p
            LEFT JOIN stock_movements AS m
                ON m.product_id = p.product_id
            WHERE p.business_id = %s
            GROUP BY
                p.product_id,
                p.product_name,
                p.selling_unit
            HAVING available <= 0
            ORDER BY available, p.product_name
            """,
            (business["business_id"],),
        )

        stock_alerts = cursor.fetchall()

    return render_template(
        "business/dashboard.html",
        business=business,
        totals=totals,
        today=today,
        week_start=week_start,
        month_start=month_start,
        chart_days=chart_days,
        chart_start=chart_start,
        top_products=top_products,
        stock_alerts=stock_alerts,
        weather=weather,
        weather_error=weather_error,
    )

@app.route(
    "/business/products/bulk-edit",
    methods=["GET", "POST"],
)
@business_required
def bulk_edit_products():
    database = get_db()
    error = None

    try:
        product_ids = list(
            dict.fromkeys(
                int(value)
                for value in request.values.getlist("product_id")
            )
        )
    except (TypeError, ValueError):
        product_ids = []

    if not product_ids:
        flash(
            "Select at least one product to edit.",
            "product_error",
        )
        return redirect(url_for("business_products"))

    if len(product_ids) > 50:
        flash(
            "You can edit up to 50 products at a time.",
            "product_error",
        )
        return redirect(url_for("business_products"))

    placeholders = ", ".join(["%s"] * len(product_ids))

    with database.cursor() as cursor:
        cursor.execute(
            f"""
            SELECT
                products.product_id,
                products.product_name,
                products.category,
                products.selling_unit,
                products.selling_price
            FROM products
            INNER JOIN businesses
                ON businesses.business_id = products.business_id
            WHERE businesses.user_id = %s
              AND products.product_id IN ({placeholders})
            ORDER BY products.product_name
            """,
            (g.user["user_id"], *product_ids),
        )

        products = cursor.fetchall()

    if len(products) != len(product_ids):
        abort(404)

    values = {}

    for product in products:
        product_id = product["product_id"]

        values[product_id] = {
            "product_name": product["product_name"],
            "category": product["category"],
            "selling_price": str(product["selling_price"]),
        }

    if request.method == "POST":
        validate_csrf()
        cleaned_products = []
        submitted_names = set()

        for product in products:
            product_id = product["product_id"]

            row_values = {
                "product_name": request.form.get(
                    f"product_name_{product_id}",
                    "",
                ).strip(),
                "category": request.form.get(
                    f"category_{product_id}",
                    "",
                ).strip(),
                "selling_price": request.form.get(
                    f"selling_price_{product_id}",
                    "",
                ).strip(),
            }

            values[product_id] = row_values

            product_name = row_values["product_name"]
            category = row_values["category"]

            if not 1 <= len(product_name) <= 100:
                error = (
                    f'Enter a product name between 1 and 100 '
                    f'characters for "{product["product_name"]}".'
                )
                break

            normalized_name = product_name.casefold()

            if normalized_name in submitted_names:
                error = (
                    f'The product name "{product_name}" appears '
                    f"more than once."
                )
                break

            submitted_names.add(normalized_name)

            if category not in PRODUCT_CATEGORIES:
                error = (
                    f'Select a valid category for '
                    f'"{product_name}".'
                )
                break

            try:
                price = Decimal(
                    row_values["selling_price"]
                )

                if not price.is_finite():
                    raise ValueError

                if (
                    price < 0
                    or price > Decimal("99999999.99")
                    or price != price.quantize(Decimal("0.01"))
                ):
                    raise ValueError

            except (InvalidOperation, ValueError):
                error = (
                    f'Enter a valid price for "{product_name}".'
                )
                break

            cleaned_products.append({
                "product_id": product_id,
                "product_name": product_name,
                "category": category,
                "selling_price": price,
            })

        if error is None:
            try:
                database.begin()

                with database.cursor() as cursor:

                    cursor.execute(
                        f"""
                        SELECT product_id
                        FROM products
                        WHERE product_id IN ({placeholders})
                          AND business_id = (
                              SELECT business_id
                              FROM businesses
                              WHERE user_id = %s
                          )
                        FOR UPDATE
                        """,
                           (*product_ids, g.user["user_id"]),
                    )

                    owned_ids = {
                        row["product_id"]
                        for row in cursor.fetchall()
                    }

                    if owned_ids != set(product_ids):
                        raise ValueError(
                            "One or more selected products "
                            "are unavailable."
                        )

                    for product in cleaned_products:
                        cursor.execute(
                            """
                            UPDATE products
                            SET
                                product_name = %s,
                                category = %s,
                                selling_price = %s
                            WHERE product_id = %s
                            """,
                            (
                                product["product_name"],
                                product["category"],
                                product["selling_price"],
                                product["product_id"],
                            ),
                        )

                database.commit()

                flash(
                    f"{len(cleaned_products)} products "
                    f"updated successfully.",
                    "product_success",
                )

                return redirect(url_for("business_products"))

            except ValueError as validation_error:
                database.rollback()
                error = str(validation_error)

            except pymysql.err.IntegrityError as database_error:
                database.rollback()

                if database_error.args[0] == 1062:
                    error = (
                        "One of the product names is already used "
                        "by another product."
                    )
                else:
                    app.logger.exception(
                        "Bulk product update failed."
                    )
                    error = (
                        "The selected products could not be updated."
                    )

            except pymysql.MySQLError:
                database.rollback()
                app.logger.exception(
                    "Database error updating selected products."
                )
                error = (
                    "The selected products could not be updated. "
                    "Please try again."
                )

    return render_template(
        "business/bulk_edit_products.html",
        products=products,
        values=values,
        categories=PRODUCT_CATEGORIES,
        error=error,
    )


@app.route(
    "/business/products/<int:product_id>/edit",
    methods=["GET", "POST"],
)
@business_required
def edit_product(product_id):
    database = get_db()
    error = None

    # Only retrieve a product belonging to the signed-in business.
    with database.cursor() as cursor:
        cursor.execute(
            """
            SELECT p.product_id, p.product_name, p.category,
                   p.selling_unit, p.selling_price
            FROM products AS p
            JOIN businesses AS b ON b.business_id = p.business_id
            WHERE p.product_id = %s AND b.user_id = %s
            """,
            (product_id, g.user["user_id"]),
        )
        product = cursor.fetchone()

    if product is None:
        abort(404)

    values = {
        "product_name": product["product_name"],
        "category": product["category"],
        "selling_price": str(product["selling_price"]),
    }

    if request.method == "POST":
        validate_csrf()

        values = {
            "product_name": request.form.get("product_name", "").strip(),
            "category": request.form.get("category", "").strip(),
            "selling_price": request.form.get("selling_price", "").strip(),
        }

        price = None

        try:
            price = Decimal(values["selling_price"])

            if not price.is_finite():
                raise ValueError

            if price < 0 or price > Decimal("99999999.99"):
                raise ValueError

            if price != price.quantize(Decimal("0.01")):
                raise ValueError

        except (InvalidOperation, ValueError):
            error = (
                "Enter a price from 0 to 99,999,999.99 "
                "with no more than two decimal places."
            )

        if not 1 <= len(values["product_name"]) <= 100:
            error = "Enter a product name between 1 and 100 characters."

        if values["category"] not in PRODUCT_CATEGORIES:
            error = "Select a valid category."

        if error is None:
            try:
                with database.cursor() as cursor:
                    cursor.execute(
                        """
                        UPDATE products AS p
                        JOIN businesses AS b
                            ON b.business_id = p.business_id
                        SET p.product_name = %s,
                            p.category = %s,
                            p.selling_price = %s
                        WHERE p.product_id = %s AND b.user_id = %s
                        """,
                        (
                            values["product_name"],
                            values["category"],
                            price,
                            product_id,
                            g.user["user_id"],
                        ),
                    )

                flash("Product updated successfully.", "product_success")
                return redirect(url_for("business_products"))

            except pymysql.err.IntegrityError as database_error:
                if database_error.args[0] == 1062:
                    error = "This product name already exists in your business."
                else:
                    app.logger.exception("Product update failed.")
                    error = "The product could not be updated."

            except pymysql.MySQLError:
                app.logger.exception("Database error updating a product.")
                error = "The product could not be updated. Please try again."

    return render_template(
        "business/edit_product.html",
        product=product,
        values=values,
        error=error,
        categories=PRODUCT_CATEGORIES,
    )

@app.route("/business/products", methods=["GET", "POST"])
@business_required
def business_products():
    database = get_db()
    error = None

    values = {
        "product_name": "",
        "selling_unit": "",
        "selling_price": "",
    }

    allowed_units = ("Piece", "Serving", "Pack", "Bottle")

    # Identify the business using the signed-in account.
    with database.cursor() as cursor:
        cursor.execute(
            """
            SELECT business_id, business_name, business_type, created_at
            FROM businesses
            WHERE user_id = %s
            """,
            (g.user["user_id"],),
        )

        business = cursor.fetchone()

    if business is None:
        abort(403, description="Your account has no linked business.")

    if request.method == "POST":
        validate_csrf()

        values = {
            "product_name": request.form.get(
                "product_name", ""
            ).strip(),
            "selling_unit": request.form.get(
                "selling_unit", ""
            ).strip(),
            "selling_price": request.form.get(
                "selling_price", ""
            ).strip(),
        }

        price = None

        try:
            price = Decimal(values["selling_price"])

            if not price.is_finite():
                raise ValueError

            if price < 0 or price > Decimal("99999999.99"):
                raise ValueError

            if price != price.quantize(Decimal("0.01")):
                raise ValueError

        except (InvalidOperation, ValueError):
            error = (
                "Enter a price from 0 to 99,999,999.99 "
                "with no more than two decimal places."
            )

        if not 1 <= len(values["product_name"]) <= 100:
            error = "Enter a product name between 1 and 100 characters."

        elif values["selling_unit"] not in allowed_units:
            error = "Select a valid selling unit."

        if error is None:
            try:
                with database.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO products (
                            business_id,
                            product_name,
                            selling_unit,
                            selling_price
                        )
                        VALUES (%s, %s, %s, %s)
                        """,
                        (
                            business["business_id"],
                            values["product_name"],
                            values["selling_unit"],
                            price,
                        ),
                    )

                return redirect(url_for("business_products"))

            except pymysql.err.IntegrityError as database_error:
                if database_error.args[0] == 1062:
                    error = "This product name already exists in your business."
                else:
                    app.logger.exception("Product creation failed.")
                    error = "The product could not be saved."

            except pymysql.MySQLError:
                app.logger.exception("Database error while saving a product.")
                error = "The product could not be saved. Please try again."

    # Read the search text from the page URL.
    search = request.args.get("search", "").strip()[:100]

    with database.cursor() as cursor:
        cursor.execute(
            """
            SELECT
                product_id,
                product_name,
                selling_unit,
                selling_price
            FROM products
            WHERE business_id = %s
              AND LOCATE(%s, product_name) > 0
            ORDER BY product_name
            """,
            (business["business_id"], search),
        )

        products = cursor.fetchall()

    return render_template(
        "business/products.html",
        business=business,
        products=products,
        allowed_units=allowed_units,
        values=values,
        error=error,
        search=search,
    )

@app.route("/business/sales", methods=["GET", "POST"])
@business_required
def business_sales():
    database = get_db()
    error = None

    today = datetime.now(
        timezone(timedelta(hours=8))
    ).date()

    filters = {
        "start_date": request.args.get("start_date", "").strip(),
        "end_date": request.args.get("end_date", "").strip(),
        "search": request.args.get("search", "").strip()[:100],
    }

    start_date = None
    end_date = None
    filter_error = None

    try:
        if filters["start_date"]:
            start_date = date.fromisoformat(filters["start_date"])

        if filters["end_date"]:
            end_date = date.fromisoformat(filters["end_date"])

        if start_date and end_date and start_date > end_date:
            filter_error = "Start date must be on or before end date."

    except ValueError:
        filter_error = "Enter valid dates for the sales filter."

    with database.cursor() as cursor:
        cursor.execute(
            """
            SELECT business_id, business_name, business_type, created_at
            FROM businesses
            WHERE user_id = %s
            """,
            (g.user["user_id"],),
        )

        business = cursor.fetchone()

        if business is None:
            abort(403, description="Your account has no linked business.")

        cursor.execute(
            """
            SELECT product_id, product_name, selling_unit, selling_price
            FROM products
            WHERE business_id = %s
            ORDER BY product_name
            """,
            (business["business_id"],),
        )

        products = cursor.fetchall()

    values = {
        "product_id": "",
        "sale_date": today.isoformat(),
        "quantity_sold": "",
        "sales_amount": "",
    }

    if request.method == "POST":
        validate_csrf()

        values = {
            field: request.form.get(field, "").strip()
            for field in values
        }

        # Only accept a product belonging to this business.
        selected_product = next(
            (
                product for product in products
                if str(product["product_id"]) == values["product_id"]
            ),
            None,
        )

        sale_date = None
        quantity = None
        amount = None

        try:
            sale_date = date.fromisoformat(values["sale_date"])

            if sale_date > today:
                error = "Actual sales cannot have a future date."

        except ValueError:
            error = "Enter a valid sales date."

        try:
            quantity = int(values["quantity_sold"])

            if quantity < 0 or quantity > 2147483647:
                raise ValueError

        except ValueError:
            error = "Enter a valid whole-number quantity of zero or more."

        if selected_product is None:
            error = "Choose one of your products."

        if error is None:
            # Calculate from the database price, not the submitted total.
            price = Decimal(str(selected_product["selling_price"]))
            amount = (price * quantity).quantize(Decimal("0.01"))

            if (
                not amount.is_finite()
                or amount < 0
                or amount > Decimal("9999999999.99")
            ):
                error = "The total is too large. Please check the quantity."
                values["sales_amount"] = ""
            else:
                values["sales_amount"] = format(amount, ".2f")

        if error is None:
            try:
                database.begin()

                with database.cursor() as cursor:
                    # Lock the selected product while checking its stock.
                    cursor.execute(
                        """
                        SELECT product_id
                        FROM products
                        WHERE product_id = %s
                          AND business_id = %s
                        FOR UPDATE
                        """,
                        (
                            selected_product["product_id"],
                            business["business_id"],
                        ),
                    )

                    owned_product = cursor.fetchone()

                    if owned_product is None:
                        error = "Choose one of your products."

                    else:
                        cursor.execute(
                            """
                            SELECT COALESCE(
                                SUM(
                                    CASE
                                        WHEN movement_type IN (
                                            'Stock In',
                                            'Adjustment In'
                                        )
                                        THEN quantity
                                        ELSE -quantity
                                    END
                                ),
                                0
                            ) AS available_stock
                            FROM stock_movements
                            WHERE product_id = %s
                            """,
                            (selected_product["product_id"],),
                        )

                        available_stock = int(
                            cursor.fetchone()["available_stock"]
                        )

                        if quantity > available_stock:
                            error = (
                                f"Only {available_stock} "
                                f"{selected_product['selling_unit']} "
                                "are available. Add stock before "
                                "recording this sale."
                            )

                        else:
                            cursor.execute(
                                """
                                INSERT INTO daily_sales (
                                    product_id,
                                    sale_date,
                                    quantity_sold,
                                    sales_amount
                                )
                                VALUES (%s, %s, %s, %s)
                                """,
                                (
                                    selected_product["product_id"],
                                    sale_date,
                                    quantity,
                                    amount,
                                ),
                            )

                            sale_id = cursor.lastrowid

                            if quantity > 0:
                                cursor.execute(
                                    """
                                    INSERT INTO stock_movements (
                                        product_id,
                                        sale_id,
                                        movement_type,
                                        quantity,
                                        notes
                                    )
                                    VALUES (
                                        %s,
                                        %s,
                                        'Sold',
                                        %s,
                                        %s
                                    )
                                    """,
                                    (
                                        selected_product["product_id"],
                                        sale_id,
                                        quantity,
                                        "Automatically recorded from sales.",
                                    ),
                                )

                if error:
                    database.rollback()
                else:
                    database.commit()
                    return redirect(url_for("business_sales"))

            except pymysql.err.IntegrityError as database_error:
                database.rollback()

                if database_error.args[0] == 1062:
                    error = (
                        "This product already has a sales record "
                        "for that date."
                    )
                else:
                    app.logger.exception(
                        "Sales record could not be saved."
                    )
                    error = "The sales record could not be saved."

            except pymysql.MySQLError:
                database.rollback()
                app.logger.exception(
                    "Database error while saving sales."
                )
                error = (
                    "The sales record could not be saved. "
                    "Try again."
                )
    sales = []

    summary = {
        "total_sales": Decimal("0.00"),
        "record_count": 0,
        "total_units": 0,
        "average_daily_sales": Decimal("0.00"),
        "best_seller_name": None,
        "best_seller_units": 0,
        "sales_change_pct": None,
        "units_change_pct": None,
        "average_daily_change_pct": None,
    }

    if filter_error is None:
        # The stat cards always compare two equal-length periods. When the
        # person hasn't chosen dates, default to the last 30 days so the
        # percentages have something to compare against. This does not
        # affect which rows appear in the table below, which still shows
        # all-time entries until a date filter is applied.
        stat_end = end_date or today
        stat_start = start_date or (stat_end - timedelta(days=29))
        period_days = (stat_end - stat_start).days + 1

        previous_end = stat_start - timedelta(days=1)
        previous_start = previous_end - timedelta(days=period_days - 1)

        def percent_change(current, previous):
            if previous:
                return float((current - previous) / previous * 100)
            return None if current == 0 else 100.0

        with database.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    COALESCE(SUM(daily_sales.sales_amount), 0)
                        AS total_sales,
                    COUNT(*) AS record_count,
                    COALESCE(SUM(daily_sales.quantity_sold), 0)
                        AS total_units
                FROM daily_sales
                INNER JOIN products
                    ON products.product_id = daily_sales.product_id
                WHERE products.business_id = %s
                  AND daily_sales.sale_date BETWEEN %s AND %s
                  AND LOCATE(%s, products.product_name) > 0
                """,
                (
                    business["business_id"],
                    stat_start,
                    stat_end,
                    filters["search"],
                ),
            )

            current_totals = cursor.fetchone()

            cursor.execute(
                """
                SELECT
                    COALESCE(SUM(daily_sales.sales_amount), 0)
                        AS total_sales,
                    COALESCE(SUM(daily_sales.quantity_sold), 0)
                        AS total_units
                FROM daily_sales
                INNER JOIN products
                    ON products.product_id = daily_sales.product_id
                WHERE products.business_id = %s
                  AND daily_sales.sale_date BETWEEN %s AND %s
                  AND LOCATE(%s, products.product_name) > 0
                """,
                (
                    business["business_id"],
                    previous_start,
                    previous_end,
                    filters["search"],
                ),
            )

            previous_totals = cursor.fetchone()

            cursor.execute(
                """
                SELECT
                    products.product_name,
                    SUM(daily_sales.quantity_sold) AS total_units
                FROM daily_sales
                INNER JOIN products
                    ON products.product_id = daily_sales.product_id
                WHERE products.business_id = %s
                  AND daily_sales.sale_date BETWEEN %s AND %s
                  AND LOCATE(%s, products.product_name) > 0
                GROUP BY products.product_id, products.product_name
                ORDER BY total_units DESC
                LIMIT 1
                """,
                (
                    business["business_id"],
                    stat_start,
                    stat_end,
                    filters["search"],
                ),
            )

            best_seller = cursor.fetchone()

            summary["total_sales"] = current_totals["total_sales"]
            summary["record_count"] = current_totals["record_count"]
            summary["total_units"] = current_totals["total_units"]
            summary["average_daily_sales"] = (
                current_totals["total_sales"] / period_days
            )

            previous_average_daily = (
                previous_totals["total_sales"] / period_days
            )

            summary["sales_change_pct"] = percent_change(
                current_totals["total_sales"], previous_totals["total_sales"]
            )
            summary["units_change_pct"] = percent_change(
                current_totals["total_units"], previous_totals["total_units"]
            )
            summary["average_daily_change_pct"] = percent_change(
                summary["average_daily_sales"], previous_average_daily
            )

            if best_seller is not None:
                summary["best_seller_name"] = best_seller["product_name"]
                summary["best_seller_units"] = best_seller["total_units"]

            cursor.execute(
                """
                SELECT
                    daily_sales.sale_id,
                    daily_sales.sale_date,
                    daily_sales.quantity_sold,
                    daily_sales.sales_amount,
                    products.product_name,
                    products.selling_unit,
                    CASE
                        WHEN daily_sales.quantity_sold > 0
                        THEN daily_sales.sales_amount / daily_sales.quantity_sold
                        ELSE products.selling_price
                    END AS unit_price
                FROM daily_sales
                INNER JOIN products
                    ON products.product_id = daily_sales.product_id
                WHERE products.business_id = %s
                  AND (%s IS NULL OR daily_sales.sale_date >= %s)
                  AND (%s IS NULL OR daily_sales.sale_date <= %s)
                  AND LOCATE(%s, products.product_name) > 0
                ORDER BY
                    daily_sales.sale_date DESC,
                    daily_sales.sale_id DESC
                LIMIT 50
                """,
                (
                    business["business_id"],
                    start_date,
                    start_date,
                    end_date,
                    end_date,
                    filters["search"],
                ),
            )

            sales = cursor.fetchall()
    total_label = "Total for all dates"

    if filter_error is None:
        if start_date and end_date:
            if start_date == end_date:
                total_label = f"Total for {start_date.strftime('%b')} {start_date.day}, {start_date.year}"

            elif (
                start_date.year == end_date.year
                and start_date.month == end_date.month
            ):
                total_label = (
                    f"Total for {start_date.strftime('%b')} "
                    f"{start_date.day}–{end_date.day}, {end_date.year}"
                )

            elif start_date.year == end_date.year:
                total_label = (
                    f"Total for {start_date.strftime('%b')} {start_date.day}"
                    f" – {end_date.strftime('%b')} {end_date.day}, {end_date.year}"
                )

            else:
                total_label = (
                    f"Total for {start_date.strftime('%b')} {start_date.day}, {start_date.year}"
                    f" – {end_date.strftime('%b')} {end_date.day}, {end_date.year}"
                )

        elif start_date:
            total_label = (
                f"Total from {start_date.strftime('%b')} "
                f"{start_date.day}, {start_date.year} onward"
            )

        elif end_date:
            total_label = (
                f"Total through {end_date.strftime('%b')} "
                f"{end_date.day}, {end_date.year}"
            )

    return render_template(
        "business/sales.html",
        business=business,
        products=products,
        sales=sales,
        values=values,
        today=today.isoformat(),
        error=error,
        filters=filters,
        filter_error=filter_error,
        summary=summary,
        total_label=total_label,
    )

@app.route(
    "/business/sales/<int:sale_id>/edit",
    methods=["GET", "POST"],
)
@business_required
def edit_sale(sale_id):
    database = get_db()
    error = None

    today = datetime.now(
        timezone(timedelta(hours=8))
    ).date()

    # Find the record only if it belongs to the signed-in business.
    with database.cursor() as cursor:
        cursor.execute(
            """
            SELECT
                daily_sales.sale_id,
                daily_sales.product_id,
                daily_sales.sale_date,
                daily_sales.quantity_sold,
                daily_sales.sales_amount,
                products.product_name,
                products.selling_unit
            FROM daily_sales
            INNER JOIN products
                ON products.product_id = daily_sales.product_id
            INNER JOIN businesses
                ON businesses.business_id = products.business_id
            WHERE daily_sales.sale_id = %s
              AND businesses.user_id = %s
            """,
            (sale_id, g.user["user_id"]),
        )

        sale = cursor.fetchone()

    if sale is None:
        abort(404)

    values = {
        "sale_date": sale["sale_date"].isoformat(),
        "quantity_sold": str(sale["quantity_sold"]),
        "sales_amount": str(sale["sales_amount"]),
    }

    if request.method == "POST":
        validate_csrf()

        values = {
            field: request.form.get(field, "").strip()
            for field in values
        }

        sale_date = None
        quantity = None
        amount = None

        try:
            sale_date = date.fromisoformat(values["sale_date"])

            if sale_date > today:
                error = "Actual sales cannot have a future date."

        except ValueError:
            error = "Enter a valid sales date."

        try:
            quantity = int(values["quantity_sold"])

            if quantity < 0 or quantity > 2147483647:
                raise ValueError

        except ValueError:
            error = "Enter a valid whole-number quantity of zero or more."

        try:
            amount = Decimal(values["sales_amount"])

            if not amount.is_finite():
                raise ValueError

            if amount < 0 or amount > Decimal("9999999999.99"):
                raise ValueError

            if amount != amount.quantize(Decimal("0.01")):
                raise ValueError

        except (InvalidOperation, ValueError):
            error = (
                "Enter a sales amount from 0 to 9,999,999,999.99 "
                "with no more than two decimal places."
            )

        if error is None and quantity == 0 and amount != 0:
            error = "Sales amount must be zero when quantity sold is zero."

        if error is None:
            try:
                database.begin()

                with database.cursor() as cursor:
                    # Lock the product while its sale and stock are updated.
                    cursor.execute(
                        """
                        SELECT product_id
                        FROM products
                        WHERE product_id = %s
                          AND business_id = (
                              SELECT business_id
                              FROM businesses
                              WHERE user_id = %s
                          )
                        FOR UPDATE
                        """,
                        (
                            sale["product_id"],
                            g.user["user_id"],
                        ),
                    )

                    owned_product = cursor.fetchone()

                    if owned_product is None:
                        error = "This sale does not belong to your business."

                    else:
                        # Calculate stock without this sale's old deduction.
                        cursor.execute(
                            """
                            SELECT COALESCE(
                                SUM(
                                    CASE
                                        WHEN movement_type IN (
                                            'Stock In',
                                            'Adjustment In'
                                        )
                                        THEN quantity
                                        ELSE -quantity
                                    END
                                ),
                                0
                            ) AS available_without_sale
                            FROM stock_movements
                            WHERE product_id = %s
                              AND (
                                  sale_id IS NULL
                                  OR sale_id != %s
                              )
                            """,
                            (
                                sale["product_id"],
                                sale_id,
                            ),
                        )

                        available_without_sale = int(
                            cursor.fetchone()[
                                "available_without_sale"
                            ]
                        )

                        if quantity > available_without_sale:
                            error = (
                                f"Only {available_without_sale} "
                                f"{sale['selling_unit']} are available. "
                                "Add stock before increasing this sale."
                            )

                        else:
                            cursor.execute(
                                """
                                UPDATE daily_sales
                                SET
                                    sale_date = %s,
                                    quantity_sold = %s,
                                    sales_amount = %s
                                WHERE sale_id = %s
                                  AND product_id = %s
                                """,
                                (
                                    sale_date,
                                    quantity,
                                    amount,
                                    sale_id,
                                    sale["product_id"],
                                ),
                            )

                            if quantity == 0:
                                cursor.execute(
                                    """
                                    DELETE FROM stock_movements
                                    WHERE sale_id = %s
                                    """,
                                    (sale_id,),
                                )

                            else:
                                cursor.execute(
                                    """
                                    INSERT INTO stock_movements (
                                        product_id,
                                        sale_id,
                                        movement_type,
                                        quantity,
                                        notes
                                    )
                                    VALUES (
                                        %s,
                                        %s,
                                        'Sold',
                                        %s,
                                        %s
                                    )
                                    ON DUPLICATE KEY UPDATE
                                        product_id = VALUES(product_id),
                                        movement_type = 'Sold',
                                        quantity = VALUES(quantity),
                                        notes = VALUES(notes)
                                    """,
                                    (
                                        sale["product_id"],
                                        sale_id,
                                        quantity,
                                        "Automatically recorded from sales.",
                                    ),
                                )

                if error:
                    database.rollback()
                else:
                    database.commit()
                    return redirect(url_for("business_sales"))

            except pymysql.err.IntegrityError as database_error:
                database.rollback()

                if database_error.args[0] == 1062:
                    error = (
                        "This product already has a record "
                        "for the selected date."
                    )
                else:
                    app.logger.exception("Sales update failed.")
                    error = "The changes could not be saved."

            except pymysql.MySQLError:
                database.rollback()
                app.logger.exception(
                    "Database error while updating sales."
                )
                error = "The changes could not be saved. Try again."

    return render_template(
        "business/edit_sale.html",
        sale=sale,
        values=values,
        today=today.isoformat(),
        error=error,
    )

@app.route(
    "/business/sales/bulk-edit",
    methods=["GET", "POST"],
)
@business_required
def bulk_edit_sales():
    database = get_db()
    error = None

    today = datetime.now(
        timezone(timedelta(hours=8))
    ).date()

    try:
        sale_ids = list(
            dict.fromkeys(
                int(value)
                for value in request.values.getlist("sale_id")
            )
        )
    except (TypeError, ValueError):
        sale_ids = []

    if not sale_ids:
        flash(
            "Select at least one sales record to edit.",
            "sales_error",
        )
        return redirect(url_for("business_sales"))

    if len(sale_ids) > 50:
        flash(
            "You can edit up to 50 sales records at a time.",
            "sales_error",
        )
        return redirect(url_for("business_sales"))

    placeholders = ", ".join(["%s"] * len(sale_ids))

    with database.cursor() as cursor:
        cursor.execute(
            f"""
            SELECT
                daily_sales.sale_id,
                daily_sales.product_id,
                daily_sales.sale_date,
                daily_sales.quantity_sold,
                daily_sales.sales_amount,
                products.product_name,
                products.selling_unit
            FROM daily_sales
            INNER JOIN products
                ON products.product_id = daily_sales.product_id
            INNER JOIN businesses
                ON businesses.business_id = products.business_id
            WHERE businesses.user_id = %s
              AND daily_sales.sale_id IN ({placeholders})
            ORDER BY daily_sales.sale_date DESC,
                     products.product_name
            """,
            (g.user["user_id"], *sale_ids),
        )

        sales = cursor.fetchall()

    if len(sales) != len(sale_ids):
        abort(404)

    values = {}

    for sale in sales:
        sale_id = sale["sale_id"]

        values[sale_id] = {
            "sale_date": sale["sale_date"].isoformat(),
            "quantity_sold": str(sale["quantity_sold"]),
            "sales_amount": str(sale["sales_amount"]),
        }

    if request.method == "POST":
        validate_csrf()
        cleaned_sales = []

        for sale in sales:
            sale_id = sale["sale_id"]

            row_values = {
                "sale_date": request.form.get(
                    f"sale_date_{sale_id}",
                    "",
                ).strip(),
                "quantity_sold": request.form.get(
                    f"quantity_sold_{sale_id}",
                    "",
                ).strip(),
                "sales_amount": request.form.get(
                    f"sales_amount_{sale_id}",
                    "",
                ).strip(),
            }

            values[sale_id] = row_values

            try:
                sale_date = date.fromisoformat(
                    row_values["sale_date"]
                )

                if sale_date > today:
                    raise ValueError

            except ValueError:
                error = (
                    f'Enter a valid date for '
                    f'"{sale["product_name"]}".'
                )
                break

            try:
                quantity = int(
                    row_values["quantity_sold"]
                )

                if quantity < 0 or quantity > 2147483647:
                    raise ValueError

            except ValueError:
                error = (
                    f'Enter a valid whole-number quantity for '
                    f'"{sale["product_name"]}".'
                )
                break

            try:
                amount = Decimal(
                    row_values["sales_amount"]
                )

                if not amount.is_finite():
                    raise ValueError

                if (
                    amount < 0
                    or amount > Decimal("9999999999.99")
                    or amount != amount.quantize(Decimal("0.01"))
                ):
                    raise ValueError

            except (InvalidOperation, ValueError):
                error = (
                    f'Enter a valid sales amount for '
                    f'"{sale["product_name"]}".'
                )
                break

            if quantity == 0 and amount != 0:
                error = (
                    f'The sales amount for '
                    f'"{sale["product_name"]}" must be zero '
                    f"when its quantity is zero."
                )
                break

            cleaned_sales.append({
                "sale_id": sale_id,
                "product_id": sale["product_id"],
                "product_name": sale["product_name"],
                "sale_date": sale_date,
                "quantity": quantity,
                "amount": amount,
            })

        if error is None:
            selected_product_ids = list(
                dict.fromkeys(
                    row["product_id"]
                    for row in cleaned_sales
                )
            )

            product_placeholders = ", ".join(
                ["%s"] * len(selected_product_ids)
            )

            requested_quantities = {}

            for row in cleaned_sales:
                product_id = row["product_id"]

                requested_quantities[product_id] = (
                    requested_quantities.get(product_id, 0)
                    + row["quantity"]
                )

            try:
                database.begin()

                with database.cursor() as cursor:
                    cursor.execute(
                        f"""
                        SELECT
                            product_id,
                            COALESCE(
                                SUM(
                                    CASE
                                        WHEN movement_type IN (
                                            'Stock In',
                                            'Adjustment In'
                                        )
                                        THEN quantity
                                        ELSE -quantity
                                    END
                                ),
                                0
                            ) AS available_without_selected_sales
                        FROM stock_movements
                        WHERE product_id IN ({product_placeholders})
                          AND (
                              sale_id IS NULL
                              OR sale_id NOT IN ({placeholders})
                          )
                        GROUP BY product_id
                        FOR UPDATE
                        """,
                        (
                            *selected_product_ids,
                            *sale_ids,
                        ),
                    )

                    available_by_product = {
                        row["product_id"]: int(
                            row["available_without_selected_sales"]
                        )
                        for row in cursor.fetchall()
                    }

                    for row in cleaned_sales:
                        product_id = row["product_id"]
                        available = available_by_product.get(
                            product_id,
                            0,
                        )

                        if (
                            requested_quantities[product_id]
                            > available
                        ):
                            error = (
                                f'Only {available} units are available '
                                f'for "{row["product_name"]}".'
                            )
                            break

                    if error is None:
                        for row in cleaned_sales:
                            cursor.execute(
                                """
                                UPDATE daily_sales
                                SET
                                    sale_date = %s,
                                    quantity_sold = %s,
                                    sales_amount = %s
                                WHERE sale_id = %s
                                """,
                                (
                                    row["sale_date"],
                                    row["quantity"],
                                    row["amount"],
                                    row["sale_id"],
                                ),
                            )

                            if row["quantity"] == 0:
                                cursor.execute(
                                    """
                                    DELETE FROM stock_movements
                                    WHERE sale_id = %s
                                    """,
                                    (row["sale_id"],),
                                )

                            else:
                                cursor.execute(
                                    """
                                    INSERT INTO stock_movements (
                                        product_id,
                                        sale_id,
                                        movement_type,
                                        quantity,
                                        notes
                                    )
                                    VALUES (
                                        %s,
                                        %s,
                                        'Sold',
                                        %s,
                                        %s
                                    )
                                    ON DUPLICATE KEY UPDATE
                                        product_id = VALUES(product_id),
                                        movement_type = 'Sold',
                                        quantity = VALUES(quantity),
                                        notes = VALUES(notes)
                                    """,
                                    (
                                        row["product_id"],
                                        row["sale_id"],
                                        row["quantity"],
                                        (
                                            "Automatically recorded "
                                            "from sales."
                                        ),
                                    ),
                                )

                if error:
                    database.rollback()

                else:
                    database.commit()

                    flash(
                        f"{len(cleaned_sales)} sales records "
                        f"updated successfully.",
                        "sales_success",
                    )

                    return redirect(
                        url_for("business_sales")
                    )

            except pymysql.err.IntegrityError as database_error:
                database.rollback()

                if database_error.args[0] == 1062:
                    error = (
                        "A product already has a sales record "
                        "for one of the selected dates."
                    )
                else:
                    app.logger.exception(
                        "Bulk sales update failed."
                    )
                    error = (
                        "The selected sales could not be updated."
                    )

            except pymysql.MySQLError:
                database.rollback()
                app.logger.exception(
                    "Database error updating selected sales."
                )
                error = (
                    "The selected sales could not be updated. "
                    "Please try again."
                )

    return render_template(
        "business/bulk_edit_sales.html",
        sales=sales,
        values=values,
        today=today.isoformat(),
        error=error,
    )


@app.route("/business/sales/<int:sale_id>/delete", methods=["POST"])
@business_required
def delete_sale(sale_id):

    @app.route("/business/sales/<int:sale_id>/delete", methods=["POST"])
    @business_required
    def delete_sale(sale_id):
      validate_csrf()

    with get_db().cursor() as cursor:
        cursor.execute(
            """
            SELECT daily_sales.sale_id
            FROM daily_sales
            INNER JOIN products
                ON products.product_id = daily_sales.product_id
            INNER JOIN businesses
                ON businesses.business_id = products.business_id
            WHERE daily_sales.sale_id = %s
              AND businesses.user_id = %s
            """,
            (sale_id, g.user["user_id"]),
        )

        if cursor.fetchone() is None:
            abort(404)

        cursor.execute(
            "DELETE FROM daily_sales WHERE sale_id = %s",
            (sale_id,),
        )

    flash("Sales record deleted.", "sales_success")

    return redirect(url_for("business_sales"))


@app.route("/business/sales/bulk-delete", methods=["POST"])
@business_required
def bulk_delete_sales():
    validate_csrf()

    try:
        sale_ids = list(
            dict.fromkeys(
                int(value)
                for value in request.form.getlist("sale_id")
            )
        )
    except (TypeError, ValueError):
        sale_ids = []

    if not sale_ids:
        flash(
            "Select at least one sales record to delete.",
            "sales_error",
        )
        return redirect(url_for("business_sales"))

    if len(sale_ids) > 200:
        flash(
            "You can delete up to 200 sales records at a time.",
            "sales_error",
        )
        return redirect(url_for("business_sales"))

    database = get_db()
    placeholders = ", ".join(["%s"] * len(sale_ids))

    try:
        database.begin()

        with database.cursor() as cursor:
            cursor.execute(
                f"""
                SELECT daily_sales.sale_id
                FROM daily_sales
                INNER JOIN products
                    ON products.product_id = daily_sales.product_id
                INNER JOIN businesses
                    ON businesses.business_id = products.business_id
                WHERE businesses.user_id = %s
                  AND daily_sales.sale_id IN ({placeholders})
                FOR UPDATE
                """,
                (g.user["user_id"], *sale_ids),
            )

            owned_ids = {
                row["sale_id"]
                for row in cursor.fetchall()
            }

            if owned_ids != set(sale_ids):
                raise ValueError(
                    "One or more selected sales records "
                    "are unavailable."
                )

            cursor.execute(
                f"""
                DELETE daily_sales
                FROM daily_sales
                INNER JOIN products
                    ON products.product_id = daily_sales.product_id
                INNER JOIN businesses
                    ON businesses.business_id = products.business_id
                WHERE businesses.user_id = %s
                  AND daily_sales.sale_id IN ({placeholders})
                """,
                (g.user["user_id"], *sale_ids),
            )

        database.commit()

        flash(
            f"{len(sale_ids)} selected sales record(s) deleted.",
            "sales_success",
        )

    except ValueError as error:
        database.rollback()
        flash(str(error), "sales_error")

    except pymysql.MySQLError:
        database.rollback()
        app.logger.exception(
            "Database error deleting selected sales records."
        )
        flash(
            "The selected sales records could not be deleted.",
            "sales_error",
        )

    return redirect(url_for("business_sales"))

@app.route("/business/help")
@business_required
def user_manual():
    with get_db().cursor() as cursor:
        cursor.execute(
            """
            SELECT
                business_id,
                business_name,
                business_type,
                created_at,
                location_latitude,
                location_longitude,
                location_name,
                location_accuracy_m,
                location_updated_at
            FROM businesses
            WHERE user_id = %s
            """,
            (g.user["user_id"],),
        )

        business = cursor.fetchone()

    if business is None:
        abort(403)

    return render_template(
        "business/user_manual.html",
        business=business,
    )


@app.route("/js/sidebar.js")
def sidebar_script():
    return send_from_directory(
        BASE_DIR / "static" / "js",
        "sidebar.js",
    )

@app.route("/js/theme.js")
def theme_script():
    return send_from_directory(
        BASE_DIR / "static" / "js",
        "theme.js",
    )

@app.route("/business/sales/export")
@business_required
def export_sales():
    start_text = request.args.get("start_date", "").strip()
    end_text = request.args.get("end_date", "").strip()

    start_date = None
    end_date = None

    try:
        if start_text:
            start_date = date.fromisoformat(start_text)

        if end_text:
            end_date = date.fromisoformat(end_text)

        if start_date and end_date and start_date > end_date:
            raise ValueError

    except ValueError:
        abort(
            400,
            description=(
                "Invalid date range. Return to Sales "
                "and correct the filters."
            ),
        )

    with get_db().cursor() as cursor:
        cursor.execute(
            """
            SELECT business_id
            FROM businesses
            WHERE user_id = %s
            """,
            (g.user["user_id"],),
        )

        business = cursor.fetchone()

        if business is None:
            abort(403, description="Your account has no linked business.")

        cursor.execute(
            """
            SELECT
                daily_sales.sale_date,
                products.product_name,
                products.selling_unit,
                daily_sales.quantity_sold,
                daily_sales.sales_amount
            FROM daily_sales
            INNER JOIN products
                ON products.product_id = daily_sales.product_id
            WHERE products.business_id = %s
              AND (%s IS NULL OR daily_sales.sale_date >= %s)
              AND (%s IS NULL OR daily_sales.sale_date <= %s)
            ORDER BY
                daily_sales.sale_date DESC,
                daily_sales.sale_id DESC
            """,
            (
                business["business_id"],
                start_date,
                start_date,
                end_date,
                end_date,
            ),
        )

        sales = cursor.fetchall()

    def spreadsheet_text(value):
        text = str(value)

        # Prevent product names from being interpreted as formulas.
        if text.lstrip().startswith(("=", "+", "-", "@")):
            return "'" + text

        if text.startswith(("\t", "\r", "\n")):
            return "'" + text

        return text

    output = io.StringIO(newline="")
    writer = csv.writer(output)

    writer.writerow([
        "Date",
        "Product",
        "Selling Unit",
        "Quantity Sold",
        "Sales Amount (PHP)",
    ])

    for sale in sales:
        writer.writerow([
            sale["sale_date"].isoformat(),
            spreadsheet_text(sale["product_name"]),
            spreadsheet_text(sale["selling_unit"]),
            sale["quantity_sold"],
            format(sale["sales_amount"], ".2f"),
        ])

    start_label = start_date.isoformat() if start_date else "beginning"
    end_label = end_date.isoformat() if end_date else "latest"

    filename = f"sales_{start_label}_to_{end_label}.csv"

    # UTF-8 BOM helps Excel recognize characters correctly.
    csv_content = output.getvalue().encode("utf-8-sig")
    output.close()

    return Response(
        csv_content,
        content_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )

@app.route("/business/inventory", methods=["GET", "POST"])
@business_required
def business_inventory():
    database = get_db()
    error = None

    movement_types = (
    "Stock In",
    "Waste",
    "Adjustment In",
    "Adjustment Out",
)

    outgoing_types = ("Waste", "Adjustment Out")

    values = {
        "product_id": "",
        "movement_type": "",
        "quantity": "",
        "notes": "",
    }

    with database.cursor() as cursor:
        cursor.execute(
            """
            SELECT business_id, business_name, business_type, created_at
            FROM businesses
            WHERE user_id = %s
            """,
            (g.user["user_id"],),
        )

        business = cursor.fetchone()

    if business is None:
        abort(403, description="Your account has no linked business.")

    if request.method == "POST":
        validate_csrf()

        values = {
            field: request.form.get(field, "").strip()
            for field in values
        }

        product_id = None
        quantity = None

        try:
            product_id = int(values["product_id"])
            quantity = int(values["quantity"])

            if quantity < 1 or quantity > 2147483647:
                raise ValueError

        except ValueError:
            error = "Select a product and enter a positive whole quantity."

        if values["movement_type"] not in movement_types:
            error = "Select a valid movement type."

        if len(values["notes"]) > 255:
            error = "Notes cannot exceed 255 characters."

        if (
            values["movement_type"] in ("Adjustment In", "Adjustment Out")
            and not values["notes"]
        ):
            error = "Explain the reason for the stock adjustment."

        if error is None:
            try:
                database.begin()

                with database.cursor() as cursor:
                    # Lock this product while checking and changing its stock.
                    cursor.execute(
                        """
                        SELECT product_id
                        FROM products
                        WHERE product_id = %s
                          AND business_id = %s
                        FOR UPDATE
                        """,
                        (product_id, business["business_id"]),
                    )

                    product = cursor.fetchone()

                    if product is None:
                        error = "Select one of your business's products."

                    else:
                        cursor.execute(
                            """
                            SELECT COALESCE(
                                SUM(
                                    CASE
                                        WHEN movement_type IN (
                                            'Stock In', 'Adjustment In'
                                        )
                                        THEN quantity
                                        ELSE -quantity
                                    END
                                ),
                                0
                            ) AS available
                            FROM stock_movements
                            WHERE product_id = %s
                            """,
                            (product_id,),
                        )

                        available = cursor.fetchone()["available"]

                        if (
                            values["movement_type"] in outgoing_types
                            and quantity > available
                        ):
                            error = (
                                f"Only {available} units are available. "
                                "You cannot remove more than the available stock."
                            )

                        else:
                            cursor.execute(
                                """
                                INSERT INTO stock_movements (
                                    product_id,
                                    movement_type,
                                    quantity,
                                    notes
                                )
                                VALUES (%s, %s, %s, %s)
                                """,
                                (
                                    product_id,
                                    values["movement_type"],
                                    quantity,
                                    values["notes"],
                                ),
                            )

                if error:
                    database.rollback()
                else:
                    database.commit()
                    return redirect(url_for("business_inventory"))

            except pymysql.MySQLError:
                database.rollback()
                app.logger.exception("Stock movement could not be saved.")
                error = "The stock movement could not be saved. Try again."

    with database.cursor() as cursor:
        cursor.execute(
            """
            SELECT
                products.product_id,
                products.product_name,
                products.selling_unit,
                COALESCE(
                    SUM(
                        CASE
                            WHEN stock_movements.movement_type IN (
                                'Stock In', 'Adjustment In'
                            )
                            THEN stock_movements.quantity
                            ELSE -stock_movements.quantity
                        END
                    ),
                    0
                ) AS available
            FROM products
            LEFT JOIN stock_movements
                ON stock_movements.product_id = products.product_id
            WHERE products.business_id = %s
            GROUP BY
                products.product_id,
                products.product_name,
                products.selling_unit
            ORDER BY products.product_name
            """,
            (business["business_id"],),
        )

        products = cursor.fetchall()

        stock_summary = {
            "total": len(products),
            "available": sum(
                1 for product in products if product["available"] > 0
            ),
            "out_of_stock": sum(
                1 for product in products if product["available"] == 0
            ),
            "needs_review": sum(
                1 for product in products if product["available"] < 0
            ),
        }

        cursor.execute(
            """
            SELECT
                stock_movements.created_at,
                stock_movements.movement_type,
                stock_movements.quantity,
                stock_movements.notes,
                products.product_name,
                products.selling_unit
            FROM stock_movements
            INNER JOIN products
                ON products.product_id = stock_movements.product_id
            WHERE products.business_id = %s
            ORDER BY stock_movements.movement_id DESC
            LIMIT 50
            """,
            (business["business_id"],),
        )

        movements = cursor.fetchall()

    return render_template(
        "business/inventory.html",
        business=business,
        products=products,
        movements=movements,
        movement_types=movement_types,
        stock_summary=stock_summary,
        values=values,
        error=error,
    )

from services.product_tools import (
    install_product_tools,
    PRODUCT_CATEGORIES,
)

install_product_tools(
    app,
    get_db,
    business_required,
    validate_csrf,
)

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )