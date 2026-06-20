"""
otp_service.py
----------------
Email OTP verification service.

Production SMTP credentials are read from environment variables so secrets
never live in source control:

    SHADOWSEC_SMTP_HOST
    SHADOWSEC_SMTP_PORT
    SHADOWSEC_SMTP_USER
    SHADOWSEC_SMTP_PASSWORD
    SHADOWSEC_SMTP_FROM
    SHADOWSEC_SMTP_USE_TLS   ("1" / "0")

If those are not configured (e.g. running this demo without a mail server,
or in a sandboxed environment with no outbound network access), the service
automatically falls back to "DEV MODE": the OTP is written to the local
console/log AND returned to the caller so the UI can surface it in a banner.
This keeps the full login flow testable end-to-end without real email.

   # FUTURE SCOPE: swap smtplib for a transactional email API (SendGrid,
   # SES, Postmark, etc.) here for higher deliverability at scale.
"""

import os
import secrets
import smtplib
import string
from email.mime.text import MIMEText

import database
import config


def _coerce_bool(value, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def get_smtp_settings():
    settings = dict(config.DEFAULT_SMTP_SETTINGS)

    env_settings = {
        "host": os.environ.get("SHADOWSEC_SMTP_HOST", "").strip(),
        "port": os.environ.get("SHADOWSEC_SMTP_PORT", "").strip(),
        "user": os.environ.get("SHADOWSEC_SMTP_USER", "").strip(),
        "password": os.environ.get("SHADOWSEC_SMTP_PASSWORD", ""),
        "sender": os.environ.get("SHADOWSEC_SMTP_FROM", "").strip(),
        "use_tls": os.environ.get("SHADOWSEC_SMTP_USE_TLS", "").strip(),
    }

    stored_settings = database.get_setting("smtp_settings") or {}

    for key, value in env_settings.items():
        if value not in (None, ""):
            settings[key] = value

    for key, value in stored_settings.items():
        if value not in (None, ""):
            settings[key] = value

    try:
        settings["port"] = int(settings.get("port", 587))
    except (TypeError, ValueError):
        settings["port"] = 587

    settings["use_tls"] = _coerce_bool(settings.get("use_tls"), True)
    return settings


def generate_otp(length=6):
    return "".join(secrets.choice(string.digits) for _ in range(length))


def _smtp_configured(settings):
    return bool(settings.get("host"))


def _send_email_smtp(to_email, subject, body, smtp_settings):
    host = smtp_settings["host"]
    port = int(smtp_settings.get("port", 587))
    user = smtp_settings.get("user", "")
    password = smtp_settings.get("password", "")
    sender = smtp_settings.get("sender") or user or "no-reply@shadowsec.local"
    use_tls = _coerce_bool(smtp_settings.get("use_tls"), True)

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = to_email

    with smtplib.SMTP(host, port, timeout=10) as server:
        if use_tls:
            server.starttls()
        if user:
            server.login(user, password)
        server.sendmail(sender, [to_email], msg.as_string())


def send_otp(user, purpose="login"):
    """
    Generate, persist, and deliver an OTP to `user`.

    Returns a dict: {"delivered": bool, "dev_mode": bool, "otp": str|None}
    `otp` is only populated when dev_mode is True (so the UI can show it).
    """
    otp_settings = database.get_setting("otp_settings") or config.DEFAULT_OTP_SETTINGS
    code = generate_otp(otp_settings.get("otp_length", 6))
    database.create_otp(
        user["id"], code, purpose, otp_settings.get("validity_minutes", 5)
    )

    subject = f"{config.APP_NAME} security code"
    purpose_label = "log in" if purpose == "login" else "reset your password"
    body = (
        f"Hello {user['full_name']},\n\n"
        f"Use the following one-time code to {purpose_label} on {config.APP_NAME}:\n\n"
        f"    {code}\n\n"
        f"This code expires in {otp_settings.get('validity_minutes', 5)} minutes "
        f"and can be used a maximum of {otp_settings.get('max_attempts', 3)} times.\n\n"
        f"If you did not request this, you can safely ignore this email.\n\n"
        f"— {config.APP_NAME} Security Team"
    )

    smtp_settings = get_smtp_settings()

    if _smtp_configured(smtp_settings):
        try:
            _send_email_smtp(user["email"], subject, body, smtp_settings)
            return {"delivered": True, "dev_mode": False, "otp": None}
        except Exception as exc:  # noqa: BLE001 - surface any SMTP failure gracefully
            # Fall through to dev mode so the demo never gets stuck.
            return {"delivered": False, "dev_mode": True, "otp": code, "error": str(exc)}

    # No SMTP configured -> dev mode
    return {"delivered": False, "dev_mode": True, "otp": code}


def verify_otp(user, submitted_code, purpose="login"):
    """
    Verify a submitted OTP code.

    Returns (success: bool, message: str)
    """
    otp_settings = database.get_setting("otp_settings") or config.DEFAULT_OTP_SETTINGS
    max_attempts = otp_settings.get("max_attempts", 3)

    record = database.get_active_otp(user["id"], purpose)
    if record is None:
        return False, "No active code found. Please request a new one."

    from datetime import datetime

    expires_at = datetime.fromisoformat(record["expires_at"])
    if datetime.utcnow() > expires_at:
        database.mark_otp_used(record["id"])
        return False, "This code has expired. Please request a new one."

    if record["attempts_used"] >= max_attempts:
        database.mark_otp_used(record["id"])
        return False, "Maximum verification attempts exceeded. Please request a new code."

    if submitted_code.strip() != record["code"]:
        database.increment_otp_attempts(record["id"])
        remaining = max_attempts - (record["attempts_used"] + 1)
        if remaining <= 0:
            database.mark_otp_used(record["id"])
            return False, "Incorrect code. No attempts remaining — request a new code."
        return False, f"Incorrect code. {remaining} attempt(s) remaining."

    database.mark_otp_used(record["id"])
    return True, "Verified successfully."
