"""
login.py
----------
Authentication UI module — login captcha + password-reset OTP flow.

Every interactive screen uses st.form so Streamlit captures widget values
correctly at submit time.  Navigation links are plain st.button calls placed
OUTSIDE the form context to avoid the "button disappears on next rerun" bug.

Screens
-------
render_auth_page()  ->  dispatcher on st.session_state.auth_view
    "login"         ->  username + password
    "register"      ->  create account
    "captcha"       ->  captcha challenge (login path)
    "forgot"        ->  request password-reset code
    "forgot_captcha" ->  captcha challenge (password-reset path)
    "reset_password"->  set new password

Session-state owned here
------------------------
    user                  logged-in user dict or None
    auth_view             which screen is active
    pending_login_user    user dict waiting for login captcha
    pending_reset_user    user dict waiting for reset captcha
    login_captcha_question  text shown in the captcha challenge
    login_captcha_answer    expected answer for the captcha challenge
    reset_captcha_question  text shown in the reset captcha challenge
    reset_captcha_answer    expected answer for the reset captcha challenge
    otp_reg_success       True after successful registration
    otp_reset_success     True after successful password reset

   # FUTURE SCOPE: plug in OAuth / SSO (Google Workspace, Okta, Azure AD).
"""

import streamlit as st
import random

import config
import database
import security


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _set_view(view: str):
    st.session_state.auth_view = view
    st.rerun()


def _centered():
    _, mid, _ = st.columns([1, 1.4, 1])
    return mid


def _logo_header(subtitle: str):
    st.markdown(
        f"""
        <div style="text-align:center;margin-bottom:18px;">
          <div style="font-size:2rem;font-weight:800;
               background:linear-gradient(95deg,#0369A1,#0EA5E9 45%,#22D3EE);
               -webkit-background-clip:text;background-clip:text;color:transparent;">
            🛡️ {config.APP_NAME}
          </div>
          <div style="color:#64748B;font-size:0.95rem;">{subtitle}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _captcha_reset():
    st.session_state.pop("login_captcha_question", None)
    st.session_state.pop("login_captcha_answer", None)
    st.session_state.pop("reset_captcha_question", None)
    st.session_state.pop("reset_captcha_answer", None)


def _captcha_generate():
    left = random.randint(2, 9)
    right = random.randint(1, 9)
    op = random.choice(["+", "-", "×"])
    if op == "+":
        answer = left + right
    elif op == "-":
        left, right = max(left, right), min(left, right)
        answer = left - right
    else:
        answer = left * right

    st.session_state.login_captcha_question = f"What is {left} {op} {right}?"
    st.session_state.login_captcha_answer = str(answer)


def _reset_captcha_generate():
    left = random.randint(2, 9)
    right = random.randint(1, 9)
    op = random.choice(["+", "-"])
    if op == "+":
        answer = left + right
    else:
        left, right = max(left, right), min(left, right)
        answer = left - right

    st.session_state.reset_captcha_question = f"What is {left} {op} {right}?"
    st.session_state.reset_captcha_answer = str(answer)


def _captcha_banner():
    st.info("Solve the captcha below to complete sign-in. This replaces the email OTP step for login.")


def _ensure_login_captcha():
    if not st.session_state.get("login_captcha_question"):
        _captcha_generate()


def _verify_login_captcha(submitted_value: str) -> bool:
    expected = str(st.session_state.get("login_captcha_answer", "")).strip()
    return submitted_value.strip() == expected


def _verify_reset_captcha(submitted_value: str) -> bool:
    expected = str(st.session_state.get("reset_captcha_answer", "")).strip()
    return submitted_value.strip() == expected


def _nav_button(label: str, key: str, view: str = None, callback=None):
    """A small navigation button rendered outside any form context."""
    if st.button(label, key=key, use_container_width=True):
        if callback:
            callback()
        if view:
            _set_view(view)


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

def _render_login():
    mid = _centered()
    with mid:
        _logo_header("Sign in to your Security Operations Center")
        with st.container(border=True):
            with st.form("login_form", clear_on_submit=False):
                username = st.text_input("Username", placeholder="e.g. admin")
                password = st.text_input("Password", type="password")
                submitted = st.form_submit_button(
                    "Login", use_container_width=True, type="primary"
                )

            if submitted:
                if not username or not password:
                    st.error("Please enter both username and password.")
                else:
                    user = database.authenticate(username.strip(), password)
                    if not user:
                        st.error("Incorrect username / password, or account is inactive.")
                        database.log_action(None, "login_failed", f"username={username}")
                    else:
                        st.session_state.pending_login_user = user
                        _captcha_reset()
                        _captcha_generate()
                        database.log_action(user["id"], "login_captcha_requested")
                        _set_view("captcha")

        col1, col2 = st.columns(2)
        with col1:
            _nav_button("Create an account", key="nav_to_register", view="register")
        with col2:
            _nav_button("Forgot password?", key="nav_to_forgot", view="forgot")

        st.caption(
            f"Demo — username **{config.SEED_ADMIN_USERNAME}** "
            f"/ password **{config.SEED_ADMIN_PASSWORD}**"
        )


# ---------------------------------------------------------------------------
# Register
# ---------------------------------------------------------------------------

def _render_register():
    mid = _centered()
    with mid:
        _logo_header("Create your analyst account")

        if st.session_state.get("otp_reg_success"):
            st.success("✅ Account created!  You can now log in.")
            if st.button("Go to Login →", type="primary",
                         use_container_width=True, key="nav_reg_done"):
                st.session_state.otp_reg_success = False
                _set_view("login")
            return

        policy = _password_policy()

        with st.container(border=True):
            with st.form("register_form"):
                full_name = st.text_input("Full Name")
                email     = st.text_input("Email")
                username  = st.text_input("Username")
                c1, c2    = st.columns(2)
                with c1:
                    password = st.text_input("Password", type="password")
                with c2:
                    confirm  = st.text_input("Confirm Password", type="password")
                st.caption(
                    f"Min {policy.get('min_length', 8)} chars — "
                    "upper, lower, number, special character."
                )
                submitted = st.form_submit_button(
                    "Create Account", use_container_width=True, type="primary"
                )

            if submitted:
                errs = []
                if not all([full_name, email, username, password, confirm]):
                    errs.append("All fields are required.")
                if email and not security.is_valid_email(email):
                    errs.append("Invalid email address.")
                if password != confirm:
                    errs.append("Passwords do not match.")
                if password:
                    errs.extend(security.validate_password_policy(password, policy))
                if username and database.get_user_by_username(username.strip()):
                    errs.append("Username already taken.")
                if email and database.get_user_by_email(email.strip()):
                    errs.append("Email already registered.")
                if errs:
                    for e in errs:
                        st.error(e)
                else:
                    u = database.create_user(
                        full_name.strip(), email.strip(), username.strip(),
                        password, role="user"
                    )
                    database.log_action(u["id"], "user_registered")
                    st.session_state.otp_reg_success = True
                    st.rerun()

        _nav_button("← Back to Login", key="nav_register_back", view="login")


# ---------------------------------------------------------------------------
# Captcha verification  (login path)
# ---------------------------------------------------------------------------

def _render_captcha():
    user = st.session_state.get("pending_login_user")

    mid = _centered()
    with mid:
        _logo_header("Captcha verification")

        # Guard: user must have been set by the previous screen.
        if not user:
            st.warning("Your session expired. Please log in again.")
            _nav_button("← Back to Login", key="nav_captcha_expired", view="login")
            return

        _captcha_banner()
        _ensure_login_captcha()

        with st.form("captcha_form", clear_on_submit=False):
            st.markdown(
                f"<p style='margin:0 0 10px;color:#475569;font-size:0.95rem;'>"
                f"{st.session_state.get('login_captcha_question', 'Solve the captcha')}</p>",
                unsafe_allow_html=True,
            )
            answer = st.text_input(
                "Captcha answer",
                placeholder="Enter the answer",
                label_visibility="collapsed",
            )
            c1, c2 = st.columns(2)
            with c1:
                verify_clicked = st.form_submit_button(
                    "✅ Verify Captcha",
                    use_container_width=True,
                    type="primary",
                )
            with c2:
                refresh_clicked = st.form_submit_button(
                    "🔄 New Challenge",
                    use_container_width=True,
                )

        if refresh_clicked:
            _captcha_generate()
            st.rerun()

        if verify_clicked:
            if not answer.strip():
                st.error("Please enter the captcha answer.")
            elif _verify_login_captcha(answer):
                st.session_state.user = user
                st.session_state.pending_login_user = None
                _captcha_reset()
                st.session_state.route = "app"
                database.log_action(user["id"], "login_success")
                st.rerun()
            else:
                st.error("Incorrect captcha answer. Please try again.")
                _captcha_generate()

        # ── Back link (always visible, outside the form) ─────────────────
        if st.button("← Back to Login",
                     key="nav_captcha_back", use_container_width=True):
            st.session_state.pending_login_user = None
            _captcha_reset()
            _set_view("login")


# ---------------------------------------------------------------------------
# Forgot password  (request captcha challenge)
# ---------------------------------------------------------------------------

def _render_forgot():
    mid = _centered()
    with mid:
        _logo_header("Reset your password")
        with st.container(border=True):
            with st.form("forgot_form"):
                email     = st.text_input("Account email", placeholder="you@example.com")
                submitted = st.form_submit_button(
                    "Send Reset Code", type="primary", use_container_width=True
                )

            if submitted:
                found = database.get_user_by_email(email.strip()) if email else None
                if found:
                    st.session_state.pending_reset_user = found
                    _reset_captcha_generate()
                    database.log_action(found["id"], "reset_captcha_requested")
                    _set_view("forgot_captcha")
                else:
                    # Generic message — avoids disclosing which emails exist.
                    st.info("If that email is registered a reset code has been sent.")

        _nav_button("← Back to Login", key="nav_forgot_back", view="login")


# ---------------------------------------------------------------------------
# Reset password  (set new password after captcha verified)
# ---------------------------------------------------------------------------


def _render_forgot_captcha():
    mid = _centered()
    with mid:
        _logo_header("Reset your password")

        user = st.session_state.get("pending_reset_user")
        if not user:
            st.warning("Session expired.  Please start the reset process again.")
            _nav_button("← Back to Login", key="nav_reset_captcha_expired", view="login")
            return

        if not st.session_state.get("reset_captcha_question"):
            _reset_captcha_generate()

        st.info("Solve the captcha to continue resetting your password.")

        with st.form("forgot_captcha_form", clear_on_submit=False):
            st.markdown(
                f"<p style='margin:0 0 10px;color:#475569;font-size:0.95rem;'>"
                f"{st.session_state.get('reset_captcha_question', 'Solve the captcha')}</p>",
                unsafe_allow_html=True,
            )
            answer = st.text_input(
                "Captcha answer",
                placeholder="Enter the answer",
                label_visibility="collapsed",
            )
            c1, c2 = st.columns(2)
            with c1:
                verify_clicked = st.form_submit_button(
                    "✅ Verify Captcha",
                    use_container_width=True,
                    type="primary",
                )
            with c2:
                refresh_clicked = st.form_submit_button(
                    "🔄 New Challenge",
                    use_container_width=True,
                )

        if refresh_clicked:
            _reset_captcha_generate()
            st.rerun()

        if verify_clicked:
            if not answer.strip():
                st.error("Please enter the captcha answer.")
            elif _verify_reset_captcha(answer):
                database.log_action(user["id"], "reset_captcha_verified")
                st.session_state.reset_captcha_question = None
                st.session_state.reset_captcha_answer = None
                _set_view("reset_password")
            else:
                st.error("Incorrect captcha answer. Please try again.")
                _reset_captcha_generate()

def _render_reset_password():
    mid = _centered()
    with mid:
        _logo_header("Choose a new password")

        if st.session_state.get("otp_reset_success"):
            st.success("✅ Password updated!  Please log in with your new password.")
            if st.button("Go to Login →", type="primary",
                         use_container_width=True, key="nav_reset_done"):
                st.session_state.otp_reset_success = False
                _set_view("login")
            return

        user = st.session_state.get("pending_reset_user")
        if not user:
            st.warning("Session expired.  Please start the reset process again.")
            _nav_button("← Back to Login", key="nav_reset_expired", view="login")
            return

        policy = _password_policy()
        with st.container(border=True):
            with st.form("reset_password_form"):
                new_pw  = st.text_input("New Password", type="password")
                confirm = st.text_input("Confirm New Password", type="password")
                submitted = st.form_submit_button(
                    "Update Password", type="primary", use_container_width=True
                )

            if submitted:
                errs = []
                if not new_pw:
                    errs.append("Please enter a new password.")
                elif new_pw != confirm:
                    errs.append("Passwords do not match.")
                else:
                    errs.extend(security.validate_password_policy(new_pw, policy))

                if errs:
                    for e in errs:
                        st.error(e)
                else:
                    database.update_password(user["id"], new_pw)
                    database.log_action(user["id"], "password_reset")
                    st.session_state.pending_reset_user = None
                    st.session_state.otp_reset_success  = True
                    st.rerun()

        _nav_button("← Back to Login", key="nav_reset_back",
                    callback=lambda: setattr(
                        st.session_state, "pending_reset_user", None
                    ),
                    view="login")


# ---------------------------------------------------------------------------
# Helpers used only here
# ---------------------------------------------------------------------------

def _password_policy():
    return database.get_setting("password_policy") or config.DEFAULT_PASSWORD_POLICY


# ---------------------------------------------------------------------------
# Public dispatcher
# ---------------------------------------------------------------------------

def render_auth_page():
    view = st.session_state.get("auth_view", "login")
    st.markdown("<div style='height:24px'></div>", unsafe_allow_html=True)

    if view == "login":
        _render_login()
    elif view == "register":
        _render_register()
    elif view == "captcha":
        _render_captcha()
    elif view == "forgot":
        _render_forgot()
    elif view == "forgot_captcha":
        _render_forgot_captcha()
    elif view == "reset_password":
        _render_reset_password()
    else:
        st.session_state.auth_view = "login"
        st.rerun()
