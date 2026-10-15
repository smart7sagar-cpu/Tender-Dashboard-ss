# ==================================================================
# AUTH BLOCK  -  paste this right AFTER the line:  conn = get_conn()
# (needs: time, st, NAVY, BLUE, conn already defined above)
# ==================================================================
import hashlib
import hmac
import re
import secrets

MIN_PW = 8
MAX_FAILS = 5          # itni galat try ke baad lock
LOCK_SECONDS = 300     # 5 minute lock


def _hash_pw(pw: str, salt: str = None):
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), bytes.fromhex(salt), 200_000).hex()
    return salt, h


@st.cache_resource
def init_auth():
    """Users table banata hai / purani plain-text passwords ko hash me convert karta hai."""
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        "username TEXT PRIMARY KEY, password TEXT NOT NULL DEFAULT '', role TEXT NOT NULL)"
    )
    existing = {r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
    extra = {
        "salt": "TEXT", "pw_hash": "TEXT", "full_name": "TEXT",
        "must_change": "INTEGER DEFAULT 0", "failed": "INTEGER DEFAULT 0",
        "locked_until": "REAL DEFAULT 0",
    }
    for col, typ in extra.items():
        if col not in existing:
            conn.execute(f"ALTER TABLE users ADD COLUMN {col} {typ}")

    # purane plain-text passwords -> hash
    for u, p in conn.execute("SELECT username, password FROM users WHERE pw_hash IS NULL").fetchall():
        salt, h = _hash_pw(p or secrets.token_hex(8))
        conn.execute(
            "UPDATE users SET salt=?, pw_hash=?, password='', must_change=? WHERE username=?",
            (salt, h, 1 if p == "admin123" else 0, u),
        )
    # pehli baar: default admin (login ke turant baad password badalna padega)
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        salt, h = _hash_pw("admin123")
        conn.execute(
            "INSERT INTO users (username, password, role, salt, pw_hash, must_change, full_name) "
            "VALUES ('admin', '', 'Admin', ?, ?, 1, 'Administrator')", (salt, h))
    conn.commit()
    return True


init_auth()


def verify_login(username: str, password: str):
    username = (username or "").strip().lower()
    row = conn.execute(
        "SELECT salt, pw_hash, role, must_change, failed, locked_until, full_name "
        "FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        _hash_pw(password)  # timing same rakhne ke liye
        return None, "Username ya password galat hai."
    salt, pw_hash, role, must_change, failed, locked_until, full_name = row
    if locked_until and locked_until > time.time():
        mins = int((locked_until - time.time()) // 60) + 1
        return None, f"Bahut zyada galat try. Account {mins} minute ke liye lock hai."
    if hmac.compare_digest(_hash_pw(password, salt)[1], pw_hash):
        conn.execute("UPDATE users SET failed=0, locked_until=0 WHERE username=?", (username,))
        conn.commit()
        return {"username": username, "role": role, "name": full_name or username,
                "must_change": bool(must_change)}, ""
    failed = (failed or 0) + 1
    lock = time.time() + LOCK_SECONDS if failed >= MAX_FAILS else 0
    if failed >= MAX_FAILS:
        failed = 0
    conn.execute("UPDATE users SET failed=?, locked_until=? WHERE username=?", (failed, lock, username))
    conn.commit()
    return None, "Username ya password galat hai."


def set_password(username: str, new_pw: str, must_change: int = 0):
    salt, h = _hash_pw(new_pw)
    conn.execute(
        "UPDATE users SET salt=?, pw_hash=?, password='', must_change=?, failed=0, locked_until=0 "
        "WHERE username=?", (salt, h, must_change, username))
    conn.commit()


def pw_problem(pw: str):
    if len(pw) < MIN_PW:
        return f"Password kam se kam {MIN_PW} characters ka hona chahiye."
    if pw.lower() in ("password", "admin123", "12345678", "qwerty123"):
        return "Ye password bahut common hai, koi dusra rakho."
    return None


def is_admin() -> bool:
    return st.session_state.get("auth", {}).get("role") == "Admin"


def current_user() -> str:
    return st.session_state.get("auth", {}).get("username", "")


# ---------- UI styling (same theme) ----------
def _auth_css():
    st.markdown(
        f"""
<style>
    div[data-testid="stForm"] {{
        background:white; border:none; border-radius:14px; padding:24px 26px;
        box-shadow:0 6px 22px rgba(18,38,74,.14); border-top:5px solid {BLUE};
    }}
    .login-note {{text-align:center; color:#6B7A90; font-size:.8rem; margin-top:10px;}}
</style>""",
        unsafe_allow_html=True,
    )


def _auth_banner(sub):
    st.markdown(
        f'<div class="topbar"><span>TENDER PORTAL</span><span>SECURE ACCESS</span></div>'
        f'<div class="banner"><h1>🔐 TENDER PORTAL</h1><p>{sub}</p></div>',
        unsafe_allow_html=True,
    )


def login_page():
    _auth_css()
    _auth_banner("SSS &nbsp;|&nbsp; PLEASE LOGIN TO CONTINUE")
    _, mid, _ = st.columns([1, 1.1, 1])
    with mid:
        with st.form("login_form", clear_on_submit=False):
            st.markdown(f"<h3 style='color:{NAVY};margin:0 0 8px 0'>Login</h3>", unsafe_allow_html=True)
            u = st.text_input("Username")
            p = st.text_input("Password", type="password")
            ok = st.form_submit_button("Login", type="primary")
        if ok:
            if not u or not p:
                st.error("Username aur password dono bharo.")
            else:
                user, err = verify_login(u, p)
                if user:
                    st.session_state["auth"] = user
                    do_rerun()
                else:
                    time.sleep(1)  # brute-force slow karne ke liye
                    st.error(err)
        st.markdown('<div class="login-note">Naya account sirf Admin bana sakta hai.</div>',
                    unsafe_allow_html=True)


def force_change_page():
    _auth_css()
    _auth_banner("SET A NEW PASSWORD TO CONTINUE")
    _, mid, _ = st.columns([1, 1.1, 1])
    with mid:
        with st.form("force_pw"):
            st.warning("Security ke liye pehle apna password badalna zaroori hai.")
            p1 = st.text_input("New password", type="password")
            p2 = st.text_input("Confirm new password", type="password")
            ok = st.form_submit_button("Save & Continue", type="primary")
        if ok:
            err = pw_problem(p1) or (None if p1 == p2 else "Dono password match nahi karte.")
            if err:
                st.error(err)
            else:
                set_password(current_user(), p1, 0)
                st.session_state["auth"]["must_change"] = False
                do_rerun()


def require_login():
    """Ye function login ke bina baaki app ko chalne hi nahi deta."""
    if not st.session_state.get("auth"):
        login_page()
        st.stop()
    if st.session_state["auth"].get("must_change"):
        force_change_page()
        st.stop()


def account_panel():
    """Banner ke neeche call karo: user info + logout + password change + user management."""
    a = st.session_state["auth"]
    c1, c2 = st.columns([6, 1])
    c1.markdown(
        f"<div style='color:{NAVY};font-weight:700;padding-top:12px'>👤 {a['name']} "
        f"<span style='color:#6B7A90;font-weight:500'>({a['role']})</span></div>",
        unsafe_allow_html=True,
    )
    if c2.button("Logout", key="logout_btn"):
        st.session_state.clear()
        do_rerun()

    with st.expander("⚙️ Account Settings" + (" & User Management" if is_admin() else "")):
        tabs = st.tabs(["🔑 Change Password"] + (["👥 Manage Users"] if is_admin() else []))

        # ---- change own password ----
        with tabs[0]:
            with st.form("chg_pw", clear_on_submit=True):
                old = st.text_input("Current password", type="password")
                n1 = st.text_input("New password", type="password")
                n2 = st.text_input("Confirm new password", type="password")
                go = st.form_submit_button("Update Password", type="primary")
            if go:
                user, _ = verify_login(current_user(), old)
                err = None
                if not user:
                    err = "Current password galat hai."
                else:
                    err = pw_problem(n1) or (None if n1 == n2 else "Dono password match nahi karte.")
                if err:
                    st.error(err)
                else:
                    set_password(current_user(), n1, 0)
                    st.success("Password badal gaya ✅")

        # ---- admin: sub-users ----
        if is_admin():
            with tabs[1]:
                st.markdown("**➕ Naya user banao**")
                with st.form("new_user", clear_on_submit=True):
                    f1, f2 = st.columns(2)
                    nu = f1.text_input("Username (a-z, 0-9, _ .)")
                    nn = f2.text_input("Full name")
                    f3, f4 = st.columns(2)
                    npw = f3.text_input("Temporary password", type="password")
                    nr = f4.selectbox("Role", ["User", "Admin"])
                    add = st.form_submit_button("Create User", type="primary")
                if add:
                    nu = nu.strip().lower()
                    if not re.fullmatch(r"[a-z0-9_.]{3,30}", nu):
                        st.error("Username 3-30 characters ka ho (sirf a-z, 0-9, _ .).")
                    elif conn.execute("SELECT 1 FROM users WHERE username=?", (nu,)).fetchone():
                        st.error("Ye username pehle se hai.")
                    elif pw_problem(npw):
                        st.error(pw_problem(npw))
                    else:
                        salt, h = _hash_pw(npw)
                        conn.execute(
                            "INSERT INTO users (username, password, role, salt, pw_hash, must_change, full_name) "
                            "VALUES (?, '', ?, ?, ?, 1, ?)", (nu, nr, salt, h, nn.strip() or nu))
                        conn.commit()
                        st.success(f"User '{nu}' ban gaya. Pehli login par wo apna password badlega.")

                st.markdown("---")
                st.markdown("**👥 Existing users**")
                users = pd.read_sql("SELECT username, full_name, role FROM users ORDER BY username", conn)
                st.dataframe(users, hide_index=True)

                names = users["username"].tolist()
                sel = st.selectbox("User chuno", names, key="adm_sel")
                a1, a2, a3 = st.columns(3)
                with a1:
                    rp = st.text_input("Naya temporary password", type="password", key="adm_rp")
                    if st.button("Reset Password", key="adm_rp_btn"):
                        err = pw_problem(rp)
                        if err:
                            st.error(err)
                        else:
                            set_password(sel, rp, 1)
                            st.success(f"{sel} ka password reset ho gaya.")
                with a2:
                    cur_role = users.loc[users.username == sel, "role"].iloc[0]
                    new_role = st.selectbox("Role", ["User", "Admin"],
                                            index=0 if cur_role == "User" else 1, key="adm_role")
                    if st.button("Change Role", key="adm_role_btn"):
                        admins = conn.execute("SELECT COUNT(*) FROM users WHERE role='Admin'").fetchone()[0]
                        if cur_role == "Admin" and new_role == "User" and admins <= 1:
                            st.error("Kam se kam ek Admin hona zaroori hai.")
                        else:
                            conn.execute("UPDATE users SET role=? WHERE username=?", (new_role, sel))
                            conn.commit()
                            st.success("Role update ho gaya.")
                with a3:
                    st.write("")
                    st.write("")
                    if st.button("🗑️ Delete User", key="adm_del_btn"):
                        admins = conn.execute("SELECT COUNT(*) FROM users WHERE role='Admin'").fetchone()[0]
                        if sel == current_user():
                            st.error("Aap khud ko delete nahi kar sakte.")
                        elif cur_role == "Admin" and admins <= 1:
                            st.error("Aakhri Admin delete nahi ho sakta.")
                        else:
                            conn.execute("DELETE FROM users WHERE username=?", (sel,))
                            conn.commit()
                            st.success(f"{sel} delete ho gaya.")
                            do_rerun()


# ----- sabse important line: login ke bina neeche ka kuch bhi nahi chalega -----
require_login()
