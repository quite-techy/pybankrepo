import hashlib
import hmac
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

import streamlit as st

# ------------------------------------------------------------
# PY BANK - Educational banking-system demo
# Run with: streamlit run app.py
# ------------------------------------------------------------

DB_FILE = Path(__file__).with_name("py_bank.db")


@contextmanager
def get_connection():
    conn = sqlite3.connect(DB_FILE, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with get_connection() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                account_number TEXT NOT NULL UNIQUE,
                balance INTEGER NOT NULL DEFAULT 0 CHECK(balance >= 0),
                pin_hash TEXT NOT NULL,
                pin_salt TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id INTEGER NOT NULL,
                transaction_type TEXT NOT NULL
                    CHECK(transaction_type IN ('DEPOSIT', 'WITHDRAWAL')),
                amount INTEGER NOT NULL CHECK(amount > 0),
                previous_balance INTEGER NOT NULL,
                new_balance INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(account_id) REFERENCES accounts(id)
            );
            """
        )


def hash_secret(secret: str, salt_hex: str | None = None):
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", secret.encode("utf-8"), salt, 200_000
    )
    return digest.hex(), salt.hex()


def verify_secret(secret: str, saved_hash: str, saved_salt: str) -> bool:
    candidate, _ = hash_secret(secret, saved_salt)
    return hmac.compare_digest(candidate, saved_hash)


def create_account_number(conn) -> str:
    while True:
        number = "PY" + "".join(secrets.choice("0123456789") for _ in range(10))
        exists = conn.execute(
            "SELECT 1 FROM accounts WHERE account_number = ?", (number,)
        ).fetchone()
        if not exists:
            return number


def get_user_and_account(email: str):
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT u.id AS user_id, u.name, u.email,
                   a.id AS account_id, a.account_number, a.balance,
                   a.pin_hash, a.pin_salt
            FROM users u
            JOIN accounts a ON a.user_id = u.id
            WHERE u.email = ? COLLATE NOCASE
            """,
            (email,),
        ).fetchone()


def register_user(name: str, email: str, password: str, pin: str):
    password_hash, password_salt = hash_secret(password)
    pin_hash, pin_salt = hash_secret(pin)

    with get_connection() as conn:
        existing = conn.execute(
            "SELECT 1 FROM users WHERE email = ? COLLATE NOCASE", (email,)
        ).fetchone()
        if existing:
            return False, "An account with this email already exists."

        cursor = conn.execute(
            """
            INSERT INTO users (name, email, password_hash, password_salt, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                name,
                email,
                password_hash,
                password_salt,
                datetime.now().isoformat(timespec="seconds"),
            ),
        )
        user_id = cursor.lastrowid
        account_number = create_account_number(conn)
        conn.execute(
            """
            INSERT INTO accounts
                (user_id, account_number, balance, pin_hash, pin_salt)
            VALUES (?, ?, 0, ?, ?)
            """,
            (user_id, account_number, pin_hash, pin_salt),
        )
    return True, account_number


def authenticate(email: str, password: str):
    with get_connection() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE email = ? COLLATE NOCASE", (email,)
        ).fetchone()

    if user and verify_secret(
        password, user["password_hash"], user["password_salt"]
    ):
        return user["email"]
    return None


def make_transaction(email: str, account_number: str, pin: str,
                     amount: int, transaction_type: str):
    if amount <= 0:
        return False, "Enter an amount greater than zero.", None

    with get_connection() as conn:
        # A transaction keeps the balance update and history row together.
        conn.execute("BEGIN IMMEDIATE")
        account = conn.execute(
            """
            SELECT a.* FROM accounts a
            JOIN users u ON u.id = a.user_id
            WHERE u.email = ? COLLATE NOCASE AND a.account_number = ?
            """,
            (email, account_number.strip()),
        ).fetchone()

        if not account:
            conn.rollback()
            return False, "Account number does not match your logged-in account.", None

        if not verify_secret(pin, account["pin_hash"], account["pin_salt"]):
            conn.rollback()
            return False, "Incorrect account PIN. Please try again.", None

        previous = int(account["balance"])
        if transaction_type == "WITHDRAWAL" and amount > previous:
            conn.rollback()
            return False, "Insufficient balance for this withdrawal.", None

        new_balance = (
            previous + amount
            if transaction_type == "DEPOSIT"
            else previous - amount
        )

        conn.execute(
            "UPDATE accounts SET balance = ? WHERE id = ?",
            (new_balance, account["id"]),
        )
        conn.execute(
            """
            INSERT INTO transactions
                (account_id, transaction_type, amount,
                 previous_balance, new_balance, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                account["id"],
                transaction_type,
                amount,
                previous,
                new_balance,
                datetime.now().isoformat(timespec="seconds"),
            ),
        )
        conn.commit()

    return True, "Transaction completed successfully.", new_balance


# Page configuration must be the first Streamlit command.
st.set_page_config(page_title="PY BANK", page_icon="🏦", layout="centered")
init_db()

st.markdown(
    """
    <style>
    .hero-banner {
        background: linear-gradient(120deg, #0b132b, #1c2541, #005f73);
        padding: 30px 18px;
        border-radius: 18px;
        border: 1px solid rgba(0, 229, 255, .45);
        text-align: center;
        margin-bottom: 24px;
    }
    .hero-icon { font-size: 3rem; }
    .bank-title {
        color: #00E5FF !important;
        font-size: 3rem !important;
        font-weight: 900 !important;
        letter-spacing: 3px;
        margin: 0 !important;
    }
    .bank-caption {
        color: #d9faff;
        font-size: 1.05rem;
        margin: 8px 0 0;
    }
    </style>
    <div class="hero-banner">
        <div class="hero-icon">🏦⚡</div>
        <h1 class="bank-title">PY BANK</h1>
        <p class="bank-caption">Welcome to Python Banking System</p>
    </div>
    """,
    unsafe_allow_html=True,
)

if "user_email" not in st.session_state:
    st.session_state.user_email = None


def show_dashboard():
    user = get_user_and_account(st.session_state.user_email)
    if not user:
        st.error("Your account record could not be found. Please log in again.")
        st.session_state.user_email = None
        st.rerun()

    st.title(f"Welcome, {user['name']}! 👋")
    st.caption(f"Account number: {user['account_number']}")

    choice = st.selectbox(
        "Select a banking option",
        [
            "Select an option",
            "Check Balance",
            "Deposit Money",
            "Withdraw Money",
            "Transaction History",
            "Logout",
        ],
    )

    if choice == "Check Balance":
        st.subheader("Account Balance")
        st.metric("Available balance", f"₹{user['balance']:,}")

    elif choice in ("Deposit Money", "Withdraw Money"):
        is_deposit = choice == "Deposit Money"
        st.subheader(choice)

        with st.form("money_transaction_form"):
            st.info(f"Account: {user['account_number']}")
            amount = st.number_input(
                "Enter amount (₹)",
                min_value=1,
                max_value=10_000_000,
                value=100,
                step=100,
            )
            account_number = st.text_input(
                "Confirm account number", value=user["account_number"]
            )
            pin = st.text_input("Enter your 4-digit account PIN", type="password",
                                max_chars=4)
            submitted = st.form_submit_button(
                "Submit Deposit" if is_deposit else "Submit Withdrawal",
                use_container_width=True,
            )

        if submitted:
            if not pin.isdigit() or len(pin) != 4:
                st.error("Please enter your 4-digit account PIN.")
            elif not account_number.strip():
                st.error("Please enter your account number.")
            else:
                with st.spinner("Processing transaction..."):
                    ok, message, balance = make_transaction(
                        st.session_state.user_email,
                        account_number,
                        pin,
                        int(amount),
                        "DEPOSIT" if is_deposit else "WITHDRAWAL",
                    )
                if ok:
                    if is_deposit:
                        st.success(f"₹{amount:,} deposited successfully.")
                    else:
                        st.success(f"₹{amount:,} withdrawn successfully.")
                    st.metric("New account balance", f"₹{balance:,}")
                else:
                    st.error(message)

    elif choice == "Transaction History":
        st.subheader("Recent Transactions")
        with get_connection() as conn:
            records = conn.execute(
                """
                SELECT t.transaction_type, t.amount, t.previous_balance,
                       t.new_balance, t.created_at
                FROM transactions t
                JOIN accounts a ON a.id = t.account_id
                JOIN users u ON u.id = a.user_id
                WHERE u.email = ? COLLATE NOCASE
                ORDER BY t.id DESC
                LIMIT 100
                """,
                (st.session_state.user_email,),
            ).fetchall()

        if records:
            st.dataframe(
                [
                    {
                        "Date & Time": row["created_at"].replace("T", " "),
                        "Transaction": row["transaction_type"].title(),
                        "Amount (₹)": row["amount"],
                        "Previous Balance (₹)": row["previous_balance"],
                        "New Balance (₹)": row["new_balance"],
                    }
                    for row in records
                ],
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info("No transactions found.")

    elif choice == "Logout":
        st.session_state.user_email = None
        st.rerun()


if st.session_state.user_email:
    show_dashboard()
else:
    login_tab, register_tab = st.tabs(["Login", "Create Account"])

    with login_tab:
        st.subheader("Access Your Dashboard")
        with st.form("login_form"):
            login_email = st.text_input("Email address")
            login_password = st.text_input("Password", type="password")
            login_submit = st.form_submit_button("Secure Login", use_container_width=True)

        if login_submit:
            if not login_email.strip() or not login_password:
                st.warning("Please enter both email and password.")
            else:
                authenticated_email = authenticate(login_email.strip(), login_password)
                if authenticated_email:
                    st.session_state.user_email = authenticated_email
                    st.success("Login successful!")
                    st.rerun()
                else:
                    st.error("Invalid email or password.")

    with register_tab:
        st.subheader("Create a New Account")
        with st.form("register_form"):
            full_name = st.text_input("Full name")
            email = st.text_input("Email address")
            new_password = st.text_input("Create password", type="password")
            confirm_password = st.text_input("Confirm password", type="password")
            new_pin = st.text_input("Create 4-digit account PIN", type="password",
                                    max_chars=4)
            register_submit = st.form_submit_button("Create Account",
                                                    use_container_width=True)

        if register_submit:
            clean_name = full_name.strip()
            clean_email = email.strip()
            if not all([clean_name, clean_email, new_password, confirm_password, new_pin]):
                st.warning("Please fill in all fields.")
            elif "@" not in clean_email or "." not in clean_email.split("@")[-1]:
                st.error("Please enter a valid email address.")
            elif len(new_password) < 8:
                st.error("Password must contain at least 8 characters.")
            elif new_password != confirm_password:
                st.error("Passwords do not match.")
            elif not new_pin.isdigit() or len(new_pin) != 4:
                st.error("Your account PIN must contain exactly 4 digits.")
            else:
                try:
                    created, result = register_user(
                        clean_name, clean_email, new_password, new_pin
                    )
                    if created:
                        st.success("Account created successfully!")
                        st.write(f"Your new PY BANK account number is: **{result}**")
                        st.info("Please save your account number. You can now log in.")
                    else:
                        st.error(result)
                except sqlite3.Error:
                    st.error("Account could not be created due to a database error. Please try again.")

st.divider()

