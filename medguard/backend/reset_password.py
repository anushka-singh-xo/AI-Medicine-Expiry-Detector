"""Safely reset one local MedGuard account password without deleting its data."""

import getpass
import hashlib
import re
import secrets
import sqlite3
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).with_name("medguard.db")
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt,
        n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=64,
    )
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${digest.hex()}"


def main() -> None:
    if not DB_PATH.exists():
        raise SystemExit(f"MedGuard database not found: {DB_PATH}")

    email = input("Account email to reset: ").strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise SystemExit("Enter a valid email address. No changes were made.")

    with sqlite3.connect(DB_PATH) as db:
        db.row_factory = sqlite3.Row
        user = db.execute(
            "SELECT id, email FROM users WHERE email=? COLLATE NOCASE", (email,)
        ).fetchone()
        if not user:
            raise SystemExit("No account was found for that email. No changes were made.")

        password = getpass.getpass("New password (at least 12 characters): ")
        confirmation = getpass.getpass("Confirm new password: ")
        if len(password) < 12:
            raise SystemExit("Use at least 12 characters. No changes were made.")
        if password != confirmation:
            raise SystemExit("Passwords do not match. No changes were made.")

        approval = input(
            f"Reset the password for {user['email']}? Type RESET to continue: "
        ).strip()
        if approval != "RESET":
            raise SystemExit("Cancelled. No changes were made.")

        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup_path = DB_PATH.with_name(f"medguard-pre-password-reset-{stamp}.db")
        backup = sqlite3.connect(backup_path)
        try:
            db.backup(backup)
        finally:
            backup.close()

        try:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "UPDATE users SET password_hash=? WHERE id=?",
                (hash_password(password), user["id"]),
            )
            db.execute("DELETE FROM sessions WHERE user_id=?", (user["id"],))
            db.commit()
        except Exception:
            db.rollback()
            backup_path.unlink(missing_ok=True)
            raise

    print("Password reset successfully. Your account and medicine inventory were preserved.")
    print("Old sessions were signed out. Sign in to MedGuard using the new password.")
    print(f"Database backup: {backup_path}")


if __name__ == "__main__":
    main()
