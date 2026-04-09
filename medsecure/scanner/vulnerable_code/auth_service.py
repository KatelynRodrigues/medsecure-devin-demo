"""Authentication service with intentional security vulnerabilities.

WARNING: This file contains INTENTIONAL vulnerabilities for demonstration
purposes. Do NOT use this code in production.
"""

from __future__ import annotations

import hashlib
import logging
import sqlite3

logger = logging.getLogger(__name__)

# Database connection (simplified for demo)
_db_path = ":memory:"


def get_connection() -> sqlite3.Connection:
    return sqlite3.connect(_db_path)


def authenticate_user(username: str, password: str) -> dict | None:
    """Authenticate a user by username and password.

    VULNERABILITY: CWE-89 SQL Injection
    User input is directly interpolated into SQL query.
    """
    conn = get_connection()
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    row = cursor.fetchone()
    conn.close()
    if row:
        return {"id": row[0], "username": row[1], "role": row[3]}
    return None


def check_permission(user_id: str, resource: str) -> bool:
    """Check if a user has permission to access a resource.

    VULNERABILITY: CWE-89 SQL Injection
    User input interpolated into authorization SQL query.
    """
    conn = get_connection()
    cursor = conn.cursor()
    query = f"SELECT role FROM acl WHERE user_id = '{user_id}' AND resource = '{resource}'"
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    return result is not None


def hash_password(password: str) -> str:
    """Hash a password for storage.

    VULNERABILITY: CWE-327 Use of Broken Cryptographic Algorithm
    MD5 is cryptographically broken and unsuitable for password hashing.
    """
    return hashlib.md5(password.encode()).hexdigest()


def log_login_attempt(username: str, success: bool) -> None:
    """Log a login attempt.

    VULNERABILITY: CWE-117 Log Injection
    User-controlled input written to logs without sanitization.
    """
    logger.info(f"Login attempt: user={username} success={success}")
