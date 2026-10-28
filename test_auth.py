"""
Comprehensive automated test suite for Cybersecurity Authentication Toolkit.
Tests scenarios:
  A. Valid registration
  B. Weak password rejection
  C. Password mismatch rejection
  D. Duplicate username/email rejection
  E. Correct login & session verification
  F. Incorrect login & generic error response (anti-enumeration)
  G. Dashboard access guard without login
  H. Logout & session clearing
  I. Login again after logout
  J. SQL Injection resiliency test
"""

import os
import unittest
import sqlite3
from app import app, DATABASE, init_db


class AuthToolkitTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Ensure database is initialized once
        init_db()

    def setUp(self):
        # Configure app for testing
        app.config["TESTING"] = True
        self.client = app.test_client()

        # Clean database table between tests (avoids Windows file-lock PermissionErrors)
        conn = sqlite3.connect(DATABASE)
        try:
            conn.execute("DELETE FROM users")
            conn.commit()
        finally:
            conn.close()

    def get_csrf_token(self):
        """Helper to get CSRF token from the session by fetching GET /register."""
        self.client.get("/register")
        with self.client.session_transaction() as sess:
            return sess.get("csrf_token")

    def test_A_valid_registration(self):
        """A. Test registering a user with strong credentials succeeds."""
        token = self.get_csrf_token()
        response = self.client.post(
            "/register",
            data={
                "csrf_token": token,
                "username": "alice_sec",
                "email": "alice@example.com",
                "password": "Password@123",
                "confirm_password": "Password@123",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Registration successful!", response.data)

        # Verify password hash exists and is NOT plaintext in SQLite
        conn = sqlite3.connect(DATABASE)
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT password_hash FROM users WHERE username = ?", ("alice_sec",))
            row = cursor.fetchone()
        finally:
            conn.close()

        self.assertIsNotNone(row)
        password_hash = row[0]
        self.assertNotEqual(password_hash, "Password@123")
        self.assertTrue(password_hash.startswith("scrypt:") or password_hash.startswith("pbkdf2:"))

    def test_B_weak_password_rejection(self):
        """B. Test that weak passwords violating complexity policy are rejected."""
        token = self.get_csrf_token()
        weak_passwords = [
            ("short1!", "Password must be at least 8 characters long."),
            ("nouppercase123!", "Password must contain at least one uppercase letter."),
            ("NOLOWERCASE123!", "Password must contain at least one lowercase letter."),
            ("NoNumberSpecial!", "Password must contain at least one number."),
            ("NoSpecial12345", "Password must contain at least one special character"),
        ]

        for pwd, expected_err in weak_passwords:
            response = self.client.post(
                "/register",
                data={
                    "csrf_token": token,
                    "username": f"user_{pwd[:4]}",
                    "email": f"{pwd[:4]}@example.com",
                    "password": pwd,
                    "confirm_password": pwd,
                },
                follow_redirects=True,
            )
            self.assertIn(expected_err.encode(), response.data)

    def test_C_password_mismatch_rejection(self):
        """C. Test that mismatched password and confirm_password are rejected."""
        token = self.get_csrf_token()
        response = self.client.post(
            "/register",
            data={
                "csrf_token": token,
                "username": "bob_tester",
                "email": "bob@example.com",
                "password": "StrongPassword@99",
                "confirm_password": "DifferentPassword@99",
            },
            follow_redirects=True,
        )
        self.assertIn(b"Passwords do not match.", response.data)

    def test_D_duplicate_registration_rejection(self):
        """D. Test that duplicate username or email is prevented."""
        token = self.get_csrf_token()
        # Initial registration
        self.client.post(
            "/register",
            data={
                "csrf_token": token,
                "username": "unique_user",
                "email": "unique@example.com",
                "password": "SecurePassword#2026",
                "confirm_password": "SecurePassword#2026",
            },
        )

        # Duplicate username attempt
        token2 = self.get_csrf_token()
        response_dup_user = self.client.post(
            "/register",
            data={
                "csrf_token": token2,
                "username": "unique_user",
                "email": "other@example.com",
                "password": "SecurePassword#2026",
                "confirm_password": "SecurePassword#2026",
            },
            follow_redirects=True,
        )
        self.assertIn(b"Username is already taken.", response_dup_user.data)

        # Duplicate email attempt
        token3 = self.get_csrf_token()
        response_dup_email = self.client.post(
            "/register",
            data={
                "csrf_token": token3,
                "username": "other_user",
                "email": "unique@example.com",
                "password": "SecurePassword#2026",
                "confirm_password": "SecurePassword#2026",
            },
            follow_redirects=True,
        )
        self.assertIn(b"Email is already registered.", response_dup_email.data)

    def test_E_correct_login_and_session(self):
        """E. Test login with correct credentials creates session and redirects to dashboard."""
        token = self.get_csrf_token()
        # Register user
        self.client.post(
            "/register",
            data={
                "csrf_token": token,
                "username": "carol_cyber",
                "email": "carol@example.com",
                "password": "CarolPassword$123",
                "confirm_password": "CarolPassword$123",
            },
        )

        # Login using username
        login_token = self.get_csrf_token()
        response = self.client.post(
            "/login",
            data={
                "csrf_token": login_token,
                "identifier": "carol_cyber",
                "password": "CarolPassword$123",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Welcome, <span class=\"highlight-username\">carol_cyber</span>", response.data)
        self.assertIn(b"Authenticated", response.data)

        # Verify session state
        with self.client.session_transaction() as sess:
            self.assertEqual(sess.get("username"), "carol_cyber")
            self.assertIsNotNone(sess.get("user_id"))

    def test_F_incorrect_login_generic_message(self):
        """F. Test login failure returns uniform generic message to prevent enumeration."""
        token = self.get_csrf_token()
        # Register user
        self.client.post(
            "/register",
            data={
                "csrf_token": token,
                "username": "dave_target",
                "email": "dave@example.com",
                "password": "DavePassword%999",
                "confirm_password": "DavePassword%999",
            },
        )

        login_token = self.get_csrf_token()
        # 1. Existing user with wrong password
        resp_wrong_pw = self.client.post(
            "/login",
            data={
                "csrf_token": login_token,
                "identifier": "dave_target",
                "password": "WrongPassword!000",
            },
            follow_redirects=True,
        )
        self.assertIn(b"Invalid username or password.", resp_wrong_pw.data)

        # 2. Non-existent user
        resp_no_user = self.client.post(
            "/login",
            data={
                "csrf_token": login_token,
                "identifier": "ghost_nonexistent",
                "password": "SomePassword#123",
            },
            follow_redirects=True,
        )
        # Message MUST be completely identical to prevent user enumeration
        self.assertIn(b"Invalid username or password.", resp_no_user.data)

    def test_G_dashboard_guard_without_login(self):
        """G. Test unauthenticated attempt to access /dashboard is blocked."""
        response = self.client.get("/dashboard", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"You must be logged in to view the dashboard.", response.data)
        self.assertIn(b"Sign In", response.data)

    def test_H_logout_and_session_clearing(self):
        """H. Test logout clears session and prevents access to dashboard."""
        token = self.get_csrf_token()
        self.client.post(
            "/register",
            data={
                "csrf_token": token,
                "username": "eve_auth",
                "email": "eve@example.com",
                "password": "EveSecretPassword*42",
                "confirm_password": "EveSecretPassword*42",
            },
        )

        # Login
        self.client.post(
            "/login",
            data={
                "csrf_token": self.get_csrf_token(),
                "identifier": "eve_auth",
                "password": "EveSecretPassword*42",
            },
        )

        # Verify logged in
        with self.client.session_transaction() as sess:
            self.assertIn("user_id", sess)

        # Call logout
        logout_resp = self.client.get("/logout", follow_redirects=True)
        self.assertIn(b"You have been logged out securely.", logout_resp.data)

        # Verify session cleared
        with self.client.session_transaction() as sess:
            self.assertNotIn("user_id", sess)

        # Verify dashboard now redirects
        dash_resp = self.client.get("/dashboard", follow_redirects=True)
        self.assertIn(b"You must be logged in to view the dashboard.", dash_resp.data)

    def test_I_login_again_after_logout(self):
        """I. Test re-login works normally after logging out."""
        token = self.get_csrf_token()
        self.client.post(
            "/register",
            data={
                "csrf_token": token,
                "username": "frank_flow",
                "email": "frank@example.com",
                "password": "FrankPassword^88",
                "confirm_password": "FrankPassword^88",
            },
        )

        # Login 1
        self.client.post(
            "/login",
            data={
                "csrf_token": self.get_csrf_token(),
                "identifier": "frank_flow",
                "password": "FrankPassword^88",
            },
        )

        # Logout
        self.client.get("/logout")

        # Login 2 (by email this time)
        relogin_resp = self.client.post(
            "/login",
            data={
                "csrf_token": self.get_csrf_token(),
                "identifier": "frank@example.com",
                "password": "FrankPassword^88",
            },
            follow_redirects=True,
        )
        self.assertEqual(relogin_resp.status_code, 200)
        self.assertIn(b"Welcome, <span class=\"highlight-username\">frank_flow</span>", relogin_resp.data)

    def test_J_sql_injection_defense(self):
        """J. Test that standard SQL injection payloads do not compromise login."""
        token = self.get_csrf_token()
        # SQL Injection attempt in identifier: ' OR '1'='1
        sqli_payload = "' OR '1'='1' --"
        response = self.client.post(
            "/login",
            data={
                "csrf_token": token,
                "identifier": sqli_payload,
                "password": "ArbitraryPassword123!",
            },
            follow_redirects=True,
        )
        self.assertIn(b"Invalid username or password.", response.data)


if __name__ == "__main__":
    unittest.main()
