"""
Admin Authentication Module
============================
Handles email/password login for dashboard access

"""

import bcrypt
import psycopg2
from psycopg2.extras import RealDictCursor
from functools import wraps
from flask import session, redirect, url_for, request, jsonify
from datetime import datetime, timezone
from error_helpers import error_response
import logging

logger = logging.getLogger(__name__)


def hash_password(password: str) -> str:
    """Hash password with bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def verify_password(password: str, password_hash: str) -> bool:
    """Verify password against bcrypt hash"""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    except (ValueError, TypeError):
        return False


def authenticate_admin(email: str, password: str, db_config: dict) -> dict:
    """
    Authenticate admin user
    Returns admin dict if valid, None if invalid
    """
    conn = None
    try:
        conn = psycopg2.connect(**db_config)
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT admin_id, email, password_hash, full_name, is_active
                FROM admin_users
                WHERE email = %s AND is_active = TRUE
            """, (email.lower(),))

            admin = cur.fetchone()

            if not admin:
                logger.warning(f"Login attempt for non-existent admin: {email}")
                return None

            if not verify_password(password, admin['password_hash']):
                logger.warning(f"Failed password for admin: {email}")
                return None

            # Update last login
            cur.execute("""
                UPDATE admin_users
                SET last_login_at = NOW()
                WHERE admin_id = %s
            """, (admin['admin_id'],))
            conn.commit()

            logger.info(f"[OK] Admin login successful: {email}")
            return dict(admin)

    except Exception as e:
        logger.error(f"Admin auth error: {e}")
        return None
    finally:
        if conn:
            conn.close()


def require_admin_login(f):
    """
    Decorator to require admin login for dashboard routes

    Usage:
        @app.route('/dashboard/b2b-authorizations')
        @require_admin_login
        def b2b_authorizations():
            ...
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_user' not in session:
            # Return JSON if API call, redirect if browser
            if request.path.startswith('/api/'):
                return error_response('Unauthorized. Admin login required.', 401)
            return redirect(url_for('admin_login_page'))
        return f(*args, **kwargs)
    return decorated_function

