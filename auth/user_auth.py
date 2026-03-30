"""
Assessment Operations Platform - User Authentication Module
Handles authentication for both admin and regular users

Usage:
    from auth.user_auth import authenticate_user, require_login, require_permission

    @app.route('/dashboard')
    @require_login
    def dashboard():
        # Accessible by both admin and users
        return render_template('dashboard.html')

    @app.route('/api/generate-questions')
    @require_login
    @require_permission('can_generate_questions')
    def generate_questions():
        # Only accessible if user has permission
        return jsonify({'success': True})
"""

from flask import session, redirect, url_for, jsonify, request
from functools import wraps
import bcrypt
from db_pool import get_connection
from error_helpers import error_response


def authenticate_user(email: str, password: str, db_config: dict) -> dict:
    """
    Authenticate regular user (non-admin)

    Args:
        email: User email (will be lowercased)
        password: Plain text password
        db_config: Database configuration dict (not used, kept for API compatibility)

    Returns:
        User dict with keys: user_id, email, full_name, permissions
        Returns None if authentication fails

    Example:
        user = authenticate_user('john@example.com', 'Password123!', DB_CONFIG)
        if user:
            session['user'] = user
    """

    if not email or not password:
        return None

    # Normalize email to lowercase
    email = email.lower().strip()

    try:
        with get_connection() as conn:
            cur = conn.cursor()

            # Get user record
            cur.execute("""
                SELECT
                    user_id,
                    email,
                    password_hash,
                    full_name,
                    is_active,
                    can_view_roles,
                    can_view_jds,
                    can_generate_questions,
                    can_view_analytics,
                    can_export_data
                FROM users
                WHERE email = %s
            """, (email,))

            user = cur.fetchone()

            if not user:
                return None

            # Unpack user data
            (user_id, user_email, password_hash, full_name, is_active,
             can_view_roles, can_view_jds, can_generate_questions,
             can_view_analytics, can_export_data) = user

            # Check if user is active
            if not is_active:
                return None

            # Verify password
            if not bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8')):
                return None

            # Update last login timestamp
            cur.execute("""
                UPDATE users
                SET last_login_at = NOW()
                WHERE user_id = %s
            """, (user_id,))
            conn.commit()

            # Return user data with permissions
            return {
                'user_id': user_id,
                'email': user_email,
                'full_name': full_name,
                'can_view_roles': can_view_roles,
                'can_view_jds': can_view_jds,
                'can_generate_questions': can_generate_questions,
                'can_view_analytics': can_view_analytics,
                'can_export_data': can_export_data
            }

    except Exception as e:
        print(f"[ERROR] User authentication failed: {e}")
        return None


def require_login(f):
    """
    Decorator: Require admin OR user login

    Checks for either:
    - session['admin_user'] (admin login)
    - session['user'] (regular user login)

    If neither exists, redirects to login page

    Example:
        @app.route('/dashboard')
        @require_login
        def dashboard():
            # Accessible by both admin and users
            return render_template('dashboard.html')
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is logged in (admin or regular user)
        if 'admin_user' not in session and 'user' not in session:
            # For API endpoints, return 401
            if request.path.startswith('/api/'):
                return error_response('Authentication required', 401)
            # For page routes, redirect to login
            return redirect(url_for('login_page'))

        return f(*args, **kwargs)

    return decorated_function


def require_permission(permission: str):
    """
    Decorator: Check if user has specific permission

    Admins always have all permissions.
    Regular users must have the permission flag set to True.

    Args:
        permission: Permission flag name (e.g., 'can_view_jds', 'can_generate_questions')

    Example:
        @app.route('/api/generate-questions')
        @require_login
        @require_permission('can_generate_questions')
        def generate_questions():
            # Only accessible if user has permission
            return jsonify({'success': True})

    Raises:
        403 Forbidden if user doesn't have permission
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Admins have all permissions
            if 'admin_user' in session:
                return f(*args, **kwargs)

            # Check if regular user has permission
            if 'user' in session:
                user = session['user']

                # Check if permission exists and is True
                if user.get(permission, False):
                    return f(*args, **kwargs)

                # Permission denied
                return error_response('Permission denied', 403, details=permission)

            # Not logged in (should be caught by @require_login)
            return error_response('Authentication required', 401)

        return decorated_function
    return decorator


def get_current_user():
    """
    Get currently logged in user (admin or regular user)

    Returns:
        dict with keys:
        - type: 'admin' or 'user'
        - email: user email
        - full_name: user full name
        - permissions: dict of permission flags (for users) or None (for admins)

    Returns None if not logged in

    Example:
        current_user = get_current_user()
        if current_user:
            print(f"Logged in as {current_user['type']}: {current_user['email']}")
    """

    if 'admin_user' in session:
        admin = session['admin_user']
        return {
            'type': 'admin',
            'email': admin.get('email'),
            'full_name': admin.get('full_name'),
            'permissions': None  # Admins have all permissions
        }

    if 'user' in session:
        user = session['user']
        return {
            'type': 'user',
            'email': user.get('email'),
            'full_name': user.get('full_name'),
            'permissions': {
                'can_view_roles': user.get('can_view_roles', False),
                'can_view_jds': user.get('can_view_jds', False),
                'can_generate_questions': user.get('can_generate_questions', False),
                'can_view_analytics': user.get('can_view_analytics', False),
                'can_export_data': user.get('can_export_data', False)
            }
        }

    return None


def check_permission(permission: str) -> bool:
    """
    Check if current user has a specific permission

    Args:
        permission: Permission flag name (e.g., 'can_view_jds')

    Returns:
        True if user has permission, False otherwise
        Admins always return True

    Example:
        if check_permission('can_export_data'):
            # Allow export
            export_data()
        else:
            # Show error
            return jsonify({'error': 'Permission denied'}), 403
    """

    # Admins have all permissions
    if 'admin_user' in session:
        return True

    # Check regular user permissions
    if 'user' in session:
        user = session['user']
        return user.get(permission, False)

    # Not logged in
    return False


def is_admin() -> bool:
    """
    Check if current user is an admin

    Returns:
        True if logged in as admin, False otherwise

    Example:
        if is_admin():
            # Show admin menu
            return render_template('admin_dashboard.html')
    """
    return 'admin_user' in session


def is_logged_in() -> bool:
    """
    Check if user is logged in (admin or regular user)

    Returns:
        True if logged in, False otherwise

    Example:
        if not is_logged_in():
            return redirect(url_for('login_page'))
    """
    return 'admin_user' in session or 'user' in session


def logout_user():
    """
    Log out current user (admin or regular user)

    Clears both admin_user and user from session

    Example:
        @app.route('/api/logout', methods=['POST'])
        def logout():
            logout_user()
            return jsonify({'success': True})
    """
    session.pop('admin_user', None)
    session.pop('user', None)

