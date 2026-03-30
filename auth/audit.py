"""
Assessment Operations Platform - Audit Logging Module
Tracks all user actions for security and compliance

Usage:
    from auth.audit import log_action

    # In your route:
    log_action('view_role', 'role', role_id)
    log_action('login', details={'success': True})
    log_action('update_user_permissions', 'user', user_id, {'permissions_changed': ['can_view_jds']})
"""

from flask import session, request, has_request_context
from db_pool import get_connection
import json
from datetime import datetime


def log_action(
    action: str,
    resource_type: str = None,
    resource_id: str = None,
    details: dict = None
):
    """
    Log user action to audit_log table

    Auto-detects from Flask context:
    - user_email: From session (admin or user)
    - user_type: 'admin', 'user', or 'anonymous'
    - ip_address: From request
    - user_agent: From request

    Args:
        action: Action performed (e.g., 'login', 'view_role', 'create_user')
        resource_type: Type of resource (e.g., 'role', 'jd', 'user')
        resource_id: ID of specific resource accessed
        details: Additional context as dict (will be stored as JSONB)

    Returns:
        log_id: ID of created audit log entry, or None if logging failed

    Examples:
        log_action('login')
        log_action('view_role', 'role', '123')
        log_action('update_user_permissions', 'user', '456', {'revoked': ['can_export_data']})
    """

    # Skip if not in Flask request context (e.g., during testing or background jobs)
    if not has_request_context():
        return None

    try:
        # Auto-detect user from session
        user_email = 'anonymous'
        user_type = 'anonymous'

        if 'admin_user' in session:
            user_email = session['admin_user'].get('email', 'unknown_admin')
            user_type = 'admin'
        elif 'user' in session:
            user_email = session['user'].get('email', 'unknown_user')
            user_type = 'user'

        # Auto-detect IP address
        # Check for proxy headers first (X-Forwarded-For, X-Real-IP)
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ip_address and ',' in ip_address:
            # X-Forwarded-For can contain multiple IPs, take the first one
            ip_address = ip_address.split(',')[0].strip()

        # Auto-detect user agent
        user_agent = request.headers.get('User-Agent', 'Unknown')

        # Convert details dict to JSON string for JSONB storage
        details_json = json.dumps(details) if details else None

        # Insert into audit_log table
        with get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO audit_log (
                    user_email,
                    user_type,
                    action,
                    resource_type,
                    resource_id,
                    details,
                    ip_address,
                    user_agent,
                    created_at
                )
                VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s, %s, NOW())
                RETURNING log_id
            """, (
                user_email,
                user_type,
                action,
                resource_type,
                resource_id,
                details_json,
                ip_address,
                user_agent
            ))

            log_id = cur.fetchone()[0]
            conn.commit()

            return log_id

    except Exception as e:
        # Log to console but don't crash the application
        # Audit logging should never break user functionality
        print(f"[WARN] Audit logging failed for action '{action}': {e}")
        return None


def get_audit_logs(
    user_email: str = None,
    action: str = None,
    start_date: datetime = None,
    end_date: datetime = None,
    limit: int = 100,
    offset: int = 0
):
    """
    Query audit logs with filters

    Args:
        user_email: Filter by user email (optional)
        action: Filter by action type (optional)
        start_date: Filter by start date (optional)
        end_date: Filter by end date (optional)
        limit: Max number of results (default 100)
        offset: Pagination offset (default 0)

    Returns:
        List of audit log entries as dicts
    """

    query = """
        SELECT
            log_id,
            user_email,
            user_type,
            action,
            resource_type,
            resource_id,
            details,
            ip_address,
            user_agent,
            created_at
        FROM audit_log
        WHERE 1=1
    """

    params = []

    # Build dynamic WHERE clause
    if user_email:
        query += " AND user_email = %s"
        params.append(user_email)

    if action:
        query += " AND action = %s"
        params.append(action)

    if start_date:
        query += " AND created_at >= %s"
        params.append(start_date)

    if end_date:
        query += " AND created_at <= %s"
        params.append(end_date)

    # Order by most recent first
    query += " ORDER BY created_at DESC"

    # Pagination
    query += " LIMIT %s OFFSET %s"
    params.extend([limit, offset])

    try:
        with get_connection() as conn:
            cur = conn.cursor()
            cur.execute(query, params)

            columns = [desc[0] for desc in cur.description]
            results = []

            for row in cur.fetchall():
                log_entry = dict(zip(columns, row))

                # Convert datetime to string for JSON serialization
                if log_entry.get('created_at'):
                    log_entry['created_at'] = log_entry['created_at'].isoformat()

                results.append(log_entry)

            return results

    except Exception as e:
        print(f"[FAIL] Failed to query audit logs: {e}")
        return []


def cleanup_old_logs(days: int = 90):
    """
    Delete audit logs older than specified days
    Records cleanup in audit_log_cleanup table

    Args:
        days: Number of days to retain (default 90)

    Returns:
        Number of records deleted
    """

    try:
        with get_connection() as conn:
            cur = conn.cursor()

            # Delete old logs
            cur.execute("""
                DELETE FROM audit_log
                WHERE created_at < NOW() - INTERVAL '%s days'
            """, (days,))

            deleted_count = cur.rowcount

            # Get oldest remaining log date
            cur.execute("""
                SELECT MIN(created_at) FROM audit_log
            """)
            oldest_date = cur.fetchone()[0]

            # Record cleanup
            cur.execute("""
                INSERT INTO audit_log_cleanup (
                    deleted_records,
                    oldest_kept_date,
                    cleanup_at
                )
                VALUES (%s, %s, NOW())
            """, (deleted_count, oldest_date))

            conn.commit()

            print(f"[OK] Cleaned up {deleted_count} audit logs older than {days} days")
            print(f"[OK] Oldest remaining log: {oldest_date}")

            return deleted_count

    except Exception as e:
        print(f"[FAIL] Audit log cleanup failed: {e}")
        return 0


# Action constants for consistency
class AuditAction:
    """Standard action names for audit logging"""

    # Authentication
    LOGIN = 'login'
    LOGOUT = 'logout'
    FAILED_LOGIN = 'failed_login'
    CHANGE_PASSWORD = 'change_password'

    # Dashboard
    VIEW_DASHBOARD = 'view_dashboard'
    VIEW_ROLES = 'view_roles'
    VIEW_ROLE_DETAIL = 'view_role_detail'

    # Job Descriptions
    VIEW_JD = 'view_jd'

    # Questions
    GENERATE_QUESTIONS = 'generate_questions'
    VIEW_QUESTIONS = 'view_questions'

    # User Management (Admin only)
    CREATE_USER = 'create_user'
    UPDATE_USER = 'update_user'
    DELETE_USER = 'delete_user'
    UPDATE_USER_PERMISSIONS = 'update_user_permissions'

    # Audit Log (Admin only)
    VIEW_AUDIT_LOG = 'view_audit_log'
    EXPORT_AUDIT_LOG = 'export_audit_log'

    # Data Export
    EXPORT_DATA = 'export_data'


# Resource type constants
class ResourceType:
    """Standard resource types for audit logging"""

    ROLE = 'role'
    JD = 'jd'
    USER = 'user'
    ADMIN = 'admin'
    QUESTION = 'question'
    AUDIT_LOG = 'audit_log'

