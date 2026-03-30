"""
Assessment Operations Platform
Sanitized public showcase of a Flask/PostgreSQL workflow application.

This snapshot focuses on API design, authentication, validation, and
server-rendered dashboard flows. Private data, proprietary integrations, and
customer-specific assets have been removed.
"""
from flask import Flask, render_template, jsonify, request, g, session, redirect, url_for
from flask_cors import CORS  # FIX STAGE 2: CORS support
from flask_limiter import Limiter  # FIX STAGE 2: Rate limiting
from flask_limiter.util import get_remote_address
from flask_compress import Compress  # FIX STAGE 3: Response compression
import psycopg2
import psycopg2.extras
from psycopg2 import pool
from psycopg2.extras import RealDictCursor
from contextlib import contextmanager
import logging
from datetime import datetime, timezone, timedelta
from functools import wraps
from typing import Dict, Any, Tuple, Optional
import signal
import sys
import os
import bcrypt
import secrets
import json
import time  # FIX STAGE 3: For latency tracking
from dotenv import load_dotenv  # SECURITY FIX: Load environment variables
from error_helpers import error_response

# SECURITY: Load .env file before anything else
load_dotenv()

# Import audit logging and user authentication (after load_dotenv so DB config is available)
from auth.audit import log_action, AuditAction, ResourceType
from auth.user_auth import authenticate_user, require_login, require_permission, get_current_user, is_admin, logout_user
from auth.admin_auth import authenticate_admin, require_admin_login, hash_password, verify_password
from services.access_requests_service import (
    list_access_requests as svc_list_access_requests,
    approve_access_request as svc_approve_access_request,
    deny_access_request as svc_deny_access_request,
    revoke_access_request as svc_revoke_access_request,
    resubmit_access_request as svc_resubmit_access_request,
)
from services.b2b_authorizations_service import (
    normalize_b2b_status_filter as svc_normalize_b2b_status_filter,
    list_b2b_authorization_requests as svc_list_b2b_authorization_requests,
    approve_b2b_authorization_request as svc_approve_b2b_authorization_request,
    deny_b2b_authorization_request as svc_deny_b2b_authorization_request,
    complete_b2b_authorization_processing as svc_complete_b2b_authorization_processing,
    fail_b2b_authorization_processing as svc_fail_b2b_authorization_processing,
)

app = Flask(__name__)

# SECURITY: Limit request body size to prevent DoS (16MB max)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB

# SECURITY: Secret key for session encryption (ADDED)
app.secret_key = os.environ.get('FLASK_SECRET_KEY')
if not app.secret_key:
    print("[FATAL] FLASK_SECRET_KEY environment variable not set", file=sys.stderr)
    print("   Generate one with: python -c 'import secrets; print(secrets.token_hex(32))'", file=sys.stderr)
    print("   Add to .env file: FLASK_SECRET_KEY=<generated_key>", file=sys.stderr)
    sys.exit(1)

# FIX STAGE 2: Enable CORS
# FIX BUG #16: Make origins configurable - default includes common dev origins
cors_origins = os.getenv('CORS_ORIGINS', 'http://localhost:5000,http://127.0.0.1:5000').split(',')
CORS(app, resources={
    r"/api/*": {
        "origins": [o.strip() for o in cors_origins],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Authorization", "Content-Type", "X-API-Key"],
        "expose_headers": ["Content-Type", "X-Total-Count"]
    }
})

# SECURITY: Error handler for payload too large (413)
@app.errorhandler(413)
def request_entity_too_large(error):
    return error_response('Request payload too large (max 16MB)', 413)

# FIX STAGE 3: Enable compression
Compress(app)

# FIX STAGE 2: Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per minute", "2000 per hour"],
    storage_uri="memory://"
)

# ============================================================================
# CONSTANTS
# ============================================================================

# Access request constants
MAX_ACCESS_DURATION_HOURS = 168
MIN_ACCESS_DURATION_HOURS = 1
DEFAULT_ACCESS_DURATION_HOURS = 24
# Fallback reviewer email used in demo and test flows
DEFAULT_REVIEWER_EMAIL = 'admin@example.com'

# Role level validation
VALID_R_LEVELS = ['R1', 'R2', 'R3', 'R4']
VALID_L_LEVELS = ['L1', 'L2', 'L3']
VALID_B_LEVELS = ['B1', 'B2', 'B3', 'B4']

# Access request statuses
VALID_ACCESS_STATUSES = ['PENDING', 'APPROVED', 'DENIED', 'REVOKED', 'EXPIRED']
ACCESS_REQUEST_ADMIN_PERMISSION_KEYS = [
    'can_manage_access_requests',
    'can_review_access_requests',
    'can_admin',
    'is_admin'
]

# FIX STAGE 1: Pagination defaults
DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 500  # FIX: Increased to handle all 480 roles

# FIX STAGE 3: API Version
API_VERSION = "v1.0"

# ============================================================================
# LOGGING
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# B2B ROUTES INTEGRATION
# ============================================================================

# Optional routes for external ATS integration
try:
    from agents.b2b_routes import b2b_routes
    app.register_blueprint(b2b_routes)
    logger.info("[OK] B2B routes registered at /api/external/*")
except ImportError as e:
    logger.warning(f"[WARN] B2B routes not available: {e}")
    logger.warning("   B2B integration will not be accessible")
except Exception as e:
    logger.error(f"[FAIL] Failed to register B2B routes: {e}")

# ============================================================================
# DATABASE CONFIGURATION
# ============================================================================

DB_CONFIG = {
    'dbname': os.environ.get('DB_NAME', 'assessment_platform'),
    'user': os.environ.get('DB_USER', 'postgres'),
    'password': os.environ['DB_PASSWORD'],  # SECURITY FIX: No fallback - fail fast!
    'host': os.environ.get('DB_HOST', 'localhost'),
    'port': os.environ.get('DB_PORT', '5432'),
    'keepalives': 1,
    'keepalives_idle': 300,
    'keepalives_interval': 30,
    'keepalives_count': 3,
    'connect_timeout': 10,
}

# Initialize connection pool
try:
    connection_pool = pool.SimpleConnectionPool(
        minconn=1,
        maxconn=10,
        **DB_CONFIG
    )
    logger.info("[OK] Connection pool initialized successfully")
except Exception as e:
    logger.error(f"[FAIL] Failed to create connection pool: {str(e)}")
    connection_pool = None


# ============================================================================
# DATABASE CONNECTION MANAGER
# ============================================================================

@contextmanager
def get_db_connection():
    """Context manager for database connections with health check"""
    conn = None
    try:
        if connection_pool:
            conn = connection_pool.getconn()
            
            # Health check
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
            except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
                logger.warning(f"Stale connection detected, recycling... ({str(e)})")
                connection_pool.putconn(conn, close=True)
                conn = connection_pool.getconn()
        else:
            conn = psycopg2.connect(**DB_CONFIG)
        
        yield conn
        conn.commit()
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Database error: {str(e)}", exc_info=True)
        raise
    finally:
        if conn:
            if connection_pool:
                connection_pool.putconn(conn)
            else:
                conn.close()


# ============================================================================
# ERROR HANDLING
# ============================================================================

def handle_errors(f):
    """
    FIX STAGE 3: Enhanced error handling with standardized responses
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # FIX STAGE 3: Track request start time
        start_time = time.time()

        try:
            result = f(*args, **kwargs)

            # FIX STAGE 3: Log latency
            latency_ms = int((time.time() - start_time) * 1000)
            logger.info(f"{f.__name__} completed in {latency_ms}ms")

            return result

        except psycopg2.Error as e:
            latency_ms = int((time.time() - start_time) * 1000)
            logger.error(f"Database error in {f.__name__} ({latency_ms}ms): {str(e)}")

            details = str(e) if app.debug else None
            return error_response('Database error occurred', 500, code='DATABASE_ERROR', details=details)

        except ValueError as e:
            latency_ms = int((time.time() - start_time) * 1000)
            logger.warning(f"Validation error in {f.__name__}: {str(e)}")

            return error_response(str(e), 400)

        except Exception as e:
            latency_ms = int((time.time() - start_time) * 1000)

            # FIX BUG #11: Re-raise rate limit exceptions so Flask returns 429, not 500
            from werkzeug.exceptions import TooManyRequests
            if isinstance(e, TooManyRequests):
                raise

            logger.error(f"Unexpected error in {f.__name__} ({latency_ms}ms): {str(e)}", exc_info=True)

            details = str(e) if app.debug else None
            return error_response('An unexpected error occurred', 500, details=details)

    return decorated_function


# ============================================================================
# API KEY AUTHENTICATION
# ============================================================================

def verify_api_key(f):
    """Decorator to verify API key OR allow browser requests"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Allow browser requests (have Referer header, no Authorization)
        referer = request.headers.get('Referer', '')
        auth_header = request.headers.get('Authorization', '')
        
        # If there's a Referer but no Authorization, it's from the web UI
        allowed_origins = [
            'localhost:5000', 
            '127.0.0.1:5000',
            ':5000'
        ]
        
        # FIX BUG #7: Remove dangerous host-based bypass that accepted ANY request
        # without Authorization header when host contains ':5000'
        # Now only allows Referer-based bypass from known localhost origins
        is_local_request = (
            referer and any(origin in referer for origin in allowed_origins) and not auth_header
        )

        if is_local_request:
            # Browser request - require user login
            if 'admin_user' not in session and 'user' not in session:
                return error_response('Authentication required', 401)

            logger.info(f"Web UI: {request.method} {request.path} from {request.remote_addr}")
            return f(*args, **kwargs)
        
        # Otherwise require API key
        auth_header = request.headers.get('Authorization', '')
        
        if not auth_header.startswith('Bearer '):
            return error_response(
                'Missing or invalid Authorization header',
                401,
                details='Expected: Authorization: Bearer <api_key>'
            )
        
        api_key = auth_header.replace('Bearer ', '').strip()
        
        if not api_key:
            return error_response('API key is empty', 401)
        
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # FIX BUG #2: Verify with Python bcrypt instead of PostgreSQL crypt()
                # bcrypt.hashpw() in manage_keys.py produces $2b$ hashes that pgcrypto
                # may not recognize. Fetch all active keys and verify in Python.
                cur.execute("""
                    SELECT 
                        key_id, key_hash, agent_name, permissions, is_active, expires_at
                    FROM api_keys
                    WHERE is_active = TRUE
                """)
                
                key_data = None
                for row in cur.fetchall():
                    try:
                        if bcrypt.checkpw(api_key.encode('utf-8'), row['key_hash'].encode('utf-8')):
                            key_data = row
                            break
                    except (ValueError, TypeError):
                        continue
                
                if not key_data:
                    log_api_access(None, request.path, request.method, 401, None)
                    return error_response('Invalid or inactive API key', 401)

                # Check expiration
                if key_data['expires_at'] and key_data['expires_at'] < datetime.now(timezone.utc):
                    return error_response('API key has expired', 401)
                
                # Update usage stats
                cur.execute("""
                    UPDATE api_keys
                    SET last_used_at = NOW(), times_used = times_used + 1
                    WHERE key_id = %s
                """, (key_data['key_id'],))
                
                log_api_access(key_data['key_id'], request.path, request.method, 200, None)
                
                g.api_key = key_data
                logger.info(f"[OK] API: {key_data['agent_name']} -> {request.method} {request.path}")
        
        return f(*args, **kwargs)
    
    return decorated_function


def _normalize_api_key_permissions(raw_permissions):
    """Normalize api key permissions to a dict for safe permission checks."""
    if raw_permissions is None:
        return {}

    if isinstance(raw_permissions, dict):
        return raw_permissions

    # RealDictCursor can already return JSONB as dict, but keep string fallback.
    if isinstance(raw_permissions, str):
        try:
            parsed = json.loads(raw_permissions)
            return parsed if isinstance(parsed, dict) else {}
        except (json.JSONDecodeError, TypeError):
            return {}

    return {}


def _has_access_request_admin_permission(api_key_data):
    """Check if an API key has explicit access-request admin permissions."""
    if not api_key_data:
        return False

    permissions = _normalize_api_key_permissions(api_key_data.get('permissions'))
    for perm_key in ACCESS_REQUEST_ADMIN_PERMISSION_KEYS:
        if permissions.get(perm_key) is True:
            return True
    return False


def require_access_request_admin(f):
    """
    Ensure only admin principals can manage access requests.
    Allowed:
    - Logged-in admin session
    - API key with explicit admin permission flag
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_user' in session:
            return f(*args, **kwargs)

        api_key_data = getattr(g, 'api_key', None)
        if api_key_data and _has_access_request_admin_permission(api_key_data):
            return f(*args, **kwargs)

        actor = None
        if api_key_data:
            actor = api_key_data.get('agent_name') or api_key_data.get('key_id')
        elif 'user' in session:
            actor = session['user'].get('email')
        elif 'admin_user' in session:
            actor = session['admin_user'].get('email')
        else:
            actor = request.remote_addr

        logger.warning(
            f"[SECURITY] Access request admin action denied for actor={actor} "
            f"path={request.path} method={request.method}"
        )
        return error_response(
            'Admin access required for access request management',
            403,
            code='INSUFFICIENT_PERMISSIONS'
        )

    return decorated_function


def log_api_access(key_id, endpoint, method, status_code, latency_ms):
    """
    FIX STAGE 3: Enhanced API logging with latency
    """
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # FIX STAGE 3: Log with latency if available
                cur.execute("""
                    INSERT INTO api_key_logs 
                    (key_id, endpoint, method, status_code, ip_address, user_agent)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (
                    key_id,
                    endpoint,
                    method,
                    status_code,
                    request.remote_addr,
                    request.headers.get('User-Agent', '')[:255]
                ))
    except Exception as e:
        logger.error(f"Failed to log API access: {str(e)}")


# ============================================================================
# PAGE ROUTES (Protected - Login Required)
# ============================================================================

@app.route('/')
@require_login
def index():
    """Main dashboard page"""
    log_action(AuditAction.VIEW_DASHBOARD)
    return render_template('index.html')


@app.route('/roles')
@require_login
def roles_browser():
    """Role browser page - search/filter"""
    log_action(AuditAction.VIEW_ROLES)
    return render_template('role_detail.html')


@app.route('/role/<role_id>')
@require_login
def role_detail(role_id):
    """Role deep dive page"""
    # Validate role_id
    if not role_id or len(role_id) > 100:
        return error_response('Invalid role ID', 400)

    safe_chars = role_id.replace('-', '').replace('_', '')
    if not safe_chars.isalnum():
        return error_response('Invalid role ID format', 400)

    log_action(AuditAction.VIEW_ROLE_DETAIL, ResourceType.ROLE, role_id)
    return render_template('role_detail.html', role_id=role_id)


@app.route('/dashboard/access-requests')
@require_admin_login
def access_requests_page():
    """Agent access requests management page (Admin only)"""
    return render_template('access_requests.html')

# Redirect old route to new one for backward compatibility
@app.route('/access-requests')
@require_admin_login
def access_requests_redirect():
    """Redirect old access-requests route to new dashboard location"""
    return redirect('/dashboard/access-requests')


# ============================================================================
# API ENDPOINTS (Protected - Require API Key)
# ============================================================================

# FIX STAGE 2: Enhanced health check (no auth required for monitoring)
@app.route('/health')
@handle_errors
def health_check():
    """
    FIX STAGE 2: Enhanced health check for monitoring/load balancers
    Public endpoint - no authentication required
    """
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # Check database connection
                cur.execute("SELECT 1")
                
                # Get role count
                cur.execute("SELECT COUNT(*) FROM role_master WHERE status = 'Active'")
                role_count = cur.fetchone()[0]
                
                # Get database version
                cur.execute("SELECT version()")
                db_version = cur.fetchone()[0].split(',')[0]
        
        return jsonify({
            "status": "healthy",
            "database": {
                "status": "connected",
                "version": db_version,
                "active_roles": role_count
            },
            "connection_pool": {
                "status": "active" if connection_pool else "disabled"
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": API_VERSION
        }), 200
        
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            "status": "unhealthy",
            "database": {
                "status": "disconnected",
                "error": str(e)
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": API_VERSION
        }), 503


# FIX STAGE 1: NEW - Metadata endpoint for dropdown values
@app.route('/api/metadata')
@verify_api_key
@handle_errors
def get_metadata():
    """
    FIX STAGE 1: Get all available filter metadata for dropdowns
    
    Returns distinct values for:
    - functions
    - domains  
    - sub_functions
    - r/l/b levels
    
    This ensures frontend dropdowns always have correct values from database.
    """
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            # Get distinct functions
            cur.execute("""
                SELECT DISTINCT function
                FROM role_master
                WHERE status = 'Active' 
                  AND function IS NOT NULL 
                  AND function != ''
                ORDER BY function
            """)
            functions = [row[0] for row in cur.fetchall()]
            
            # Get distinct domains
            cur.execute("""
                SELECT DISTINCT domain
                FROM role_master
                WHERE status = 'Active' 
                  AND domain IS NOT NULL 
                  AND domain != ''
                ORDER BY domain
            """)
            domains = [row[0] for row in cur.fetchall()]
            
            # Get distinct sub-functions
            cur.execute("""
                SELECT DISTINCT sub_function
                FROM role_master
                WHERE status = 'Active' 
                  AND sub_function IS NOT NULL 
                  AND sub_function != ''
                ORDER BY sub_function
            """)
            sub_functions = [row[0] for row in cur.fetchall()]
            
            logger.info(
                f"Metadata: {len(functions)} functions, "
                f"{len(domains)} domains, {len(sub_functions)} sub-functions"
            )
            
            # FIX STAGE 3: Standardized success response
            return jsonify({
                "success": True,
                "data": {
                    "functions": functions,
                    "domains": domains,
                    "sub_functions": sub_functions,
                    "r_levels": VALID_R_LEVELS,
                    "l_levels": VALID_L_LEVELS,
                    "b_levels": VALID_B_LEVELS
                },
                "meta": {
                    "total_functions": len(functions),
                    "total_domains": len(domains),
                    "total_sub_functions": len(sub_functions),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "version": API_VERSION
                }
            })


@app.route('/api/roles')
@verify_api_key
@handle_errors
@limiter.limit("100 per minute")  # FIX STAGE 2: Rate limiting
def get_roles():
    """
    FIX STAGE 1: Added pagination and fixed function filter

    Get active roles with filters and pagination.

    Query Parameters:
        - search: Search term
        - function: Exact function filter (use /api/metadata to get valid values)
        - r_level, l_level, b_level: Level filters
        - page: Page number (default 1)
        - page_size: Results per page (default 20, max 100)
    """
    # Check permission for regular users (admins and API key users bypass this)
    if 'user' in session and not session['user'].get('can_view_roles', False):
        return error_response('Permission denied', 403, details='can_view_roles')

    # Get filter parameters
    search_term = request.args.get('search', '').strip()
    function_filter = request.args.get('function', '').strip()
    r_level_filter = request.args.get('r_level', '').strip()
    l_level_filter = request.args.get('l_level', '').strip()
    b_level_filter = request.args.get('b_level', '').strip()
    
    # FIX STAGE 1: Get pagination parameters
    try:
        page = int(request.args.get('page', 1))
        page_size = int(request.args.get('page_size', DEFAULT_PAGE_SIZE))
    except ValueError:
        raise ValueError("Page and page_size must be integers")
    
    # FIX STAGE 1: Validate pagination
    if page < 1:
        raise ValueError("Page must be >= 1")
    if page_size < 1 or page_size > MAX_PAGE_SIZE:
        raise ValueError(f"Page size must be between 1 and {MAX_PAGE_SIZE}")
    
    # Validate level filters
    if r_level_filter and r_level_filter not in VALID_R_LEVELS:
        raise ValueError(f"Invalid r_level: {r_level_filter}")
    if l_level_filter and l_level_filter not in VALID_L_LEVELS:
        raise ValueError(f"Invalid l_level: {l_level_filter}")
    if b_level_filter and b_level_filter not in VALID_B_LEVELS:
        raise ValueError(f"Invalid b_level: {b_level_filter}")
    
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Base query
            query = """
                SELECT 
                    role_master_id,
                    role_title,
                    function,
                    sub_function,
                    r_level,
                    l_level,
                    b_level,
                    typical_designation,
                    years_experience_min,
                    years_experience_max,
                    tech_qa_bank_id,
                    beh_qa_bank_id,
                    domain,
                    status
                FROM role_master
                WHERE status = 'Active'
            """
            
            params = []
            
            # Search filter
            if search_term:
                query += """
                    AND (
                        LOWER(role_title) LIKE %s
                        OR LOWER(function) LIKE %s
                        OR LOWER(sub_function) LIKE %s
                        OR LOWER(typical_designation) LIKE %s
                        OR LOWER(domain) LIKE %s
                        OR role_master_id LIKE %s
                    )
                """
                search_pattern = f'%{search_term.lower()}%'
                params.extend([search_pattern] * 6)
            
            # FIX STAGE 1: Function filter (EXACT MATCH - critical fix!)
            if function_filter:
                query += " AND function = %s"
                params.append(function_filter)
            
            # Level filters
            if r_level_filter:
                query += " AND r_level = %s"
                params.append(r_level_filter)
            
            if l_level_filter:
                query += " AND l_level = %s"
                params.append(l_level_filter)
            
            if b_level_filter:
                query += " AND b_level = %s"
                params.append(b_level_filter)
            
            # FIX STAGE 1: Get total count BEFORE pagination
            # Build count query from scratch (more reliable than string replace)
            count_query = """
                SELECT COUNT(*) as count
                FROM role_master
                WHERE status = 'Active'
            """
            
            count_params = []
            
            # Add same filters as main query
            if search_term:
                count_query += """
                    AND (
                        LOWER(role_title) LIKE %s
                        OR LOWER(function) LIKE %s
                        OR LOWER(sub_function) LIKE %s
                        OR LOWER(typical_designation) LIKE %s
                        OR LOWER(domain) LIKE %s
                        OR role_master_id LIKE %s
                    )
                """
                search_pattern = f'%{search_term.lower()}%'
                count_params.extend([search_pattern] * 6)
            
            if function_filter:
                count_query += " AND function = %s"
                count_params.append(function_filter)
            
            if r_level_filter:
                count_query += " AND r_level = %s"
                count_params.append(r_level_filter)
            
            if l_level_filter:
                count_query += " AND l_level = %s"
                count_params.append(l_level_filter)
            
            if b_level_filter:
                count_query += " AND b_level = %s"
                count_params.append(b_level_filter)
            
            cur.execute(count_query, count_params)
            total_count = cur.fetchone()['count']
            
            # FIX STAGE 1: Add sorting and pagination
            query += " ORDER BY role_title"
            offset = (page - 1) * page_size
            query += " LIMIT %s OFFSET %s"
            params.extend([page_size, offset])
            
            # Execute main query
            cur.execute(query, params)
            roles = cur.fetchall()
            
            # FIX STAGE 1: Calculate total pages
            total_pages = (total_count + page_size - 1) // page_size
            
            logger.info(
                f"Roles query: Page {page}/{total_pages} | "
                f"{len(roles)} results (of {total_count} total) | "
                f"Search: '{search_term}' | Function: '{function_filter}' | "
                f"R: {r_level_filter} | L: {l_level_filter} | B: {b_level_filter}"
            )
            
            # FIX STAGE 3: Standardized success response with pagination
            return jsonify({
                "success": True,
                "data": {
                    "roles": roles,
                    "count": len(roles)
                },
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total_count": total_count,
                    "total_pages": total_pages,
                    "has_next": page < total_pages,
                    "has_prev": page > 1
                },
                "filters": {
                    "search": search_term,
                    "function": function_filter,
                    "r_level": r_level_filter,
                    "l_level": l_level_filter,
                    "b_level": b_level_filter
                },
                "meta": {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "version": API_VERSION
                }
            })


@app.route('/api/jd/<identifier>')
@verify_api_key
@handle_errors
def get_job_description(identifier):
    """
    FIX STAGE 2: Fixed N+1 query problem - now uses single JOIN query
    FIX STAGE 1: Fixed 404 handling
    FIX: Now accepts both role_id (AOP-QA-...) and jd_id (JD-...)

    Get complete job description with ALL sections and duties.
    """
    # Check permission for regular users (admins and API key users bypass this)
    if 'user' in session and not session['user'].get('can_view_jds', False):
        return error_response('Permission denied', 403, details='can_view_jds')

    if not identifier:
        raise ValueError("Identifier is required")
    
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Determine if it's a jd_id or role_id
            role_id = None  # Initialize to avoid scope issues
            
            if identifier.startswith('JD-'):
                # Direct JD lookup
                jd_id = identifier
                
                # Get role details from JD
                cur.execute("""
                    SELECT 
                        rm.role_master_id,
                        rm.role_title,
                        rm.function,
                        rm.sub_function,
                        rm.r_level,
                        rm.l_level,
                        rm.b_level,
                        rm.typical_designation,
                        rm.years_experience_min,
                        rm.years_experience_max,
                        rm.domain,
                        jd.jd_id
                    FROM job_descriptions jd
                    JOIN role_master rm ON rm.role_master_id = jd.role_master_id
                    WHERE jd.jd_id = %s AND rm.status = 'Active'
                """, (jd_id,))
                
                role = cur.fetchone()
                
                if not role:
                    return error_response(
                        'Job description not found', 404,
                        code='JD_NOT_FOUND',
                        details=f'No JD found with ID: {jd_id}'
                    )

                role_id = role['role_master_id']  # Set role_id from result
                    
            elif identifier.startswith('AOP-QA-'):
                # Role ID lookup
                role_id = identifier
                
                # Get role details
                cur.execute("""
                    SELECT 
                        rm.role_master_id,
                        rm.role_title,
                        rm.function,
                        rm.sub_function,
                        rm.r_level,
                        rm.l_level,
                        rm.b_level,
                        rm.typical_designation,
                        rm.years_experience_min,
                        rm.years_experience_max,
                        rm.domain
                    FROM role_master rm
                    WHERE rm.role_master_id = %s AND rm.status = 'Active'
                """, (role_id,))
                
                role = cur.fetchone()
                
                if not role:
                    return error_response(
                        'Role not found or inactive', 404,
                        code='ROLE_NOT_FOUND',
                        details=f'No active role with ID: {role_id}'
                    )
                
                # Get job description ID
                cur.execute("""
                    SELECT jd_id 
                    FROM job_descriptions 
                    WHERE role_master_id = %s
                    LIMIT 1
                """, (role_id,))
                
                jd_result = cur.fetchone()
                
                if not jd_result:
                    return error_response(
                        'Job description not found for this role', 404,
                        code='JD_NOT_FOUND',
                        details=f'No JD found for role: {role_id}'
                    )
                
                jd_id = jd_result['jd_id']
            else:
                raise ValueError(f"Invalid identifier format: {identifier}. Must start with 'JD-' or 'AOP-QA-'")
            
            # FIX STAGE 2: Single JOIN query instead of N+1
            # This is MUCH faster - one query instead of 1 + N queries
            cur.execute("""
                SELECT 
                    s.jd_section_id,
                    s.section_title,
                    s.full_content,
                    s.display_order as section_order,
                    d.jd_duty_id,
                    d.duty_number,
                    d.duty_description,
                    d.status as duty_status
                FROM jd_sections s
                LEFT JOIN jd_duties d ON s.jd_section_id = d.jd_section_id
                    AND d.status = 'Active'
                WHERE s.jd_id = %s
                    AND s.status = 'Active'
                ORDER BY s.display_order, d.duty_number
            """, (jd_id,))
            
            rows = cur.fetchall()
            
            # Organize into sections with duties (in Python, not SQL)
            sections_dict = {}
            for row in rows:
                section_id = row['jd_section_id']
                
                if section_id not in sections_dict:
                    sections_dict[section_id] = {
                        'section_id': section_id,
                        'section_title': row['section_title'],
                        'full_content': row['full_content'],  # FIX: Match frontend expectation
                        'section_order': row['section_order'],
                        'duties': []
                    }

                # Add duty if exists
                if row['jd_duty_id']:
                    sections_dict[section_id]['duties'].append({
                        'duty_id': row['jd_duty_id'],
                        'duty_number': row['duty_number'],
                        'duty_description': row['duty_description']  # FIX: Match frontend expectation
                    })
            
            # Convert to sorted list
            sections = sorted(sections_dict.values(), key=lambda x: x['section_order'])
            
            logger.info(f"JD for {role_id}: {len(sections)} sections retrieved (single query)")

            # Log JD view
            log_action(AuditAction.VIEW_JD, ResourceType.JD, identifier)

            # FIX STAGE 3: Standardized success response
            return jsonify({
                "success": True,
                "data": {
                    "role": dict(role),
                    "sections": sections,
                    "total_sections": len(sections)
                },
                "meta": {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "version": API_VERSION
                }
            })


@app.route('/api/questions/<role_id>')
@verify_api_key
@handle_errors
def get_questions(role_id):
    """Get questions for a specific role"""
    # Check permission for regular users (admins and API key users bypass this)
    if 'user' in session and not session['user'].get('can_view_roles', False):
        return error_response('Permission denied', 403, details='can_view_roles')

    if not role_id or not role_id.startswith('AOP-QA-'):
        raise ValueError(f"Invalid role_id format: {role_id}")
    
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get role details
            cur.execute("""
                SELECT tech_qa_bank_id, beh_qa_bank_id, role_title,
                       r_level, l_level, b_level
                FROM role_master
                WHERE role_master_id = %s AND status = 'Active'
            """, (role_id,))
            
            role = cur.fetchone()
            
            if not role:
                return error_response('Role not found or inactive', 404, code='ROLE_NOT_FOUND')

            # Get technical questions
            cur.execute("""
                SELECT
                    question_id,
                    text,
                    model_answer,
                    scoring_criteria,
                    competency,
                    level,
                    category,
                    status
                FROM questions
                WHERE bank_id = %s
                    AND status = 'Active'
                    AND LOWER(question_bank) = 'technical'
                ORDER BY level, question_id
            """, (role['tech_qa_bank_id'],))
            
            technical_questions = cur.fetchall()
            
            # Get behavioral questions
            cur.execute("""
                SELECT
                    question_id,
                    text,
                    model_answer,
                    scoring_criteria,
                    competency,
                    level,
                    category,
                    status
                FROM questions
                WHERE bank_id = %s
                    AND status = 'Active'
                    AND LOWER(question_bank) = 'behavioral'
                ORDER BY level, question_id
            """, (role['beh_qa_bank_id'],))
            
            behavioral_questions = cur.fetchall()
            
            # Organize by level
            tech_by_level = {'L1': [], 'L2': [], 'L3': []}
            for q in technical_questions:
                level = q['level']
                if level in tech_by_level:
                    tech_by_level[level].append(dict(q))
            
            beh_by_level = {'B1': [], 'B2': [], 'B3': [], 'B4': []}
            for q in behavioral_questions:
                level = q['level']
                if level in beh_by_level:
                    beh_by_level[level].append(dict(q))
            
            logger.info(
                f"Questions for {role_id}: "
                f"{len(technical_questions)} technical, "
                f"{len(behavioral_questions)} behavioral"
            )

            # Log questions view
            log_action(AuditAction.VIEW_QUESTIONS, ResourceType.QUESTION, role_id)

            # FIX STAGE 3: Standardized response
            return jsonify({
                "success": True,
                "data": {
                    "role_id": role_id,
                    "r_level": role['r_level'],
                    "l_level": role['l_level'],
                    "b_level": role['b_level'],
                    "technical_questions": tech_by_level,
                    "behavioral_questions": beh_by_level,
                    "counts": {
                        "technical_total": len(technical_questions),
                        "behavioral_total": len(behavioral_questions),
                        "technical_by_level": {k: len(v) for k, v in tech_by_level.items()},
                        "behavioral_by_level": {k: len(v) for k, v in beh_by_level.items()}
                    }
                },
                "meta": {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "version": API_VERSION
                }
            })


@app.route('/api/roles/<role_id>/available-levels')
@verify_api_key
@handle_errors
def get_available_levels(role_id):
    """Get available question levels for a specific role"""
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get question bank IDs
            cur.execute("""
                SELECT tech_qa_bank_id, beh_qa_bank_id
                FROM role_master
                WHERE role_master_id = %s AND status = 'Active'
            """, (role_id,))
            
            role = cur.fetchone()
            
            if not role:
                return error_response('Role not found', 404, code='ROLE_NOT_FOUND')

            # Get available technical levels
            cur.execute("""
                SELECT DISTINCT level
                FROM questions
                WHERE bank_id = %s
                    AND status = 'Active'
                    AND LOWER(question_bank) = 'technical'
                ORDER BY level
            """, (role['tech_qa_bank_id'],))
            
            tech_levels = [row['level'] for row in cur.fetchall()]
            
            # Get available behavioral levels
            cur.execute("""
                SELECT DISTINCT level
                FROM questions
                WHERE bank_id = %s
                    AND status = 'Active'
                    AND LOWER(question_bank) = 'behavioral'
                ORDER BY level
            """, (role['beh_qa_bank_id'],))
            
            beh_levels = [row['level'] for row in cur.fetchall()]
            
            return jsonify({
                "success": True,
                "data": {
                    "role_id": role_id,
                    "tech_qa_bank_id": role['tech_qa_bank_id'],
                    "beh_qa_bank_id": role['beh_qa_bank_id'],
                    "available_tech_levels": tech_levels,
                    "available_beh_levels": beh_levels
                },
                "meta": {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "version": API_VERSION
                }
            })


@app.route('/api/generate-script', methods=['POST'])
@verify_api_key
@handle_errors
@limiter.limit("20 per minute")  # FIX STAGE 2: Rate limit expensive operations
def generate_interview_script():
    """
    FIX STAGE 1: Added comprehensive input validation

    Generate random interview script with validated input.

    Request Body:
        {
            "role_id": "AOP-QA-...",
            "l1_count": 3,  // Optional, default 0
            "l2_count": 2,  // Optional, default 0
            "l3_count": 1   // Optional, default 0
        }
    """
    # Check permission for regular users (admins and API key users bypass this)
    if 'user' in session and not session['user'].get('can_generate_questions', False):
        return error_response('Permission denied', 403, details='can_generate_questions')

    data = request.json

    if not data:
        raise ValueError("Request body is required")
    
    role_id = data.get('role_id')
    
    if not role_id:
        raise ValueError("role_id is required")
    
    if not role_id.startswith('AOP-QA-'):
        raise ValueError(f"Invalid role_id format: {role_id}")
    
    # FIX STAGE 1: Parse and validate question counts
    try:
        l1_count = int(data.get('l1_count', 0))
        l2_count = int(data.get('l2_count', 0))
        l3_count = int(data.get('l3_count', 0))
    except (ValueError, TypeError):
        raise ValueError("Question counts must be integers")
    
    # FIX STAGE 1: Validate ranges
    if l1_count < 0 or l2_count < 0 or l3_count < 0:
        raise ValueError("Question counts cannot be negative")
    
    total_questions = l1_count + l2_count + l3_count
    
    if total_questions == 0:
        raise ValueError("At least one question must be requested")
    
    if total_questions > 50:
        raise ValueError("Total questions cannot exceed 50")
    
    # FIX STAGE 1: Validate individual counts
    if l1_count > 20 or l2_count > 20 or l3_count > 10:
        raise ValueError("Individual level counts too high (max: L1=20, L2=20, L3=10)")
    
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Verify role exists
            cur.execute("""
                SELECT tech_qa_bank_id, beh_qa_bank_id, role_title
                FROM role_master
                WHERE role_master_id = %s AND status = 'Active'
            """, (role_id,))
            
            role = cur.fetchone()
            
            if not role:
                return error_response('Role not found or inactive', 404, code='ROLE_NOT_FOUND')

            # Get questions for each level
            script = []
            
            # Helper function to get random questions
            def get_random_questions(bank_id, level, count):
                if count == 0:
                    return []
                
                cur.execute("""
                    SELECT
                        question_id,
                        text,
                        level,
                        competency,
                        model_answer,
                        scoring_criteria
                    FROM questions
                    WHERE bank_id = %s
                        AND level = %s
                        AND status = 'Active'
                        AND LOWER(question_bank) = 'technical'
                    ORDER BY RANDOM()
                    LIMIT %s
                """, (bank_id, level, count))
                
                return cur.fetchall()
            
            # Get L1 questions
            if l1_count > 0:
                l1_questions = get_random_questions(role['tech_qa_bank_id'], 'L1', l1_count)
                script.extend(l1_questions)
                
                # FIX STAGE 1: Check if we got enough
                if len(l1_questions) < l1_count:
                    logger.warning(
                        f"Only {len(l1_questions)} L1 questions available, "
                        f"requested {l1_count}"
                    )
            
            # Get L2 questions
            if l2_count > 0:
                l2_questions = get_random_questions(role['tech_qa_bank_id'], 'L2', l2_count)
                script.extend(l2_questions)
                
                if len(l2_questions) < l2_count:
                    logger.warning(
                        f"Only {len(l2_questions)} L2 questions available, "
                        f"requested {l2_count}"
                    )
            
            # Get L3 questions
            if l3_count > 0:
                l3_questions = get_random_questions(role['tech_qa_bank_id'], 'L3', l3_count)
                script.extend(l3_questions)
                
                if len(l3_questions) < l3_count:
                    logger.warning(
                        f"Only {len(l3_questions)} L3 questions available, "
                        f"requested {l3_count}"
                    )
            
            logger.info(
                f"Generated script for {role_id}: "
                f"{len(script)} questions (L1:{l1_count}, L2:{l2_count}, L3:{l3_count})"
            )

            # Log question generation
            log_action(
                AuditAction.GENERATE_QUESTIONS,
                ResourceType.ROLE,
                role_id,
                {'l1_count': l1_count, 'l2_count': l2_count, 'l3_count': l3_count, 'total_generated': len(script)}
            )

            # FIX STAGE 3: Standardized response
            return jsonify({
                "success": True,
                "data": {
                    "role_id": role_id,
                    "role_title": role['role_title'],
                    "questions": script,
                    "requested": {
                        "l1": l1_count,
                        "l2": l2_count,
                        "l3": l3_count,
                        "total": total_questions
                    },
                    "actual": {
                        "total": len(script)
                    }
                },
                "meta": {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "version": API_VERSION
                }
            })


# ============================================================================
# ACCESS REQUEST ENDPOINTS (Existing - keeping as is)
# ============================================================================

@app.route('/api/access-requests', methods=['GET'])
@verify_api_key
@require_access_request_admin
@handle_errors
def get_access_requests():
    """Get all access requests (admin only)"""
    status_filter = request.args.get('status', '').upper()

    if status_filter and status_filter not in VALID_ACCESS_STATUSES:
        raise ValueError(f"Invalid status: {status_filter}")

    with get_db_connection() as conn:
        requests_data = svc_list_access_requests(conn, status_filter=status_filter or None)

        return jsonify({
            "success": True,
            "data": {
                "requests": requests_data,
                "count": len(requests_data)
            },
            "filters": {
                "status": status_filter if status_filter else "all"
            }
        })


@app.route('/api/access-requests/<int:request_id>/approve', methods=['POST'])
@verify_api_key
@require_access_request_admin
@handle_errors
def approve_access_request(request_id):
    """
    Approve an access request
    SECURITY FIX: SQL injection vulnerability fixed - using make_interval()
    """
    data = request.json or {}

    duration_hours = int(data.get('duration_hours', DEFAULT_ACCESS_DURATION_HOURS))
    review_notes = data.get('notes', '').strip()
    reviewed_by = data.get('reviewed_by', DEFAULT_REVIEWER_EMAIL).strip()

    # Validate duration
    if duration_hours <= 0 or duration_hours > MAX_ACCESS_DURATION_HOURS:
        raise ValueError(
            f"duration_hours must be between {MIN_ACCESS_DURATION_HOURS} "
            f"and {MAX_ACCESS_DURATION_HOURS}"
        )

    with get_db_connection() as conn:
        updated = svc_approve_access_request(
            conn,
            request_id=request_id,
            reviewed_by=reviewed_by,
            review_notes=review_notes,
            duration_hours=duration_hours,
        )

        if not updated:
            return error_response('Request not found or already processed', 404, code='REQUEST_NOT_FOUND')

        logger.info(
            f"[OK] Access request #{request_id} APPROVED by {reviewed_by} "
            f"for {duration_hours}h"
        )

        return jsonify({
            "success": True,
            "data": {
                "request_id": request_id,
                "status": "APPROVED",
                "access_expires_at": updated['access_expires_at'].isoformat(),
                "message": f"Access granted for {duration_hours} hours"
            },
            "meta": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "version": API_VERSION
            }
        })


@app.route('/api/access-requests/<int:request_id>/deny', methods=['POST'])
@verify_api_key
@require_access_request_admin
@handle_errors
def deny_access_request(request_id):
    """Deny an access request"""
    data = request.json or {}

    reason = data.get('reason', '').strip()
    reviewed_by = data.get('reviewed_by', DEFAULT_REVIEWER_EMAIL).strip()

    if not reason:
        raise ValueError("Denial reason is required")

    with get_db_connection() as conn:
        updated = svc_deny_access_request(
            conn,
            request_id=request_id,
            reviewed_by=reviewed_by,
            reason=reason,
        )

        if not updated:
            return error_response('Request not found or already processed', 404, code='REQUEST_NOT_FOUND')

        logger.info(f"[DENIED] Access request #{request_id} DENIED by {reviewed_by}: {reason}")

        return jsonify({
            "success": True,
            "data": {
                "request_id": request_id,
                "status": "DENIED",
                "message": "Access request denied"
            },
            "meta": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "version": API_VERSION
            }
        })


@app.route('/api/access-requests/<int:request_id>/revoke', methods=['POST'])
@verify_api_key
@require_access_request_admin
@handle_errors
def revoke_access_request(request_id):
    """Revoke an approved access request"""
    data = request.json or {}

    reason = data.get('reason', '').strip()

    if not reason:
        raise ValueError("Revocation reason is required")

    with get_db_connection() as conn:
        updated = svc_revoke_access_request(
            conn,
            request_id=request_id,
            reason=reason,
        )

        if not updated:
            return error_response('Request not found or not approved', 404, code='REQUEST_NOT_FOUND')

        logger.info(f"[REVOKED] Access request #{request_id}: {reason}")

        return jsonify({
            "success": True,
            "data": {
                "request_id": request_id,
                "status": "REVOKED",
                "message": "Access revoked"
            },
            "meta": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "version": API_VERSION
            }
        })

# ====================================================================================
# UNIFIED AUTHENTICATION ROUTES (Admin + Users)
# ====================================================================================

@app.route('/login', methods=['GET'])
def login_page():
    """Render unified login page for both admin and users"""
    # If already logged in, redirect to dashboard
    if 'admin_user' in session or 'user' in session:
        return redirect('/')
    return render_template('login.html')


@app.route('/api/login', methods=['POST'])
def login():
    """
    Unified login endpoint - tries admin first, then user
    Auto-detects whether email belongs to admin or regular user
    """
    try:
        data = request.json
        if not data:
            return error_response('Request body is required', 400)

        email = data.get('email', '').strip().lower()
        password = data.get('password', '')

        if not email or not password:
            return error_response('Email and password are required', 400)

        # Try admin login first
        admin = authenticate_admin(email, password, DB_CONFIG)
        if admin:
            # Admin login successful
            session['admin_user'] = {
                'admin_id': admin['admin_id'],
                'email': admin['email'],
                'full_name': admin['full_name']
            }

            # Log successful admin login
            log_action(AuditAction.LOGIN)

            return jsonify({
                'success': True,
                'user_type': 'admin',
                'user': {
                    'email': admin['email'],
                    'full_name': admin['full_name']
                }
            }), 200

        # Try user login
        user = authenticate_user(email, password, DB_CONFIG)
        if user:
            # User login successful
            session['user'] = user

            # Log successful user login
            log_action(AuditAction.LOGIN)

            return jsonify({
                'success': True,
                'user_type': 'user',
                'user': {
                    'email': user['email'],
                    'full_name': user['full_name'],
                    'permissions': {
                        'can_view_roles': user['can_view_roles'],
                        'can_view_jds': user['can_view_jds'],
                        'can_generate_questions': user['can_generate_questions'],
                        'can_view_analytics': user['can_view_analytics'],
                        'can_export_data': user['can_export_data']
                    }
                }
            }), 200

        # Both failed - invalid credentials
        log_action(AuditAction.FAILED_LOGIN, details={'email': email})
        return error_response('Invalid email or password', 401)

    except Exception as e:
        logger.error(f"Login error: {e}", exc_info=True)
        return error_response('Internal server error', 500)


@app.route('/api/logout', methods=['POST'])
def logout():
    """Unified logout endpoint - logs out both admin and users"""
    # Log logout before clearing session
    log_action(AuditAction.LOGOUT)

    # Clear session
    logout_user()

    return jsonify({'success': True}), 200


# ====================================================================================
# ADMIN AUTHENTICATION ROUTES (Legacy - kept for compatibility)
# ====================================================================================

# Note: authenticate_admin and require_admin_login imported at top of file
from validators import validate_request, validate_path_param, AdminLoginRequest, ApprovalRequest, DenialRequest, is_safe_integer
from db_pool import get_transaction
from psycopg2.extensions import ISOLATION_LEVEL_READ_COMMITTED

@app.route('/admin/login', methods=['GET'])
def admin_login_page():
    """Render admin login page"""
    # If already logged in, redirect to dashboard
    if 'admin_user' in session:
        return redirect('/dashboard/b2b-authorizations')
    return render_template('admin_login.html')

@app.route('/api/admin/login', methods=['POST'])
@validate_request(AdminLoginRequest)
def admin_login():
    """Admin login API endpoint"""
    try:
        # Get validated data (validated by @validate_request decorator)
        validated = request.validated_data

        admin = authenticate_admin(validated.email, validated.password, DB_CONFIG)

        if not admin:
            # Log failed login attempt
            log_action(AuditAction.FAILED_LOGIN, details={'email': validated.email})
            return error_response('Invalid credentials', 401)

        # Store in session
        session['admin_user'] = {
            'admin_id': admin['admin_id'],
            'email': admin['email'],
            'full_name': admin['full_name']
        }

        # Log successful login
        log_action(AuditAction.LOGIN)
        logger.info(f"[OK] Admin logged in: {validated.email}")

        return jsonify({
            'success': True,
            'admin': {
                'email': admin['email'],
                'full_name': admin['full_name']
            }
        }), 200

    except Exception as e:
        logger.error(f"Login error: {e}", exc_info=True)
        return error_response('Internal server error', 500)

@app.route('/api/admin/logout', methods=['POST'])
def admin_logout():
    """Admin logout"""
    admin_email = session.get('admin_user', {}).get('email', 'Unknown')

    # Log logout before clearing session
    log_action(AuditAction.LOGOUT)

    session.pop('admin_user', None)
    logger.info(f"Admin logged out: {admin_email}")
    return jsonify({'success': True}), 200

@app.route('/api/admin/me', methods=['GET'])
@require_admin_login
def admin_me():
    """Get current admin user"""
    return jsonify(session['admin_user']), 200


# ====================================================================================
# B2B AUTHORIZATION DASHBOARD ROUTES
# ====================================================================================
# USER MANAGEMENT ROUTES (Admin Only)
# ====================================================================================

@app.route('/dashboard/users')
@require_admin_login
def users_management_page():
    """Render user management dashboard"""
    log_action('view_user_management_page')
    return render_template('admin_users.html')


@app.route('/api/admin/users', methods=['GET'])
@require_admin_login
def list_users():
    """
    List all users with their permissions
    Returns all users (active and inactive)
    """
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()

            cur.execute("""
                SELECT
                    user_id,
                    email,
                    full_name,
                    is_active,
                    created_at,
                    created_by,
                    last_login_at,
                    can_view_roles,
                    can_view_jds,
                    can_generate_questions,
                    can_view_analytics,
                    can_export_data
                FROM users
                ORDER BY created_at DESC
            """)

            users = []
            for row in cur.fetchall():
                users.append({
                    'user_id': row[0],
                    'email': row[1],
                    'full_name': row[2],
                    'is_active': row[3],
                    'created_at': row[4].isoformat() if row[4] else None,
                    'created_by': row[5],
                    'last_login_at': row[6].isoformat() if row[6] else None,
                    'permissions': {
                        'can_view_roles': row[7],
                        'can_view_jds': row[8],
                        'can_generate_questions': row[9],
                        'can_view_analytics': row[10],
                        'can_export_data': row[11]
                    }
                })

            log_action('list_users', details={'count': len(users)})

            return jsonify({
                'success': True,
                'users': users,
                'total': len(users)
            }), 200

    except Exception as e:
        logger.error(f"Failed to list users: {e}", exc_info=True)
        return error_response('Failed to retrieve users', 500)


@app.route('/api/admin/users', methods=['POST'])
@require_admin_login
def create_user():
    """
    Create new user
    Request body: { email, password, full_name, permissions }
    """
    try:
        data = request.json
        if not data:
            return error_response('Request body is required', 400)

        # Validate required fields
        email = data.get('email', '').strip().lower()
        password = data.get('password', '').strip()
        full_name = data.get('full_name', '').strip()

        if not email or not password or not full_name:
            return error_response('Email, password, and full name are required', 400)

        # Validate email format
        import re
        if not re.match(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$', email):
            return error_response('Invalid email format', 400)

        # Validate password strength
        if len(password) < 8:
            return error_response('Password must be at least 8 characters', 400)

        # Get permissions (default all to False except basic viewing)
        permissions = data.get('permissions', {})
        can_view_roles = permissions.get('can_view_roles', True)
        can_view_jds = permissions.get('can_view_jds', True)
        can_generate_questions = permissions.get('can_generate_questions', False)
        can_view_analytics = permissions.get('can_view_analytics', False)
        can_export_data = permissions.get('can_export_data', False)

        # Hash password
        import bcrypt
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Get admin email
        admin_email = session['admin_user']['email']

        with get_db_connection() as conn:
            cur = conn.cursor()

            # Check if user already exists
            cur.execute("SELECT user_id FROM users WHERE email = %s", (email,))
            if cur.fetchone():
                return error_response('User with this email already exists', 409)

            # Create user
            cur.execute("""
                INSERT INTO users (
                    email, password_hash, full_name, created_by,
                    can_view_roles, can_view_jds, can_generate_questions,
                    can_view_analytics, can_export_data
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING user_id
            """, (
                email, password_hash, full_name, admin_email,
                can_view_roles, can_view_jds, can_generate_questions,
                can_view_analytics, can_export_data
            ))

            user_id = cur.fetchone()[0]
            conn.commit()

            # Log user creation
            log_action(
                AuditAction.CREATE_USER,
                ResourceType.USER,
                str(user_id),
                {
                    'email': email,
                    'full_name': full_name,
                    'permissions': {
                        'can_view_roles': can_view_roles,
                        'can_view_jds': can_view_jds,
                        'can_generate_questions': can_generate_questions,
                        'can_view_analytics': can_view_analytics,
                        'can_export_data': can_export_data
                    }
                }
            )

            logger.info(f"User created: {email} by {admin_email}")

            return jsonify({
                'success': True,
                'user_id': user_id,
                'message': f'User {email} created successfully'
            }), 201

    except Exception as e:
        logger.error(f"Failed to create user: {e}", exc_info=True)
        return error_response('Failed to create user', 500)


@app.route('/api/admin/users/<int:user_id>', methods=['PUT'])
@require_admin_login
def update_user_permissions(user_id):
    """
    Update user details (permissions, email, full_name, or password)
    Request body: { permissions } or { email, full_name } or { password }
    """
    try:
        data = request.json
        if not data:
            return error_response('Request body is required', 400)

        # Get current user state
        with get_db_connection() as conn:
            cur = conn.cursor()

            # Get current user
            cur.execute("""
                SELECT email, full_name, can_view_roles, can_view_jds, can_generate_questions,
                       can_view_analytics, can_export_data
                FROM users
                WHERE user_id = %s
            """, (user_id,))

            user = cur.fetchone()
            if not user:
                return error_response('User not found', 404)

            old_email, old_full_name, old_view_roles, old_view_jds, old_gen_questions, old_view_analytics, old_export = user

            changes = {}
            update_message = ''

            # Handle password reset
            if 'password' in data:
                new_password = data.get('password', '').strip()

                if len(new_password) < 8:
                    return error_response('Password must be at least 8 characters', 400)

                # Hash the new password
                password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

                cur.execute("""
                    UPDATE users
                    SET password_hash = %s
                    WHERE user_id = %s
                """, (password_hash, user_id))

                changes['password'] = 'reset'
                update_message = f'Password reset for {old_email}'

                # Log password reset
                log_action(
                    AuditAction.UPDATE_USER_PERMISSIONS,
                    ResourceType.USER,
                    str(user_id),
                    {'email': old_email, 'action': 'password_reset'}
                )

            # Handle email/full_name update
            elif 'email' in data or 'full_name' in data:
                new_email = data.get('email', old_email).strip()
                new_full_name = data.get('full_name', old_full_name).strip()

                if not new_email or not new_full_name:
                    return error_response('Email and full name are required', 400)

                # Check if new email is already taken by another user
                if new_email != old_email:
                    cur.execute("""
                        SELECT user_id FROM users WHERE email = %s AND user_id != %s
                    """, (new_email, user_id))
                    if cur.fetchone():
                        return error_response('Email already in use', 409)

                cur.execute("""
                    UPDATE users
                    SET email = %s, full_name = %s
                    WHERE user_id = %s
                """, (new_email, new_full_name, user_id))

                if new_email != old_email:
                    changes['email'] = {'old': old_email, 'new': new_email}
                if new_full_name != old_full_name:
                    changes['full_name'] = {'old': old_full_name, 'new': new_full_name}

                update_message = f'User details updated for {new_email}'

                # Log user detail changes
                log_action(
                    AuditAction.UPDATE_USER_PERMISSIONS,
                    ResourceType.USER,
                    str(user_id),
                    {'old_email': old_email, 'new_email': new_email, 'changes': changes}
                )

            # Handle permissions update
            elif 'permissions' in data:
                permissions = data.get('permissions', {})

                # Get new permission values (use existing if not provided)
                can_view_roles = permissions.get('can_view_roles', old_view_roles)
                can_view_jds = permissions.get('can_view_jds', old_view_jds)
                can_generate_questions = permissions.get('can_generate_questions', old_gen_questions)
                can_view_analytics = permissions.get('can_view_analytics', old_view_analytics)
                can_export_data = permissions.get('can_export_data', old_export)

                # Update permissions
                cur.execute("""
                    UPDATE users
                    SET can_view_roles = %s,
                        can_view_jds = %s,
                        can_generate_questions = %s,
                        can_view_analytics = %s,
                        can_export_data = %s
                    WHERE user_id = %s
                """, (
                    can_view_roles, can_view_jds, can_generate_questions,
                    can_view_analytics, can_export_data, user_id
                ))

                # Track changes for audit log
                if can_view_roles != old_view_roles:
                    changes['can_view_roles'] = {'old': old_view_roles, 'new': can_view_roles}
                if can_view_jds != old_view_jds:
                    changes['can_view_jds'] = {'old': old_view_jds, 'new': can_view_jds}
                if can_generate_questions != old_gen_questions:
                    changes['can_generate_questions'] = {'old': old_gen_questions, 'new': can_generate_questions}
                if can_view_analytics != old_view_analytics:
                    changes['can_view_analytics'] = {'old': old_view_analytics, 'new': can_view_analytics}
                if can_export_data != old_export:
                    changes['can_export_data'] = {'old': old_export, 'new': can_export_data}

                update_message = f'Permissions updated for {old_email}'

                # Log permission changes
                log_action(
                    AuditAction.UPDATE_USER_PERMISSIONS,
                    ResourceType.USER,
                    str(user_id),
                    {'email': old_email, 'changes': changes}
                )

            else:
                return error_response('No valid update fields provided', 400)

            conn.commit()

            logger.info(f"User {old_email} updated by {session['admin_user']['email']}: {changes}")

            return jsonify({
                'success': True,
                'message': update_message,
                'changes': changes
            }), 200

    except Exception as e:
        logger.error(f"Failed to update user: {e}", exc_info=True)
        return error_response('Failed to update user', 500)


@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@require_admin_login
def deactivate_user(user_id):
    """
    Deactivate user (soft delete)
    Sets is_active = FALSE
    """
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()

            # Get user email
            cur.execute("SELECT email, is_active FROM users WHERE user_id = %s", (user_id,))
            user = cur.fetchone()

            if not user:
                return error_response('User not found', 404)

            email, is_active = user

            if not is_active:
                return error_response('User is already deactivated', 400)

            # Deactivate user
            cur.execute("""
                UPDATE users
                SET is_active = FALSE
                WHERE user_id = %s
            """, (user_id,))

            conn.commit()

            # Log deactivation
            log_action(
                AuditAction.DELETE_USER,
                ResourceType.USER,
                str(user_id),
                {'email': email, 'action': 'deactivated'}
            )

            logger.info(f"User deactivated: {email} by {session['admin_user']['email']}")

            return jsonify({
                'success': True,
                'message': f'User {email} deactivated successfully'
            }), 200

    except Exception as e:
        logger.error(f"Failed to deactivate user: {e}", exc_info=True)
        return error_response('Failed to deactivate user', 500)


# ====================================================================================
# AUDIT LOG ROUTES (Admin Only)
# ====================================================================================

@app.route('/dashboard/audit-log')
@require_admin_login
def audit_log_page():
    """Render audit log viewer dashboard"""
    log_action(AuditAction.VIEW_AUDIT_LOG)
    return render_template('admin_audit_log.html')


@app.route('/api/admin/audit-log', methods=['GET'])
@require_admin_login
def get_audit_log():
    """
    Query audit logs with filters

    Query Parameters:
        - user_email: Filter by user email
        - action: Filter by action type
        - start_date: Filter by start date (ISO format)
        - end_date: Filter by end date (ISO format)
        - page: Page number (default 1)
        - page_size: Results per page (default 50, max 200)
    """
    try:
        # Get filter parameters
        user_email = request.args.get('user_email', '').strip()
        action = request.args.get('action', '').strip()
        start_date = request.args.get('start_date', '').strip()
        end_date = request.args.get('end_date', '').strip()

        # Get pagination parameters
        try:
            page = int(request.args.get('page', 1))
            page_size = min(int(request.args.get('page_size', 50)), 200)
        except (ValueError, TypeError):
            page = 1
            page_size = 50

        if page < 1:
            page = 1
        if page_size < 1:
            page_size = 50

        offset = (page - 1) * page_size

        # Build query
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

        # Add filters
        if user_email:
            query += " AND user_email ILIKE %s"
            params.append(f'%{user_email}%')

        if action:
            query += " AND action = %s"
            params.append(action)

        if start_date:
            try:
                from datetime import datetime
                start = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
                query += " AND created_at >= %s"
                params.append(start)
            except:
                pass

        if end_date:
            try:
                from datetime import datetime
                end = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                query += " AND created_at <= %s"
                params.append(end)
            except:
                pass

        # Order by most recent first
        query += " ORDER BY created_at DESC"

        # Get total count (before pagination)
        count_query = f"SELECT COUNT(*) FROM ({query}) AS count_query"

        with get_db_connection() as conn:
            cur = conn.cursor()

            # Get total count
            cur.execute(count_query, params)
            total = cur.fetchone()[0]

            # Add pagination
            query += " LIMIT %s OFFSET %s"
            params.extend([page_size, offset])

            # Execute query
            cur.execute(query, params)

            logs = []
            for row in cur.fetchall():
                logs.append({
                    'log_id': row[0],
                    'user_email': row[1],
                    'user_type': row[2],
                    'action': row[3],
                    'resource_type': row[4],
                    'resource_id': row[5],
                    'details': row[6],  # Already JSON
                    'ip_address': row[7],
                    'user_agent': row[8],
                    'created_at': row[9].isoformat() if row[9] else None
                })

            return jsonify({
                'success': True,
                'logs': logs,
                'pagination': {
                    'page': page,
                    'page_size': page_size,
                    'total': total,
                    'total_pages': (total + page_size - 1) // page_size
                }
            }), 200

    except Exception as e:
        logger.error(f"Failed to query audit log: {e}", exc_info=True)
        return error_response('Failed to retrieve audit logs', 500)


@app.route('/api/admin/audit-log/export', methods=['GET'])
@require_admin_login
def export_audit_log():
    """
    Export audit logs to CSV
    Uses same filters as get_audit_log
    """
    try:
        import csv
        from io import StringIO

        # Get filter parameters (same as get_audit_log)
        user_email = request.args.get('user_email', '').strip()
        action = request.args.get('action', '').strip()
        start_date = request.args.get('start_date', '').strip()
        end_date = request.args.get('end_date', '').strip()

        # Build query (no pagination for export)
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

        # Add filters
        if user_email:
            query += " AND user_email ILIKE %s"
            params.append(f'%{user_email}%')

        if action:
            query += " AND action = %s"
            params.append(action)

        if start_date:
            try:
                from datetime import datetime
                start = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
                query += " AND created_at >= %s"
                params.append(start)
            except:
                pass

        if end_date:
            try:
                from datetime import datetime
                end = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                query += " AND created_at <= %s"
                params.append(end)
            except:
                pass

        query += " ORDER BY created_at DESC"

        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute(query, params)

            # Create CSV
            output = StringIO()
            writer = csv.writer(output)

            # Write header
            writer.writerow([
                'Log ID', 'User Email', 'User Type', 'Action',
                'Resource Type', 'Resource ID', 'Details',
                'IP Address', 'User Agent', 'Timestamp'
            ])

            # Write rows
            for row in cur.fetchall():
                writer.writerow([
                    row[0],  # log_id
                    row[1],  # user_email
                    row[2],  # user_type
                    row[3],  # action
                    row[4],  # resource_type
                    row[5],  # resource_id
                    json.dumps(row[6]) if row[6] else '',  # details
                    row[7],  # ip_address
                    row[8],  # user_agent
                    row[9].isoformat() if row[9] else ''  # created_at
                ])

            # Log export action
            log_action(AuditAction.EXPORT_AUDIT_LOG, details={'format': 'csv'})

            # Return CSV
            from flask import make_response
            response = make_response(output.getvalue())
            response.headers['Content-Type'] = 'text/csv'
            response.headers['Content-Disposition'] = f'attachment; filename=audit_log_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'

            return response

    except Exception as e:
        logger.error(f"Failed to export audit log: {e}", exc_info=True)
        return error_response('Failed to export audit logs', 500)


# ====================================================================================
# ADMIN PROFILE & PASSWORD MANAGEMENT
# ====================================================================================

@app.route('/dashboard/profile')
@require_admin_login
def admin_profile_page():
    """Render admin profile page"""
    log_action(AuditAction.VIEW_DASHBOARD, details={'page': 'profile'})
    return render_template('admin_profile.html')

@app.route('/test-modals')
@require_admin_login
def test_modals_page():
    """Test page for debugging modals and API"""
    return render_template('test_modals.html')


@app.route('/api/admin/change-password', methods=['POST'])
@require_admin_login
def change_admin_password():
    """
    Change admin password
    Request body: {
        "current_password": "...",
        "new_password": "...",
        "confirm_password": "..."
    }
    """
    try:
        data = request.json
        if not data:
            return error_response('Request body is required', 400)

        current_password = data.get('current_password', '').strip()
        new_password = data.get('new_password', '').strip()
        confirm_password = data.get('confirm_password', '').strip()

        # Validation
        if not current_password:
            return error_response('Current password is required', 400)

        if not new_password:
            return error_response('New password is required', 400)

        if len(new_password) < 8:
            return error_response('New password must be at least 8 characters', 400)

        if new_password != confirm_password:
            return error_response('New passwords do not match', 400)

        if current_password == new_password:
            return error_response('New password must be different from current password', 400)

        # Get admin from session
        admin_user = session.get('admin_user')
        admin_email = admin_user['email']

        with get_db_connection() as conn:
            cur = conn.cursor()

            # Get current password hash
            cur.execute("""
                SELECT password_hash FROM admin_users
                WHERE email = %s AND is_active = TRUE
            """, (admin_email,))

            result = cur.fetchone()
            if not result:
                return error_response('Admin user not found', 404)

            current_hash = result[0]

            # Verify current password
            if not verify_password(current_password, current_hash):
                log_action(
                    AuditAction.CHANGE_PASSWORD,
                    ResourceType.ADMIN,
                    details={'status': 'failed', 'reason': 'incorrect_current_password'}
                )
                return error_response('Current password is incorrect', 401)

            # Hash new password
            new_hash = hash_password(new_password)

            # Update password
            cur.execute("""
                UPDATE admin_users
                SET password_hash = %s
                WHERE email = %s
            """, (new_hash, admin_email))

            conn.commit()

            # Log success
            log_action(
                AuditAction.CHANGE_PASSWORD,
                ResourceType.ADMIN,
                details={'status': 'success', 'admin_email': admin_email}
            )

            logger.info(f"Password changed successfully for admin: {admin_email}")

            return jsonify({
                'success': True,
                'message': 'Password changed successfully'
            }), 200

    except Exception as e:
        logger.error(f"Failed to change password: {e}", exc_info=True)
        return error_response('Failed to change password', 500)


# ====================================================================================
# B2B AUTHORIZATION ROUTES (Admin Only)
# ====================================================================================

@app.route('/dashboard/b2b-authorizations')
@require_admin_login
def b2b_authorizations_page():
    """Render B2B authorization dashboard"""
    return render_template('b2b_authorizations.html')

@app.route('/api/dashboard/b2b-requests', methods=['GET'])
@require_admin_login
def list_b2b_requests():
    """List B2B authorization requests with optional filter"""
    try:
        status_filter = svc_normalize_b2b_status_filter(request.args.get('status', 'pending'))

        with get_db_connection() as conn:
            requests = svc_list_b2b_authorization_requests(
                conn,
                status_filter=status_filter,
                limit=100,
            )

            # Convert datetime objects to ISO format
            for req in requests:
                for key in ['requested_at', 'reviewed_at', 'processing_started_at', 'processing_completed_at']:
                    if req.get(key):
                        req[key] = req[key].isoformat()

            return jsonify({
                'count': len(requests),
                'requests': requests
            }), 200

    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Error listing B2B requests: {e}", exc_info=True)
        return error_response('Internal server error', 500)

@app.route('/api/dashboard/b2b-requests/<int:request_id>/approve', methods=['POST'])
@require_admin_login
@validate_path_param('request_id', lambda x: is_safe_integer(x, 1, 1000000))
@validate_request(ApprovalRequest)
def approve_b2b_request(request_id):
    """
    Approve B2B authorization request
    Kicks off async processing in background thread
    """
    try:
        admin_email = session['admin_user']['email']
        validated = request.validated_data
        notes = validated.notes

        # Update status + write audit log atomically
        with get_transaction(ISOLATION_LEVEL_READ_COMMITTED) as conn:
            req = svc_approve_b2b_authorization_request(
                conn,
                request_id=request_id,
                admin_email=admin_email,
                notes=notes,
            )

            if not req:
                return error_response('Request not found or already processed', 404)

        # Start async processing in background thread
        import threading
        thread = threading.Thread(
            target=process_b2b_authorization_async,
            args=(request_id, req['company_name'], req['base_role_id'], req['custom_jd_data'])
        )
        thread.daemon = True
        thread.start()

        logger.info(f"[OK] B2B request #{request_id} approved by {admin_email}. Processing in background...")

        return jsonify({
            'success': True,
            'message': 'Request approved! Processing in background...',
            'request_id': request_id
        }), 200

    except Exception as e:
        logger.error(f"Error approving B2B request: {e}", exc_info=True)
        return error_response('Internal server error', 500)

@app.route('/api/dashboard/b2b-requests/<int:request_id>/deny', methods=['POST'])
@require_admin_login
@validate_path_param('request_id', lambda x: is_safe_integer(x, 1, 1000000))
@validate_request(DenialRequest)
def deny_b2b_request(request_id):
    """Deny B2B authorization request"""
    try:
        admin_email = session['admin_user']['email']
        validated = request.validated_data
        reason = validated.reason

        # Update status + write audit log atomically
        with get_transaction(ISOLATION_LEVEL_READ_COMMITTED) as conn:
            req = svc_deny_b2b_authorization_request(
                conn,
                request_id=request_id,
                admin_email=admin_email,
                reason=reason,
            )

            if not req:
                return error_response('Request not found or already processed', 404)

        logger.info(f"[OK] B2B request #{request_id} denied by {admin_email}")

        return jsonify({
            'success': True,
            'message': 'Request denied',
            'request_id': request_id
        }), 200

    except Exception as e:
        logger.error(f"Error denying B2B request: {e}", exc_info=True)
        return error_response('Internal server error', 500)


# ====================================================================================
# ASYNC PROCESSING FUNCTION
# ====================================================================================

def process_b2b_authorization_async(request_id, company_name, base_role_id, custom_jd_data):
    """
    Background thread function to process B2B request after approval
    This may take 30 seconds to 5 minutes depending on AI agent speed
    """
    from agents.b2b_interview_preparation import B2BInterviewPreparationAgent

    logger.info(f"[PROCESSING] Background processing started for B2B request #{request_id}")

    try:
        # Initialize B2B agent
        b2b_agent = B2BInterviewPreparationAgent(DB_CONFIG)

        # Branch based on whether custom JD was provided
        # Note: custom_jd_data always has metadata (requested_job_title, resolved_role_title, etc.)
        # so we check for actual JD content like 'responsibilities' to distinguish full JD vs title-only
        has_actual_jd = custom_jd_data and any(
            k in custom_jd_data for k in ('responsibilities', 'requirements', 'certifications', 'department')
        )
        if has_actual_jd:
            # Full path: map JD, compare, extract keywords, select questions
            result = b2b_agent.prepare_interview(
                company_name=company_name,
                base_role_id=base_role_id,
                custom_jd=custom_jd_data
            )
        else:
            # Title-only path: skip JD processing, select questions randomly
            result = b2b_agent.prepare_interview_random(
                company_name=company_name,
                base_role_id=base_role_id
            )

        # Store results in database using explicit transaction (atomic update + audit)
        with get_transaction(ISOLATION_LEVEL_READ_COMMITTED) as conn:
            svc_complete_b2b_authorization_processing(
                conn,
                request_id=request_id,
                result=result,
            )

        logger.info(f"[OK] Background processing completed for B2B request #{request_id}")
        logger.info(f"   Questions generated: {len(result.get('questions', []))}")

    except Exception as e:
        logger.error(f"[FAIL] Background processing failed for B2B request #{request_id}: {e}", exc_info=True)

        # Update status to failed using explicit transaction (atomic update + audit)
        try:
            with get_transaction(ISOLATION_LEVEL_READ_COMMITTED) as conn:
                svc_fail_b2b_authorization_processing(
                    conn,
                    request_id=request_id,
                    error_message=str(e),
                )
        except Exception as e2:
            logger.error(f"Failed to update failed status: {e2}")


# ====================================================================================
# DASHBOARD - ACCESS REQUESTS (Agent Access Management)
# ====================================================================================

@app.route('/api/dashboard/access-requests', methods=['GET'])
@require_admin_login
def dashboard_get_access_requests():
    """
    Get agent access requests for dashboard (session auth)
    Separate from /api/access-requests which uses API key auth
    """
    try:
        status_filter = request.args.get('status', '').upper()
        if status_filter and status_filter != 'ALL' and status_filter not in VALID_ACCESS_STATUSES:
            return error_response('Invalid status filter', 400)

        effective_status = None if not status_filter or status_filter == 'ALL' else status_filter

        with get_db_connection() as conn:
            requests_data = svc_list_access_requests(
                conn,
                status_filter=effective_status,
                include_hours_waiting=True,
                limit=100,
            )

            # Convert datetime objects to ISO format
            for req in requests_data:
                for key in ['requested_at', 'reviewed_at', 'access_expires_at']:
                    if req.get(key):
                        req[key] = req[key].isoformat()

            return jsonify({
                'count': len(requests_data),
                'requests': requests_data
            }), 200

    except Exception as e:
        logger.error(f"Error loading access requests: {e}", exc_info=True)
        return error_response('Internal server error', 500)


@app.route('/api/dashboard/access-requests/<int:request_id>/approve', methods=['POST'])
@require_admin_login
def dashboard_approve_access_request(request_id):
    """Approve agent access request (dashboard version)"""
    try:
        admin_email = session['admin_user']['email']
        data = request.json or {}

        duration_hours = int(data.get('duration_hours', 24))
        review_notes = data.get('notes', 'Approved').strip()
        reviewed_by = data.get('reviewed_by', admin_email).strip()

        # Validate duration (1-168 hours = 1 week max)
        if duration_hours <= 0 or duration_hours > 168:
            return error_response('Duration must be between 1 and 168 hours', 400)

        with get_db_connection() as conn:
            result = svc_approve_access_request(
                conn,
                request_id=request_id,
                reviewed_by=reviewed_by,
                review_notes=review_notes,
                duration_hours=duration_hours,
                reset_times_used=True,
            )

            if not result:
                return error_response('Request not found or already processed', 404)

            logger.info(f"[OK] Access request #{request_id} approved by {admin_email}")

            return jsonify({
                'success': True,
                'message': f'Request approved for {duration_hours} hours',
                'request_id': request_id
            }), 200

    except Exception as e:
        logger.error(f"Error approving access request: {e}", exc_info=True)
        return error_response('Internal server error', 500)


@app.route('/api/dashboard/access-requests/<int:request_id>/deny', methods=['POST'])
@require_admin_login
def dashboard_deny_access_request(request_id):
    """Deny agent access request (dashboard version)"""
    try:
        admin_email = session['admin_user']['email']
        data = request.json or {}
        reason = data.get('reason', 'Denied').strip()

        with get_db_connection() as conn:
            result = svc_deny_access_request(
                conn,
                request_id=request_id,
                reviewed_by=admin_email,
                reason=reason,
            )

            if not result:
                return error_response('Request not found or already processed', 404)

            logger.info(f"[OK] Access request #{request_id} denied by {admin_email}")

            return jsonify({
                'success': True,
                'message': 'Request denied',
                'request_id': request_id
            }), 200

    except Exception as e:
        logger.error(f"Error denying access request: {e}", exc_info=True)
        return error_response('Internal server error', 500)


@app.route('/api/dashboard/access-requests/<int:request_id>/revoke', methods=['POST'])
@require_admin_login
def dashboard_revoke_access_request(request_id):
    """Revoke agent access request (dashboard version)"""
    try:
        admin_email = session['admin_user']['email']
        data = request.json or {}
        reason = data.get('reason', 'Revoked').strip()

        with get_db_connection() as conn:
            result = svc_revoke_access_request(
                conn,
                request_id=request_id,
                reason=reason,
                reviewed_by=admin_email,
            )

            if not result:
                return error_response('Request not found or not approved', 404)

            logger.info(f"[OK] Access request #{request_id} revoked by {admin_email}")

            return jsonify({
                'success': True,
                'message': 'Access revoked',
                'request_id': request_id
            }), 200

    except Exception as e:
        logger.error(f"Error revoking access request: {e}", exc_info=True)
        return error_response('Internal server error', 500)


@app.route('/api/dashboard/access-requests/<int:request_id>/resubmit', methods=['POST'])
@require_admin_login
def dashboard_resubmit_access_request(request_id):
    """Re-submit a denied/revoked/expired access request (dashboard version)"""
    try:
        with get_db_connection() as conn:
            result = svc_resubmit_access_request(conn, request_id=request_id)

            if not result:
                return error_response('Request not found or cannot be resubmitted', 404)

            logger.info(f"[OK] Access request #{request_id} resubmitted")

            return jsonify({
                'success': True,
                'message': 'Request moved to pending',
                'request_id': request_id
            }), 200

    except Exception as e:
        logger.error(f"Error resubmitting access request: {e}", exc_info=True)
        return error_response('Internal server error', 500)


# ============================================================================
# SHUTDOWN HANDLER
# ============================================================================

def shutdown_handler(signum, frame):
    """Clean shutdown on SIGTERM/SIGINT"""
    logger.info("Shutting down gracefully...")
    if connection_pool:
        connection_pool.closeall()
    sys.exit(0)


signal.signal(signal.SIGTERM, shutdown_handler)
signal.signal(signal.SIGINT, shutdown_handler)


# ============================================================================
# RUN APPLICATION
# ============================================================================

if __name__ == '__main__':
    logger.info("=" * 60)
    logger.info("Assessment Operations Platform showcase starting")
    logger.info("Private integrations and customer data are intentionally omitted")
    logger.info("=" * 60)
    
    # FIX BUG #4: Never run debug=True on 0.0.0.0 - exposes interactive debugger (RCE)
    debug_mode = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    host = '127.0.0.1' if debug_mode else '0.0.0.0'
    
    app.run(
        host=host,
        port=5000,
        debug=debug_mode,
        use_reloader=debug_mode,
        extra_files=[]
    )

