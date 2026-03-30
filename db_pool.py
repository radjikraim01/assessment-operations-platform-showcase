"""
Database Connection Pool Manager
Centralized connection pooling for all agents and modules
"""

import os
import psycopg2
from psycopg2 import pool
from contextlib import contextmanager
import logging
from typing import Optional, Callable, Any
from psycopg2.extensions import ISOLATION_LEVEL_READ_COMMITTED, ISOLATION_LEVEL_SERIALIZABLE
import time
from functools import wraps

logger = logging.getLogger(__name__)

# Global connection pool instance
_connection_pool: Optional[pool.SimpleConnectionPool] = None


def initialize_pool(min_conn: int = 2, max_conn: int = 20, **db_config):
    """
    Initialize the global connection pool

    Args:
        min_conn: Minimum number of connections to maintain
        max_conn: Maximum number of connections allowed
        **db_config: Database configuration (dbname, user, password, host, port)
    """
    global _connection_pool

    if _connection_pool:
        logger.warning("Connection pool already initialized")
        return

    try:
        _connection_pool = pool.SimpleConnectionPool(
            minconn=min_conn,
            maxconn=max_conn,
            **db_config
        )
        logger.info(f"[OK] Database connection pool initialized (min={min_conn}, max={max_conn})")
    except Exception as e:
        logger.error(f"[FAIL] Failed to initialize connection pool: {e}")
        raise


def get_pool() -> Optional[pool.SimpleConnectionPool]:
    """Get the global connection pool instance"""
    return _connection_pool


@contextmanager
def get_connection():
    """
    Context manager for getting a pooled database connection

    Usage:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT ...")

    Features:
    - Automatic connection acquisition from pool
    - Auto-commit on success
    - Auto-rollback on error
    - Connection health check
    - Automatic return to pool
    """
    conn = None
    try:
        if _connection_pool:
            # Get connection from pool
            conn = _connection_pool.getconn()

            # Health check - ensure connection is alive
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
            except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
                logger.warning(f"Stale connection detected, recycling... ({e})")
                _connection_pool.putconn(conn, close=True)
                conn = _connection_pool.getconn()
        else:
            # Fallback: direct connection if pool not initialized
            logger.warning("Pool not initialized, creating direct connection")
            from dotenv import load_dotenv
            load_dotenv()

            conn = psycopg2.connect(
                dbname=os.environ.get('DB_NAME', 'assessment_platform'),
                user=os.environ.get('DB_USER', 'postgres'),
                password=os.environ['DB_PASSWORD'],
                host=os.environ.get('DB_HOST', 'localhost'),
                port=os.environ.get('DB_PORT', '5432')
            )

        yield conn

        # Auto-commit on success
        conn.commit()

    except Exception as e:
        # Auto-rollback on error
        if conn:
            conn.rollback()
        logger.error(f"Database error: {e}", exc_info=True)
        raise

    finally:
        # Return connection to pool or close if direct
        if conn:
            if _connection_pool:
                _connection_pool.putconn(conn)
            else:
                conn.close()


@contextmanager
def get_transaction(isolation_level=ISOLATION_LEVEL_READ_COMMITTED):
    """
    Context manager for explicit transactions with isolation level control

    Usage:
        with get_transaction(ISOLATION_LEVEL_SERIALIZABLE) as conn:
            with conn.cursor() as cur:
                cur.execute("INSERT ...")
                cur.execute("UPDATE ...")
                # Auto-commit on success, rollback on error

    Args:
        isolation_level: PostgreSQL isolation level
            - ISOLATION_LEVEL_READ_COMMITTED (default) - standard isolation
            - ISOLATION_LEVEL_SERIALIZABLE - strictest isolation

    Features:
    - Explicit BEGIN...COMMIT/ROLLBACK
    - Configurable isolation level
    - Auto-rollback on exceptions
    - Connection pooling
    - Prevents partial commits
    """
    conn = None
    old_autocommit = None
    old_isolation = None

    try:
        if _connection_pool:
            conn = _connection_pool.getconn()

            # Health check
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
                # Clear the implicit transaction started by SELECT 1
                # so we can change session settings below
                conn.rollback()
            except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
                logger.warning(f"Stale connection detected, recycling... ({e})")
                _connection_pool.putconn(conn, close=True)
                conn = _connection_pool.getconn()
        else:
            # Fallback: direct connection
            from dotenv import load_dotenv
            load_dotenv()

            conn = psycopg2.connect(
                dbname=os.environ.get('DB_NAME', 'assessment_platform'),
                user=os.environ.get('DB_USER', 'postgres'),
                password=os.environ['DB_PASSWORD'],
                host=os.environ.get('DB_HOST', 'localhost'),
                port=os.environ.get('DB_PORT', '5432')
            )

        # Disable autocommit and set isolation level
        old_autocommit = conn.autocommit
        old_isolation = conn.isolation_level
        conn.autocommit = False
        conn.set_isolation_level(isolation_level)

        yield conn

        # Commit on success
        conn.commit()
        logger.debug("[OK] Transaction committed")

    except Exception as e:
        # Rollback on error
        if conn:
            conn.rollback()
            logger.warning(f"[WARN] Transaction rolled back: {e}")
        raise

    finally:
        # Restore settings and return connection
        if conn:
            if old_autocommit is not None:
                conn.autocommit = old_autocommit
            if old_isolation is not None:
                conn.set_isolation_level(old_isolation)

            if _connection_pool:
                _connection_pool.putconn(conn)
            else:
                conn.close()


def close_pool():
    """Close all connections in the pool (call on shutdown)"""
    global _connection_pool

    if _connection_pool:
        _connection_pool.closeall()
        _connection_pool = None
        logger.info("[OK] Connection pool closed")


# ============================================================================
# RETRY LOGIC FOR TRANSIENT ERRORS
# ============================================================================

def with_db_retry(max_retries: int = 3, initial_delay: float = 0.5, backoff: float = 2.0):
    """
    Decorator to retry database operations on transient errors

    Retries on:
    - psycopg2.OperationalError (connection issues, timeouts)
    - psycopg2.InterfaceError (connection closed unexpectedly)
    - psycopg2.DatabaseError with specific error codes

    Does NOT retry on:
    - Integrity errors (duplicate keys, foreign key violations)
    - Data errors (invalid input)
    - Programming errors (SQL syntax)

    Args:
        max_retries: Maximum number of retry attempts (default: 3)
        initial_delay: Initial delay in seconds (default: 0.5s)
        backoff: Backoff multiplier (default: 2.0 = exponential)

    Usage:
        @with_db_retry(max_retries=3)
        def my_db_function():
            with get_connection() as conn:
                # ... database operations ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            delay = initial_delay
            last_exception = None

            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)

                except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
                    last_exception = e

                    if attempt < max_retries:
                        logger.warning(
                            f"Database transient error (attempt {attempt + 1}/{max_retries + 1}): {e}. "
                            f"Retrying in {delay:.2f}s..."
                        )
                        time.sleep(delay)
                        delay *= backoff
                    else:
                        logger.error(f"Database operation failed after {max_retries + 1} attempts: {e}")
                        raise

                except psycopg2.DatabaseError as e:
                    # Check if it's a transient error (connection/timeout related)
                    error_msg = str(e).lower()
                    if any(keyword in error_msg for keyword in ['timeout', 'connection', 'reset', 'closed']):
                        last_exception = e

                        if attempt < max_retries:
                            logger.warning(
                                f"Database transient error (attempt {attempt + 1}/{max_retries + 1}): {e}. "
                                f"Retrying in {delay:.2f}s..."
                            )
                            time.sleep(delay)
                            delay *= backoff
                        else:
                            logger.error(f"Database operation failed after {max_retries + 1} attempts: {e}")
                            raise
                    else:
                        # Not a transient error, don't retry
                        raise

            # Should never reach here, but just in case
            raise last_exception

        return wrapper
    return decorator


# ============================================================================
# AUTO-INITIALIZATION
# ============================================================================

# Auto-initialize pool if imported and environment variables available
if __name__ != "__main__":
    try:
        from dotenv import load_dotenv
        load_dotenv()

        # Only auto-initialize if DB_PASSWORD is set
        if 'DB_PASSWORD' in os.environ:
            initialize_pool(
                min_conn=2,
                max_conn=20,
                dbname=os.environ.get('DB_NAME', 'assessment_platform'),
                user=os.environ.get('DB_USER', 'postgres'),
                password=os.environ['DB_PASSWORD'],
                host=os.environ.get('DB_HOST', 'localhost'),
                port=os.environ.get('DB_PORT', '5432'),
                keepalives=1,
                keepalives_idle=300,
                keepalives_interval=30,
                keepalives_count=3,
                connect_timeout=10
            )
    except Exception as e:
        logger.warning(f"Auto-initialization failed: {e}")

