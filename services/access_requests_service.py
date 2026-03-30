"""
Access request service operations.

Keeps SQL/business operations out of route handlers so app.py can stay focused on
request parsing, auth, and response formatting.
"""

from typing import Any, Dict, List, Optional

from psycopg2.extras import RealDictCursor


VALID_ACCESS_STATUSES = ["PENDING", "APPROVED", "DENIED", "REVOKED", "EXPIRED"]


def validate_access_status(status: str) -> str:
    """Validate and normalize an access request status."""
    normalized = (status or "").strip().upper()
    if normalized and normalized not in VALID_ACCESS_STATUSES:
        raise ValueError(f"Invalid status: {normalized}")
    return normalized


def list_access_requests(
    conn,
    status_filter: Optional[str] = None,
    include_hours_waiting: bool = False,
    limit: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """
    List access requests with optional status filter and dashboard-only fields.
    """
    params: List[Any] = []

    if include_hours_waiting:
        select_clause = """
            SELECT
                request_id,
                agent_id,
                request_type,
                purpose,
                scope,
                status,
                requested_at,
                reviewed_by,
                reviewed_at,
                review_notes,
                access_expires_at,
                times_used,
                EXTRACT(EPOCH FROM (NOW() - requested_at)) / 3600.0 AS hours_waiting
            FROM agent_access_requests
        """
    else:
        select_clause = "SELECT * FROM agent_access_requests"

    query = [select_clause]

    if status_filter:
        query.append("WHERE status = %s")
        params.append(status_filter)

    query.append("ORDER BY requested_at DESC")

    if limit is not None:
        query.append("LIMIT %s")
        params.append(int(limit))

    sql = "\n".join(query)

    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, tuple(params))
        return cur.fetchall()


def approve_access_request(
    conn,
    request_id: int,
    reviewed_by: str,
    review_notes: str,
    duration_hours: int,
    reset_times_used: bool = False,
) -> Optional[Dict[str, Any]]:
    """Approve a pending access request and set an expiry window."""
    set_parts = [
        "status = 'APPROVED'",
        "reviewed_by = %s",
        "reviewed_at = NOW()",
        "review_notes = %s",
        "access_granted_at = NOW()",
        "access_expires_at = NOW() + make_interval(hours => %s)",
    ]

    if reset_times_used:
        set_parts.append("times_used = 0")

    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            f"""
                UPDATE agent_access_requests
                SET
                    {", ".join(set_parts)}
                WHERE request_id = %s
                    AND status = 'PENDING'
                RETURNING *
            """,
            (reviewed_by, review_notes, duration_hours, request_id),
        )
        return cur.fetchone()


def deny_access_request(
    conn,
    request_id: int,
    reviewed_by: str,
    reason: str,
) -> Optional[Dict[str, Any]]:
    """Deny a pending access request."""
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
                UPDATE agent_access_requests
                SET
                    status = 'DENIED',
                    reviewed_by = %s,
                    reviewed_at = NOW(),
                    review_notes = %s
                WHERE request_id = %s
                    AND status = 'PENDING'
                RETURNING *
            """,
            (reviewed_by, reason, request_id),
        )
        return cur.fetchone()


def revoke_access_request(
    conn,
    request_id: int,
    reason: str,
    reviewed_by: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Revoke an approved access request."""
    if reviewed_by:
        sql = """
            UPDATE agent_access_requests
            SET
                status = 'REVOKED',
                reviewed_by = %s,
                reviewed_at = NOW(),
                review_notes = %s
            WHERE request_id = %s
                AND status = 'APPROVED'
            RETURNING *
        """
        params = (reviewed_by, reason, request_id)
    else:
        sql = """
            UPDATE agent_access_requests
            SET
                status = 'REVOKED',
                review_notes = %s
            WHERE request_id = %s
                AND status = 'APPROVED'
            RETURNING *
        """
        params = (reason, request_id)

    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, params)
        return cur.fetchone()


def resubmit_access_request(conn, request_id: int) -> Optional[Dict[str, Any]]:
    """Move a terminal request back to pending for re-review."""
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
                UPDATE agent_access_requests
                SET
                    status = 'PENDING',
                    reviewed_by = NULL,
                    reviewed_at = NULL,
                    review_notes = NULL,
                    access_expires_at = NULL
                WHERE request_id = %s
                    AND status IN ('DENIED', 'REVOKED', 'EXPIRED')
                RETURNING *
            """,
            (request_id,),
        )
        return cur.fetchone()
