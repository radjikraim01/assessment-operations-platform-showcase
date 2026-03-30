"""
B2B authorization service operations.

Encapsulates dashboard-related SQL and transaction-safe operations so route
handlers stay focused on request/response concerns.
"""

from typing import Any, Dict, Optional

from psycopg2.extras import Json, RealDictCursor


VALID_B2B_REQUEST_STATUSES = {
    "pending",
    "approved_processing",
    "approved_ready",
    "denied",
    "failed",
}


def normalize_b2b_status_filter(raw_status: Optional[str]) -> Optional[str]:
    """
    Normalize the dashboard status filter.

    Returns:
    - None for "all" (no filter)
    - normalized status string for supported statuses
    Raises ValueError for unsupported values.
    """
    status = (raw_status or "pending").strip().lower()
    if not status or status == "all":
        return None
    if status not in VALID_B2B_REQUEST_STATUSES:
        raise ValueError(f"Invalid B2B status: {status}")
    return status


def list_b2b_authorization_requests(
    conn,
    status_filter: Optional[str] = None,
    limit: int = 100,
):
    """Fetch B2B authorization requests for dashboard display."""
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        if status_filter is None:
            cur.execute(
                """
                    SELECT *
                    FROM b2b_authorization_requests
                    ORDER BY requested_at DESC
                    LIMIT %s
                """,
                (limit,),
            )
        else:
            cur.execute(
                """
                    SELECT *
                    FROM b2b_authorization_requests
                    WHERE status = %s
                    ORDER BY requested_at DESC
                    LIMIT %s
                """,
                (status_filter, limit),
            )
        return cur.fetchall()


def approve_b2b_authorization_request(
    conn,
    request_id: int,
    admin_email: str,
    notes: str,
) -> Optional[Dict[str, Any]]:
    """
    Approve a pending B2B request and append an audit row.
    Must be called inside a transaction.
    """
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
                UPDATE b2b_authorization_requests
                SET status = 'approved_processing',
                    reviewed_by = %s,
                    reviewed_at = NOW(),
                    review_notes = %s,
                    processing_started_at = NOW()
                WHERE request_id = %s
                    AND status = 'pending'
                RETURNING company_name, base_role_id, custom_jd_data
            """,
            (admin_email, notes, request_id),
        )
        req = cur.fetchone()
        if not req:
            return None

        cur.execute(
            """
                INSERT INTO b2b_audit_log (request_id, event_type, admin_email, event_details)
                VALUES (%s, %s, %s, %s)
            """,
            (request_id, "approved", admin_email, Json({"notes": notes})),
        )
        return req


def deny_b2b_authorization_request(
    conn,
    request_id: int,
    admin_email: str,
    reason: str,
) -> Optional[Dict[str, Any]]:
    """
    Deny a pending B2B request and append an audit row.
    Must be called inside a transaction.
    """
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
                UPDATE b2b_authorization_requests
                SET status = 'denied',
                    reviewed_by = %s,
                    reviewed_at = NOW(),
                    review_notes = %s
                WHERE request_id = %s
                    AND status = 'pending'
                RETURNING company_name
            """,
            (admin_email, reason, request_id),
        )
        req = cur.fetchone()
        if not req:
            return None

        cur.execute(
            """
                INSERT INTO b2b_audit_log (request_id, event_type, admin_email, event_details)
                VALUES (%s, %s, %s, %s)
            """,
            (request_id, "denied", admin_email, Json({"reason": reason})),
        )
        return req


def complete_b2b_authorization_processing(
    conn,
    request_id: int,
    result: Dict[str, Any],
) -> None:
    """
    Persist successful background processing output and audit record.
    Must be called inside a transaction.
    """
    questions = result.get("questions", [])
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
                UPDATE b2b_authorization_requests
                SET status = 'approved_ready',
                    custom_jd_id = %s,
                    custom_role_id = %s,
                    comparison_id = %s,
                    questions = %s,
                    processing_completed_at = NOW()
                WHERE request_id = %s
            """,
            (
                result.get("custom_jd_id"),
                result.get("custom_role_id"),
                result.get("comparison_id"),
                Json(questions),
                request_id,
            ),
        )
        cur.execute(
            """
                INSERT INTO b2b_audit_log (request_id, event_type, event_details)
                VALUES (%s, %s, %s)
            """,
            (
                request_id,
                "processing_completed",
                Json(
                    {
                        "questions_count": len(questions),
                        "custom_role_id": result.get("custom_role_id"),
                    }
                ),
            ),
        )


def fail_b2b_authorization_processing(
    conn,
    request_id: int,
    error_message: str,
) -> None:
    """
    Persist background processing failure details and audit record.
    Must be called inside a transaction.
    """
    with conn.cursor() as cur:
        cur.execute(
            """
                UPDATE b2b_authorization_requests
                SET status = 'failed',
                    processing_error = %s,
                    processing_completed_at = NOW()
                WHERE request_id = %s
            """,
            (error_message, request_id),
        )
        cur.execute(
            """
                INSERT INTO b2b_audit_log (request_id, event_type, event_details)
                VALUES (%s, %s, %s)
            """,
            (request_id, "processing_failed", Json({"error": error_message})),
        )
