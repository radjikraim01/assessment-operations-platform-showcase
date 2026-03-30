"""
Regression checks for access-request security and SQL interval syntax.

This test is static (source-based) to avoid requiring a running database.
"""

from pathlib import Path
import re
import sys


APP_PATH = Path(__file__).resolve().parent / "app.py"
SERVICE_PATH = Path(__file__).resolve().parent / "services" / "access_requests_service.py"


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def test_interval_operator_fixed(app_source: str, service_source: str) -> None:
    _assert(
        "make_interval(hours := %s)" not in app_source,
        "Unsafe/invalid interval operator ':=' still present in app.py",
    )
    _assert(
        "make_interval(hours := %s)" not in service_source,
        "Unsafe/invalid interval operator ':=' still present in service SQL",
    )
    _assert(
        service_source.count("make_interval(hours => %s)") >= 1,
        "Expected safe make_interval(hours => %s) usage not found in service SQL",
    )


def test_legacy_access_routes_are_admin_guarded(app_source: str) -> None:
    route_patterns = [
        r"@app\.route\('/api/access-requests', methods=\['GET'\]\)\s+@verify_api_key\s+@require_access_request_admin\s+@handle_errors\s+def get_access_requests",
        r"@app\.route\('/api/access-requests/<int:request_id>/approve', methods=\['POST'\]\)\s+@verify_api_key\s+@require_access_request_admin\s+@handle_errors\s+def approve_access_request",
        r"@app\.route\('/api/access-requests/<int:request_id>/deny', methods=\['POST'\]\)\s+@verify_api_key\s+@require_access_request_admin\s+@handle_errors\s+def deny_access_request",
        r"@app\.route\('/api/access-requests/<int:request_id>/revoke', methods=\['POST'\]\)\s+@verify_api_key\s+@require_access_request_admin\s+@handle_errors\s+def revoke_access_request",
    ]

    for pattern in route_patterns:
        _assert(
            re.search(pattern, app_source, flags=re.MULTILINE),
            f"Missing admin guard decorator stack for route pattern: {pattern}",
        )


def test_admin_permission_helper_exists(app_source: str) -> None:
    required_tokens = [
        "def _has_access_request_admin_permission",
        "ACCESS_REQUEST_ADMIN_PERMISSION_KEYS",
        "def require_access_request_admin",
        "INSUFFICIENT_PERMISSIONS",
    ]
    for token in required_tokens:
        _assert(token in app_source, f"Missing required token in app.py: {token}")


def test_access_routes_use_service_layer(app_source: str) -> None:
    required_calls = [
        "svc_list_access_requests",
        "svc_approve_access_request",
        "svc_deny_access_request",
        "svc_revoke_access_request",
        "svc_resubmit_access_request",
    ]
    for call in required_calls:
        _assert(call in app_source, f"Expected service-layer call missing: {call}")


def main() -> int:
    if not APP_PATH.exists():
        print(f"[FAIL] app.py not found at {APP_PATH}")
        return 1
    if not SERVICE_PATH.exists():
        print(f"[FAIL] service file not found at {SERVICE_PATH}")
        return 1

    source = APP_PATH.read_text(encoding="utf-8")
    service_source = SERVICE_PATH.read_text(encoding="utf-8")

    try:
        test_interval_operator_fixed(source, service_source)
        test_legacy_access_routes_are_admin_guarded(source)
        test_admin_permission_helper_exists(source)
        test_access_routes_use_service_layer(source)
    except AssertionError as exc:
        print(f"[FAIL] {exc}")
        return 1

    print("[PASS] Access-request security and SQL interval regression checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
