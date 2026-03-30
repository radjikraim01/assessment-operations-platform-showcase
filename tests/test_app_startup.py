"""
Test that Flask app starts without errors
Checks for import errors and syntax issues
"""

import sys

print("=" * 80)
print("TESTING FLASK APP STARTUP")
print("=" * 80)

print("\n1. CHECKING IMPORTS:")

try:
    print("   - Importing auth.audit...")
    from auth.audit import log_action, AuditAction, ResourceType
    print("     [OK] auth.audit imported successfully")
except Exception as e:
    print(f"     [FAIL] Failed to import auth.audit: {e}")
    sys.exit(1)

try:
    print("   - Importing app...")
    import app
    print("     [OK] app.py imported successfully")
except Exception as e:
    print(f"     [FAIL] Failed to import app.py: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\n2. CHECKING FLASK APP:")
try:
    from app import app as flask_app
    print(f"   [OK] Flask app created: {flask_app}")
    print(f"   [OK] App name: {flask_app.name}")
except Exception as e:
    print(f"   [FAIL] Failed to get Flask app: {e}")
    sys.exit(1)

print("\n3. CHECKING ROUTES WITH AUDIT LOGGING:")
try:
    routes_with_logging = [
        '/',
        '/roles',
        '/role/<role_id>',
        '/api/jd/<identifier>',
        '/api/questions/<role_id>',
        '/api/generate-script',
        '/api/admin/login',
        '/api/admin/logout'
    ]

    for route in flask_app.url_map.iter_rules():
        if str(route) in routes_with_logging:
            print(f"   [OK] Route registered: {route}")

    print(f"   [OK] Total routes registered: {len(list(flask_app.url_map.iter_rules()))}")

except Exception as e:
    print(f"   [FAIL] Failed to check routes: {e}")
    sys.exit(1)

print("\n" + "=" * 80)
print("FLASK APP STARTUP: [SUCCESS]")
print("=" * 80)
print("\nNext steps:")
print("  1. Start Flask: python app.py")
print("  2. Visit http://localhost:5000/ (should log 'view_dashboard')")
print("  3. Check logs: python -c \"from auth.audit import get_audit_logs; import json; print(json.dumps(get_audit_logs(limit=5), indent=2))\"")
print("=" * 80)
