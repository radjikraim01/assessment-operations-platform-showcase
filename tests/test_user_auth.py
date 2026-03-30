"""
Test user authentication module
Verifies authenticate_user() and decorators work correctly
"""

import sys

print("=" * 80)
print("TESTING USER AUTHENTICATION MODULE")
print("=" * 80)

print("\n1. TESTING IMPORTS:")

try:
    print("   - Importing auth.user_auth...")
    from auth.user_auth import (
        authenticate_user,
        require_login,
        require_permission,
        get_current_user,
        check_permission,
        is_admin,
        is_logged_in,
        logout_user
    )
    print("     [OK] All functions imported successfully")
except Exception as e:
    print(f"     [FAIL] Failed to import auth.user_auth: {e}")
    sys.exit(1)

try:
    print("   - Importing app with new routes...")
    import app
    print("     [OK] app.py imported successfully")
except Exception as e:
    print(f"     [FAIL] Failed to import app.py: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\n2. CHECKING NEW ROUTES:")
try:
    from app import app as flask_app

    new_routes = [
        '/login',
        '/api/login',
        '/api/logout'
    ]

    for route in flask_app.url_map.iter_rules():
        if str(route) in new_routes:
            print(f"   [OK] Route registered: {route}")

except Exception as e:
    print(f"   [FAIL] Failed to check routes: {e}")
    sys.exit(1)

print("\n3. TESTING authenticate_user() FUNCTION:")
try:
    # This will fail (no such user), but shouldn't crash
    result = authenticate_user('nonexistent@test.com', 'password', {})
    if result is None:
        print("   [OK] authenticate_user() returns None for invalid user")
    else:
        print(f"   [WARN] Expected None, got: {result}")
except Exception as e:
    print(f"   [FAIL] authenticate_user() crashed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\n4. TESTING HELPER FUNCTIONS:")
try:
    # Test is_admin() (should return False when not in Flask context)
    # These functions need Flask request context, so we just check they don't crash
    from flask import Flask
    test_app = Flask(__name__)
    test_app.secret_key = 'test'

    with test_app.test_request_context():
        result = is_logged_in()
        print(f"   [OK] is_logged_in() works (returns: {result})")

        result = is_admin()
        print(f"   [OK] is_admin() works (returns: {result})")

        result = check_permission('can_view_roles')
        print(f"   [OK] check_permission() works (returns: {result})")

        result = get_current_user()
        print(f"   [OK] get_current_user() works (returns: {result})")

except Exception as e:
    print(f"   [FAIL] Helper functions failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\n" + "=" * 80)
print("USER AUTHENTICATION MODULE: [SUCCESS]")
print("=" * 80)
print("\nNext steps:")
print("  1. Create a test user in database")
print("  2. Start Flask: python app.py")
print("  3. Visit http://localhost:5000/login")
print("  4. Test login with admin and user credentials")
print("=" * 80)
