"""
Test Pydantic Validators in Isolation
Updated: February 12, 2026 - Uses current API format (job_title, no base_role_id)
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from validators import (
    B2BInterviewPrepareRequest, validate_role_id, sanitize_string,
    ROLE_ID_PATTERN
)
from pydantic import ValidationError

print("=" * 70)
print("PYDANTIC VALIDATOR ISOLATION TEST")
print("=" * 70)

passed = 0
failed = 0

# Test 1: XSS in company_name (script tag)
print("\n[TEST 1] XSS in company_name (script tag)")
try:
    request = B2BInterviewPrepareRequest(
        company_name="Test<script>alert('XSS')</script>Company",
        job_title="Safety Officer"
    )
    print(f"[FAIL] Should have raised ValidationError, got: {request.company_name}")
    failed += 1
except ValidationError as e:
    print(f"[PASS] ValidationError raised: {e.errors()[0]['msg']}")
    passed += 1
except Exception as e:
    print(f"[ERROR] Unexpected error: {e}")
    failed += 1

# Test 2: XSS in company_name (img tag)
print("\n[TEST 2] XSS in company_name (img tag)")
try:
    request = B2BInterviewPrepareRequest(
        company_name='Test<img src=x onerror=alert(1)>Corp',
        job_title="Safety Officer"
    )
    print(f"[FAIL] Should have raised ValidationError, got: {request.company_name}")
    failed += 1
except ValidationError as e:
    print(f"[PASS] ValidationError raised: {e.errors()[0]['msg']}")
    passed += 1
except Exception as e:
    print(f"[ERROR] Unexpected error: {e}")
    failed += 1

# Test 3: XSS in company_name (svg tag)
print("\n[TEST 3] XSS in company_name (svg tag)")
try:
    request = B2BInterviewPrepareRequest(
        company_name='<svg onload=alert(1)>Corp',
        job_title="Safety Officer"
    )
    print(f"[FAIL] Should have raised ValidationError, got: {request.company_name}")
    failed += 1
except ValidationError as e:
    print(f"[PASS] ValidationError raised: {e.errors()[0]['msg']}")
    passed += 1
except Exception as e:
    print(f"[ERROR] Unexpected error: {e}")
    failed += 1

# Test 4: XSS in job_title (javascript protocol)
print("\n[TEST 4] XSS in job_title (javascript: protocol)")
try:
    request = B2BInterviewPrepareRequest(
        company_name="TestCorp",
        job_title="javascript:alert(document.cookie)"
    )
    print(f"[FAIL] Should have raised ValidationError, got: {request.job_title}")
    failed += 1
except ValidationError as e:
    print(f"[PASS] ValidationError raised: {e.errors()[0]['msg']}")
    passed += 1
except Exception as e:
    print(f"[ERROR] Unexpected error: {e}")
    failed += 1

# Test 5: XSS in job_title (data URI)
print("\n[TEST 5] XSS in job_title (data: URI)")
try:
    request = B2BInterviewPrepareRequest(
        company_name="TestCorp",
        job_title="data:text/html,<script>alert(1)</script>"
    )
    print(f"[FAIL] Should have raised ValidationError, got: {request.job_title}")
    failed += 1
except ValidationError as e:
    print(f"[PASS] ValidationError raised: {e.errors()[0]['msg']}")
    passed += 1
except Exception as e:
    print(f"[ERROR] Unexpected error: {e}")
    failed += 1

# Test 6: DoS - Long company_name
print("\n[TEST 6] DoS - Long company_name (10,000 chars)")
try:
    request = B2BInterviewPrepareRequest(
        company_name="A" * 10000,
        job_title="Safety Officer"
    )
    print(f"[FAIL] Should have raised ValidationError, got name length: {len(request.company_name)}")
    failed += 1
except ValidationError as e:
    print(f"[PASS] ValidationError raised: {e.errors()[0]['msg']}")
    passed += 1
except Exception as e:
    print(f"[ERROR] Unexpected error: {e}")
    failed += 1

# Test 7: DoS - Long job_title
print("\n[TEST 7] DoS - Long job_title (10,000 chars)")
try:
    request = B2BInterviewPrepareRequest(
        company_name="TestCorp",
        job_title="A" * 10000
    )
    print(f"[FAIL] Should have raised ValidationError, got title length: {len(request.job_title)}")
    failed += 1
except ValidationError as e:
    print(f"[PASS] ValidationError raised: {e.errors()[0]['msg']}")
    passed += 1
except Exception as e:
    print(f"[ERROR] Unexpected error: {e}")
    failed += 1

# Test 8: Role ID validation - valid format
print("\n[TEST 8] Role ID validation - valid format")
try:
    result = validate_role_id("AOP-QA-HSE-SO-R1L1B1-263")
    print(f"[PASS] Valid role ID accepted: {result}")
    passed += 1
except Exception as e:
    print(f"[FAIL] Valid role ID rejected: {e}")
    failed += 1

# Test 9: Role ID validation - invalid format
print("\n[TEST 9] Role ID validation - invalid format")
try:
    result = validate_role_id("INVALID-FORMAT")
    print(f"[FAIL] Invalid role ID accepted: {result}")
    failed += 1
except ValueError as e:
    print(f"[PASS] ValueError raised: {e}")
    passed += 1
except Exception as e:
    print(f"[ERROR] Unexpected error: {e}")
    failed += 1

# Test 10: Role ID validation - rejects B-prefix (was previously accepted)
print("\n[TEST 10] Role ID validation - rejects B-prefix level")
try:
    result = validate_role_id("AOP-QA-HSE-SO-B1L1B1-263")
    print(f"[FAIL] B-prefix role ID accepted: {result}")
    failed += 1
except ValueError as e:
    print(f"[PASS] B-prefix role ID rejected: {e}")
    passed += 1
except Exception as e:
    print(f"[ERROR] Unexpected error: {e}")
    failed += 1

# Test 11: Extra fields rejected (strict mode)
print("\n[TEST 11] Extra fields rejected (strict mode)")
try:
    request = B2BInterviewPrepareRequest(
        company_name="TestCorp",
        job_title="Safety Officer",
        base_role_id="AOP-QA-HSE-SO-R3L3B3-265"  # Old field, should be rejected
    )
    print(f"[FAIL] Extra field accepted")
    failed += 1
except ValidationError as e:
    print(f"[PASS] Extra field rejected: {e.errors()[0]['msg']}")
    passed += 1
except Exception as e:
    print(f"[ERROR] Unexpected error: {e}")
    failed += 1

# Test 12: Valid request (should pass)
print("\n[TEST 12] Valid request (should pass)")
try:
    request = B2BInterviewPrepareRequest(
        company_name="ClientCo",
        job_title="Senior Safety Officer"
    )
    print(f"[PASS] Valid request accepted: company={request.company_name}, title={request.job_title}")
    passed += 1
except ValidationError as e:
    print(f"[FAIL] Should not have raised error: {e}")
    failed += 1
except Exception as e:
    print(f"[ERROR] Unexpected error: {e}")
    failed += 1

# Test 13: Valid request with custom JD (should pass)
print("\n[TEST 13] Valid request with custom JD (should pass)")
try:
    request = B2BInterviewPrepareRequest(
        company_name="ClientCo",
        job_title="Senior Safety Officer (Operations)",
        custom_jd={
            "job_title": "Senior Safety Officer - Offshore",
            "location": "Offshore Platform",
            "responsibilities": ["Monitor HSE compliance", "Conduct safety audits"]
        }
    )
    print(f"[PASS] Valid request with JD accepted: {request.custom_jd.job_title}")
    passed += 1
except ValidationError as e:
    print(f"[FAIL] Should not have raised error: {e}")
    failed += 1
except Exception as e:
    print(f"[ERROR] Unexpected error: {e}")
    failed += 1

print("\n" + "=" * 70)
print(f"RESULTS: {passed} passed, {failed} failed, {passed + failed} total")
print("=" * 70)

sys.exit(0 if failed == 0 else 1)

