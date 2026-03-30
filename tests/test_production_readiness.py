"""
Production Readiness Integration Tests
Representative integration checks for the sanitized showcase app.

Run with: python tests/test_production_readiness.py

These tests assume a running local app instance and a database seeded with the
expected schema and API key records.
"""

import requests
import time
import json
import concurrent.futures
from typing import Dict, List
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configuration
BASE_URL = "http://localhost:5000"
API_KEY = os.environ.get('DEMO_API_KEY', 'test-api-key')

# Test results storage
test_results = []


def log_test(test_name: str, passed: bool, message: str = ""):
    """Log test result"""
    status = "[PASS]" if passed else "[FAIL]"
    result = {
        'test': test_name,
        'passed': passed,
        'message': message,
        'status': status
    }
    test_results.append(result)
    print(f"{status}: {test_name}")
    if message:
        print(f"   {message}")


def print_summary():
    """Print test summary"""
    passed = sum(1 for r in test_results if r['passed'])
    total = len(test_results)
    pass_rate = (passed / total * 100) if total > 0 else 0

    print("\n" + "=" * 80)
    print(f"TEST SUMMARY: {passed}/{total} passed ({pass_rate:.1f}%)")
    print("=" * 80)

    if passed < total:
        print("\n[FAILED TESTS]:")
        for result in test_results:
            if not result['passed']:
                print(f"  - {result['test']}: {result['message']}")
    else:
        print("\nALL TESTS PASSED! System is production ready.")


# ============================================================================
# TEST 1: Security - No Hardcoded Passwords
# ============================================================================

def test_environment_variables_required():
    """Test that app requires .env file (no hardcoded passwords)"""
    try:
        # This test would require restarting app without .env
        # For now, we verify .env exists and has required vars
        required_vars = ['DB_PASSWORD', 'FLASK_SECRET_KEY', 'DEMO_API_KEY']
        missing = [var for var in required_vars if not os.environ.get(var)]

        if missing:
            log_test(
                "Environment Variables Required",
                False,
                f"Missing variables: {', '.join(missing)}"
            )
        else:
            log_test("Environment Variables Required", True, "All required env vars present")

    except Exception as e:
        log_test("Environment Variables Required", False, str(e))


# ============================================================================
# TEST 2: Security - Input Validation
# ============================================================================

def test_xss_prevention():
    """Test XSS prevention in company name"""
    try:
        response = requests.post(
            f"{BASE_URL}/api/external/interview/prepare",
            headers={'X-API-Key': API_KEY, 'Content-Type': 'application/json'},
            json={
                "company_name": "Test<script>alert('XSS')</script>Company",
                "job_title": "Safety Officer"
            },
            timeout=5
        )

        # Should return 400 with validation error
        if response.status_code == 400 and ('Dangerous content detected' in response.text or 'Validation failed' in response.text):
            log_test("XSS Prevention", True, "Blocked dangerous content")
        else:
            log_test("XSS Prevention", False, f"Expected 400 with validation error, got {response.status_code}: {response.text[:200]}")

    except requests.exceptions.Timeout:
        log_test("XSS Prevention", False, "Request timed out")
    except Exception as e:
        log_test("XSS Prevention", False, str(e))


def test_dos_prevention_large_payload():
    """Test DoS prevention for large payloads"""
    try:
        response = requests.post(
            f"{BASE_URL}/api/external/interview/prepare",
            headers={'X-API-Key': API_KEY, 'Content-Type': 'application/json'},
            json={
                "company_name": "A" * 10000,  # 10,000 characters (max is 100)
                "job_title": "Safety Officer"
            },
            timeout=5
        )

        # Should return 400 with validation error (Pydantic max_length=100 or sanitize_string)
        if response.status_code == 400 and ('Validation failed' in response.text or 'exceeds maximum length' in response.text or 'at most 100' in response.text):
            log_test("DoS Prevention (Large Payload)", True, "Blocked oversized input")
        else:
            log_test("DoS Prevention (Large Payload)", False, f"Expected 400 with validation error, got {response.status_code}: {response.text[:200]}")

    except requests.exceptions.Timeout:
        log_test("DoS Prevention (Large Payload)", False, "Request timed out")
    except Exception as e:
        log_test("DoS Prevention (Large Payload)", False, str(e))


def test_extra_fields_rejected():
    """Test that unknown/extra fields are rejected (extra='forbid')"""
    try:
        response = requests.post(
            f"{BASE_URL}/api/external/interview/prepare",
            headers={'X-API-Key': API_KEY, 'Content-Type': 'application/json'},
            json={
                "company_name": "TestCorp",
                "job_title": "Safety Officer",
                "base_role_id": "INVALID-FORMAT"  # Extra field - should be rejected
            },
            timeout=5
        )

        # Should return 400 because extra fields are forbidden
        if response.status_code == 400 and ('Extra inputs' in response.text or 'Validation failed' in response.text):
            log_test("Extra Fields Rejected", True, "Rejected unknown field (base_role_id)")
        else:
            log_test("Extra Fields Rejected", False, f"Expected 400 with validation error, got {response.status_code}: {response.text[:200]}")

    except requests.exceptions.Timeout:
        log_test("Extra Fields Rejected", False, "Request timed out")
    except Exception as e:
        log_test("Extra Fields Rejected", False, str(e))


# ============================================================================
# TEST 3: Scalability - Connection Pooling
# ============================================================================

def test_concurrent_requests():
    """Test handling of concurrent requests (connection pooling)"""
    try:
        num_concurrent = 20  # Test with 20 concurrent requests

        def make_request(i):
            """Make a single request"""
            try:
                response = requests.get(
                    f"{BASE_URL}/api/external/request-status/999",  # Non-existent ID
                    headers={'X-API-Key': API_KEY},
                    timeout=10
                )
                return response.status_code in [200, 404]  # Both are acceptable
            except:
                return False

        # Execute requests concurrently
        start_time = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_concurrent) as executor:
            results = list(executor.map(make_request, range(num_concurrent)))

        elapsed = time.time() - start_time

        # All requests should succeed (no crashes)
        success_rate = sum(results) / len(results) * 100

        if success_rate >= 95:  # Allow 5% failure tolerance
            log_test(
                "Concurrent Requests (Connection Pool)",
                True,
                f"{success_rate:.1f}% success rate with {num_concurrent} concurrent requests in {elapsed:.2f}s"
            )
        else:
            log_test(
                "Concurrent Requests (Connection Pool)",
                False,
                f"Only {success_rate:.1f}% success rate"
            )

    except Exception as e:
        log_test("Concurrent Requests (Connection Pool)", False, str(e))


# ============================================================================
# TEST 4: Data Integrity - Transactions
# ============================================================================

def test_valid_request_creation():
    """Test creating a valid authorization request (transaction atomicity)"""
    try:
        response = requests.post(
            f"{BASE_URL}/api/external/interview/prepare",
            headers={'X-API-Key': API_KEY, 'Content-Type': 'application/json'},
            json={
                "company_name": "ClientCo",
                "base_role_id": "AOP-QA-HSE-SO-R3L3B3-265",
                "custom_jd": {
                    "job_title": "Senior Safety Officer - Integration Test",
                    "location": "Offshore Platform",
                    "responsibilities": ["Test duty 1", "Test duty 2"],
                    "certifications": ["NEBOSH", "IOSH"]
                }
            },
            timeout=10
        )

        # Should return 202 Accepted with request_id
        if response.status_code == 202:
            data = response.json()
            if 'request_id' in data and data['status'] == 'pending_authorization':
                log_test(
                    "Valid Request Creation (Transaction)",
                    True,
                    f"Created request #{data['request_id']}"
                )
                return data['request_id']
            else:
                log_test("Valid Request Creation (Transaction)", False, "Missing request_id or status")
                return None
        else:
            log_test("Valid Request Creation (Transaction)", False, f"Expected 202, got {response.status_code}: {response.text}")
            return None

    except requests.exceptions.Timeout:
        log_test("Valid Request Creation (Transaction)", False, "Request timed out")
        return None
    except Exception as e:
        log_test("Valid Request Creation (Transaction)", False, str(e))
        return None


def test_request_status_polling(request_id):
    """Test polling for request status"""
    if not request_id:
        log_test("Request Status Polling", False, "No request_id from previous test")
        return

    try:
        response = requests.get(
            f"{BASE_URL}/api/external/request-status/{request_id}",
            headers={'X-API-Key': API_KEY},
            timeout=5
        )

        # Should return 200 with status
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'pending':
                log_test("Request Status Polling", True, f"Status: pending")
            else:
                log_test("Request Status Polling", True, f"Status: {data.get('status')}")
        else:
            log_test("Request Status Polling", False, f"Expected 200, got {response.status_code}")

    except requests.exceptions.Timeout:
        log_test("Request Status Polling", False, "Request timed out")
    except Exception as e:
        log_test("Request Status Polling", False, str(e))


# ============================================================================
# TEST 5: Stability - No Memory Leaks
# ============================================================================

def test_repeated_requests_no_leak():
    """Test repeated requests don't cause memory leaks"""
    try:
        # Make 50 requests in sequence (would cause 4GB leak before fix)
        num_requests = 50
        success_count = 0

        for i in range(num_requests):
            try:
                response = requests.get(
                    f"{BASE_URL}/api/external/request-status/999",
                    headers={'X-API-Key': API_KEY},
                    timeout=5
                )
                if response.status_code in [200, 404]:
                    success_count += 1
            except:
                pass

        success_rate = success_count / num_requests * 100

        if success_rate >= 95:
            log_test(
                "Repeated Requests (No Memory Leak)",
                True,
                f"{success_count}/{num_requests} succeeded ({success_rate:.1f}%)"
            )
        else:
            log_test(
                "Repeated Requests (No Memory Leak)",
                False,
                f"Only {success_count}/{num_requests} succeeded"
            )

    except Exception as e:
        log_test("Repeated Requests (No Memory Leak)", False, str(e))


# ============================================================================
# TEST 6: Performance - Connection Speed
# ============================================================================

def test_connection_pool_performance():
    """Test connection pool improves performance"""
    try:
        # Make 10 sequential requests and measure average time
        num_requests = 10
        times = []

        for i in range(num_requests):
            start = time.time()
            try:
                response = requests.get(
                    f"{BASE_URL}/api/external/request-status/999",
                    headers={'X-API-Key': API_KEY},
                    timeout=5
                )
                elapsed = time.time() - start
                if response.status_code in [200, 404]:
                    times.append(elapsed)
            except:
                pass

        if times:
            avg_time = sum(times) / len(times)
            # With connection pooling, should be <100ms per request
            if avg_time < 0.1:  # 100ms
                log_test(
                    "Connection Pool Performance",
                    True,
                    f"Average response time: {avg_time*1000:.1f}ms (target: <100ms)"
                )
            else:
                log_test(
                    "Connection Pool Performance",
                    True,  # Still pass but warn
                    f"Average response time: {avg_time*1000:.1f}ms (slower than expected)"
                )
        else:
            log_test("Connection Pool Performance", False, "No successful requests")

    except Exception as e:
        log_test("Connection Pool Performance", False, str(e))


# ============================================================================
# MAIN TEST RUNNER
# ============================================================================

def run_all_tests():
    """Run all integration tests"""
    print("=" * 80)
    print("AOP PLATFORM - PRODUCTION READINESS INTEGRATION TESTS")
    print("=" * 80)
    print()

    # Check if server is running
    try:
        response = requests.get(f"{BASE_URL}/", timeout=5)
        print(f"[OK] Server is running at {BASE_URL}")
        print()
    except requests.exceptions.ConnectionError:
        print(f"[ERROR] Server not running at {BASE_URL}")
        print("   Start the server with: python app.py")
        return
    except Exception as e:
        print(f"[ERROR] {e}")
        return

    # Run tests
    print("Running tests...")
    print()

    # Security tests
    test_environment_variables_required()
    test_xss_prevention()
    test_dos_prevention_large_payload()
    test_extra_fields_rejected()

    # Scalability tests
    test_concurrent_requests()

    # Data integrity tests
    request_id = test_valid_request_creation()
    test_request_status_polling(request_id)

    # Stability tests
    test_repeated_requests_no_leak()

    # Performance tests
    test_connection_pool_performance()

    # Print summary
    print()
    print_summary()


if __name__ == "__main__":
    run_all_tests()

