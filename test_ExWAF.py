"""
exwaf test script
copyright (c) 2025

this script verifies the functionality of the exwaf by sending test requests
to check if it properly detects and blocks various attack attempts.
"""

import urllib.request
import urllib.error
import time
import sys

# configuration
WAF_URL = "http://localhost:8080"  # adjust as needed to match your waf configuration
TEST_PATH = "/owa/auth/logon.aspx"  # common exchange path

def test_normal_request():
    """test a normal, legitimate request"""
    print("\n[TEST] Normal request...")
    try:
        with urllib.request.urlopen(f"{WAF_URL}{TEST_PATH}") as response:
            print(f"✓ Normal request passed (Status code: {response.status})")
            return True
    except urllib.error.HTTPError as e:
        print(f"✗ Normal request failed! Status code: {e.code}")
        print(f"  Response: {e.read().decode('utf-8')}")
        return False
    except Exception as e:
        print(f"✗ Error on normal request: {str(e)}")
        return False

def test_xss_attack():
    """test an xss attack attempt"""
    print("\n[TEST] XSS attack simulation...")
    xss_payload = "<script>alert('XSS')</script>"
    test_url = f"{WAF_URL}{TEST_PATH}?username={xss_payload}"
    
    try:
        with urllib.request.urlopen(test_url) as response:
            print(f"✗ XSS test failed - attack was not blocked! Status code: {response.status}")
            return False
    except urllib.error.HTTPError as e:
        if e.code == 403:
            print("✓ XSS attack correctly blocked!")
            # output response body to see the full error message
            error_msg = e.read().decode('utf-8')
            print(f"  Response: {error_msg}")
            return True
        else:
            print(f"? XSS test failed with unexpected status code: {e.code}")
            return False
    except Exception as e:
        print(f"? Error testing XSS: {str(e)}")
        return False

def test_sql_injection():
    """test a sql injection attack attempt"""
    print("\n[TEST] SQL injection simulation...")
    sql_payload = "' OR 1=1 --"
    test_url = f"{WAF_URL}{TEST_PATH}?id={sql_payload}"
    
    try:
        with urllib.request.urlopen(test_url) as response:
            print(f"✗ SQL injection test failed - attack was not blocked! Status code: {response.status}")
            return False
    except urllib.error.HTTPError as e:
        if e.code == 403:
            print("✓ SQL injection attack correctly blocked!")
            # output response body to see the full error message
            error_msg = e.read().decode('utf-8')
            print(f"  Response: {error_msg}")
            return True
        else:
            print(f"? SQL injection test failed with unexpected status code: {e.code}")
            return False
    except Exception as e:
        print(f"? Error testing SQL injection: {str(e)}")
        return False

def test_rate_limiting():
    """test rate limiting functionality"""
    print("\n[TEST] Rate limiting simulation...")
    
    # make multiple requests in rapid succession
    success_count = 0
    block_count = 0
    total_requests = 15
    
    for i in range(total_requests):
        try:
            # add a unique query parameter to prevent caching
            test_url = f"{WAF_URL}{TEST_PATH}?nocache={i}"
            with urllib.request.urlopen(test_url) as response:
                if response.status == 200:
                    success_count += 1
                print(f"Request {i+1}/{total_requests}: Status {response.status}", end="\r")
        except urllib.error.HTTPError as e:
            if e.code == 429:  # too many requests
                block_count += 1
                print(f"Request {i+1}/{total_requests}: Blocked (429)", end="\r")
                # output response body to see the full error message
                error_msg = e.read().decode('utf-8')
                print(f"\n  Response: {error_msg}")
                # successfully detected rate limiting, we can stop
                print(f"\n✓ Rate limiting correctly blocked after {i+1} requests!")
                return True
            else:
                print(f"\nRequest {i+1}/{total_requests}: Unexpected status {e.code}")
        except Exception as e:
            print(f"\nError during rate limit test: {str(e)}")
            return False
        
        # small delay to make the output more readable but still trigger rate limiting
        time.sleep(0.1)
    
    # if we made all requests without being rate limited, the test fails
    print(f"\n✗ Rate limiting test failed - made {total_requests} requests without being blocked")
    return False

def run_tests():
    """run all tests"""
    print("=== ExWAF Test Suite ===")
    print(f"Testing against WAF at: {WAF_URL}")
    
    tests = {
        "Normal Request": test_normal_request,
        "XSS Attack Detection": test_xss_attack,
        "SQL Injection Detection": test_sql_injection,
        "Rate Limiting": test_rate_limiting
    }
    
    results = {}
    
    for name, test_func in tests.items():
        print(f"\n--- Testing: {name} ---")
        try:
            results[name] = test_func()
        except Exception as e:
            print(f"! Test crashed: {str(e)}")
            results[name] = False
    
    # print summary
    print("\n=== Test Summary ===")
    passed = 0
    for name, result in results.items():
        status = "PASS" if result else "FAIL"
        if result:
            passed += 1
        print(f"{name}: {status}")
    
    print(f"\nResults: {passed}/{len(results)} tests passed")
    
    if passed == len(results):
        print("\nAll tests passed! Your ExWAF is working correctly.")
    else:
        print("\nSome tests failed. Review the exwaf.log file for details.")

if __name__ == "__main__":
    run_tests() 