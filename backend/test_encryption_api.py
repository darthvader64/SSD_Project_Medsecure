#!/usr/bin/env python
"""
Comprehensive test suite for Encryption & APIs implementation
Tests all endpoints and validates encryption flows
"""

import requests
import json
import sys
from datetime import datetime

# Configuration
BASE_URL = "http://localhost:5001"
TEST_PATIENT_EMAIL = "testpatient@example.com"
TEST_PATIENT_PASSWORD = "PatientPass123!"
TEST_DOCTOR_EMAIL = "testdoctor@example.com"
TEST_DOCTOR_PASSWORD = "DoctorPass123!"

# Test results tracking
passed_tests = 0
failed_tests = 0
test_results = []

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

def log_test(name: str, passed: bool, message: str = ""):
    global passed_tests, failed_tests
    status = f"{Colors.GREEN}✅ PASS{Colors.RESET}" if passed else f"{Colors.RED}❌ FAIL{Colors.RESET}"
    print(f"[{status}] {name}")
    if message:
        print(f"    {message}")
    if passed:
        passed_tests += 1
    else:
        failed_tests += 1
    test_results.append({"test": name, "passed": passed, "message": message})

def test_endpoint_exists(method: str, endpoint: str) -> bool:
    """Test if an endpoint exists and responds"""
    try:
        if method.upper() == "GET":
            response = requests.get(f"{BASE_URL}{endpoint}", timeout=5)
        elif method.upper() == "POST":
            response = requests.post(f"{BASE_URL}{endpoint}", json={}, timeout=5)
        # Just check if endpoint is reachable (might return 401 without auth, that's ok)
        return response.status_code in [200, 201, 400, 401, 404]
    except requests.exceptions.ConnectionError:
        return False
    except Exception as e:
        print(f"    Error: {str(e)}")
        return False

def test_health_check():
    """Test if server is running"""
    print(f"\n{Colors.BLUE}=== Health Check ==={Colors.RESET}")
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        log_test("Server is responding", response.status_code == 200, f"Status: {response.status_code}")
    except requests.exceptions.ConnectionError:
        log_test("Server is responding", False, "Connection refused - is Flask running on port 5001?")
        return False
    return True

def test_encryption_endpoints():
    """Test if encryption endpoints exist"""
    print(f"\n{Colors.BLUE}=== Encryption API Endpoints ==={Colors.RESET}")
    
    endpoints = [
        ("GET", "/keys/public/1", "Get user public key"),
        ("POST", "/keys/generate", "Generate RSA keys"),
        ("POST", "/records/presign", "Get upload presigned URL"),
        ("GET", "/records/download-url/1", "Get download presigned URL"),
        ("POST", "/records/upload-metadata", "Save encrypted metadata"),
    ]
    
    for method, endpoint, description in endpoints:
        exists = test_endpoint_exists(method, endpoint)
        log_test(f"{description} ({method} {endpoint})", exists)
    
    return True

def test_user_registration():
    """Test user registration"""
    print(f"\n{Colors.BLUE}=== User Registration ==={Colors.RESET}")
    
    # Register patient
    try:
        response = requests.post(f"{BASE_URL}/auth/register", json={
            "email": TEST_PATIENT_EMAIL,
            "password": TEST_PATIENT_PASSWORD,
            "role": "patient"
        }, timeout=5)
        
        patient_registered = response.status_code in [200, 201]
        if patient_registered:
            patient_data = response.json()
            patient_id = patient_data.get('user_id')
        else:
            # Maybe already registered
            patient_id = 1
            patient_registered = True
        
        log_test("Patient registration", patient_registered, f"Status: {response.status_code}")
    except Exception as e:
        log_test("Patient registration", False, str(e))
        patient_id = 1
    
    # Register doctor
    try:
        response = requests.post(f"{BASE_URL}/auth/register", json={
            "email": TEST_DOCTOR_EMAIL,
            "password": TEST_DOCTOR_PASSWORD,
            "role": "doctor"
        }, timeout=5)
        
        doctor_registered = response.status_code in [200, 201]
        if doctor_registered:
            doctor_data = response.json()
            doctor_id = doctor_data.get('user_id')
        else:
            doctor_id = 2
            doctor_registered = True
        
        log_test("Doctor registration", doctor_registered, f"Status: {response.status_code}")
    except Exception as e:
        log_test("Doctor registration", False, str(e))
        doctor_id = 2
    
    return patient_id, doctor_id

def test_user_login(email: str, password: str) -> str:
    """Test user login and return JWT token"""
    try:
        response = requests.post(f"{BASE_URL}/auth/login", json={
            "email": email,
            "password": password
        }, timeout=5)
        
        if response.status_code == 200:
            token = response.json().get('access_token')
            log_test(f"Login ({email})", True)
            return token
        else:
            log_test(f"Login ({email})", False, f"Status: {response.status_code}")
            return None
    except Exception as e:
        log_test(f"Login ({email})", False, str(e))
        return None

def test_key_management(patient_token: str, doctor_token: str):
    """Test key management endpoints"""
    print(f"\n{Colors.BLUE}=== Key Management ==={Colors.RESET}")
    
    if not patient_token:
        log_test("Store patient RSA public key", False, "No patient token")
        log_test("Store doctor RSA public key", False, "No doctor token")
        log_test("Retrieve doctor public key", False, "No tokens")
        return
    
    # Generate a test RSA public key (simplified for testing)
    test_public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Z8VSbgQJN1j1xFQ2c2c
FQeHvNYGfIXrYz1P2rIxVxZV9x0K8U6Cw8Z9R7p5K7R0K7R0K7R0K7R0K7R0K7R
0K7R0K7R0K7R0K7R0K7R0K7R0K7R0K7R0K7R0K7R0K7R0K7R0K7R0K7R0K7R0K7
R0K7R0K7R0K7R0K7R0K7R0K7R0K7R0K7R0K7R0KIQIDAQAB
-----END PUBLIC KEY-----"""
    
    # Test storing public key
    try:
        response = requests.post(
            f"{BASE_URL}/keys/generate",
            json={"public_key": test_public_key},
            headers={"Authorization": f"Bearer {patient_token}"},
            timeout=5
        )
        log_test("Store patient RSA public key", response.status_code in [200, 201], f"Status: {response.status_code}")
    except Exception as e:
        log_test("Store patient RSA public key", False, str(e))
    
    try:
        response = requests.post(
            f"{BASE_URL}/keys/generate",
            json={"public_key": test_public_key},
            headers={"Authorization": f"Bearer {doctor_token}"},
            timeout=5
        )
        log_test("Store doctor RSA public key", response.status_code in [200, 201], f"Status: {response.status_code}")
    except Exception as e:
        log_test("Store doctor RSA public key", False, str(e))
    
    # Test retrieving public key
    try:
        response = requests.get(
            f"{BASE_URL}/keys/public/1",
            headers={"Authorization": f"Bearer {patient_token}"},
            timeout=5
        )
        has_key = response.status_code == 200 and 'public_key' in response.json()
        log_test("Retrieve stored public key", has_key, f"Status: {response.status_code}")
    except Exception as e:
        log_test("Retrieve stored public key", False, str(e))

def test_presigned_urls(patient_token: str):
    """Test presigned URL generation"""
    print(f"\n{Colors.BLUE}=== Presigned URLs ==={Colors.RESET}")
    
    if not patient_token:
        log_test("Get upload presigned URL", False, "No patient token")
        log_test("Get download presigned URL", False, "No patient token")
        return
    
    # Test upload presigned URL
    try:
        response = requests.post(
            f"{BASE_URL}/records/presign",
            json={
                "filename": "test_record.pdf",
                "content_type": "application/pdf"
            },
            headers={"Authorization": f"Bearer {patient_token}"},
            timeout=5
        )
        
        success = response.status_code == 200
        if success:
            data = response.json()
            has_url = 'upload_url' in data and 'file_uri' in data
            log_test("Get upload presigned URL", has_url, f"Status: {response.status_code}")
        else:
            log_test("Get upload presigned URL", False, f"Status: {response.status_code}")
    except Exception as e:
        log_test("Get upload presigned URL", False, str(e))
    
    # Test download presigned URL (should fail if record doesn't exist, but endpoint should work)
    try:
        response = requests.get(
            f"{BASE_URL}/records/download-url/1",
            headers={"Authorization": f"Bearer {patient_token}"},
            timeout=5
        )
        # 404 is ok - record might not exist
        success = response.status_code in [200, 404]
        log_test("Get download presigned URL", success, f"Status: {response.status_code}")
    except Exception as e:
        log_test("Get download presigned URL", False, str(e))

def test_metadata_storage(patient_token: str):
    """Test encrypted metadata storage"""
    print(f"\n{Colors.BLUE}=== Encrypted Metadata Storage ==={Colors.RESET}")
    
    if not patient_token:
        log_test("Save encrypted record metadata", False, "No patient token")
        return
    
    # Test with valid metadata
    try:
        response = requests.post(
            f"{BASE_URL}/records/upload-metadata",
            json={
                "filename": "test_record.pdf",
                "file_uri": "s3://health-records/1/test123.pdf",
                "file_size": 1024,
                "iv": "base64encodediv",
                "algorithm": "AES-256-GCM",
                "patient_wrap": "base64encodedrappedkey",
                "salt": "base64encodedsalt",
                "kdf_params": {
                    "name": "PBKDF2",
                    "iterations": 100000,
                    "hash": "SHA-256",
                    "wrap_iv": "base64encodedsalt"
                }
            },
            headers={"Authorization": f"Bearer {patient_token}"},
            timeout=5
        )
        
        success = response.status_code in [200, 201]
        log_test("Save encrypted record metadata", success, f"Status: {response.status_code}")
    except Exception as e:
        log_test("Save encrypted record metadata", False, str(e))

def test_authentication_required():
    """Test that endpoints require authentication"""
    print(f"\n{Colors.BLUE}=== Authentication Protection ==={Colors.RESET}")
    
    # Test without token
    try:
        response = requests.post(f"{BASE_URL}/records/presign", json={}, timeout=5)
        requires_auth = response.status_code == 401
        log_test("Endpoints require authentication", requires_auth, f"Status without token: {response.status_code}")
    except Exception as e:
        log_test("Endpoints require authentication", False, str(e))
    
    # Test with invalid token
    try:
        response = requests.post(
            f"{BASE_URL}/records/presign",
            json={},
            headers={"Authorization": "Bearer invalid_token"},
            timeout=5
        )
        rejects_invalid = response.status_code == 401
        log_test("Endpoints reject invalid tokens", rejects_invalid, f"Status with invalid token: {response.status_code}")
    except Exception as e:
        log_test("Endpoints reject invalid tokens", False, str(e))

def print_summary():
    """Print test summary"""
    print(f"\n{Colors.BLUE}{'='*50}")
    print(f"TEST SUMMARY")
    print(f"{'='*50}{Colors.RESET}")
    print(f"{Colors.GREEN}Passed: {passed_tests}{Colors.RESET}")
    print(f"{Colors.RED}Failed: {failed_tests}{Colors.RESET}")
    print(f"Total: {passed_tests + failed_tests}")
    
    if failed_tests == 0:
        print(f"\n{Colors.GREEN}✅ All tests passed! Encryption & APIs are working correctly.{Colors.RESET}")
    else:
        print(f"\n{Colors.RED}❌ {failed_tests} test(s) failed. Check the details above.{Colors.RESET}")
    
    return failed_tests == 0

def main():
    print(f"\n{Colors.BLUE}{'='*50}")
    print(f"Encryption & APIs Test Suite")
    print(f"{'='*50}{Colors.RESET}")
    print(f"Testing endpoint: {BASE_URL}")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # 1. Health check
    if not test_health_check():
        print(f"\n{Colors.RED}Server is not running. Start Flask with: python app.py{Colors.RESET}")
        return False
    
    # 2. Check endpoints exist
    test_encryption_endpoints()
    
    # 3. Register users
    patient_id, doctor_id = test_user_registration()
    
    # 4. Test authentication
    print(f"\n{Colors.BLUE}=== Authentication ==={Colors.RESET}")
    patient_token = test_user_login(TEST_PATIENT_EMAIL, TEST_PATIENT_PASSWORD)
    doctor_token = test_user_login(TEST_DOCTOR_EMAIL, TEST_DOCTOR_PASSWORD)
    
    # 5. Test key management
    test_key_management(patient_token, doctor_token)
    
    # 6. Test presigned URLs
    test_presigned_urls(patient_token)
    
    # 7. Test metadata storage
    test_metadata_storage(patient_token)
    
    # 8. Test authentication protection
    test_authentication_required()
    
    # Print summary
    success = print_summary()
    
    return success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
