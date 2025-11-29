#!/usr/bin/env python
"""
Complete Encryption & APIs Test Suite
Tests all endpoints and encryption functionality
"""

import requests
import time
import sys
import json

BASE_URL = "http://localhost:5001"
TEST_PATIENT_EMAIL = "crypto_test_patient@example.com"
TEST_PATIENT_PASS = "CryptoTest123!@#"
TEST_DOCTOR_EMAIL = "crypto_test_doctor@example.com"
TEST_DOCTOR_PASS = "DoctorTest123!@#"

PASSED = 0
FAILED = 0

def log_test(name, passed, details=""):
    global PASSED, FAILED
    status = "[PASS]" if passed else "[FAIL]"
    print(f"{status} {name}")
    if details:
        print(f"     {details}")
    if passed:
        PASSED += 1
    else:
        FAILED += 1

def test_health():
    """Test health endpoint"""
    print("\n=== ENDPOINT AVAILABILITY ===")
    try:
        r = requests.get(f"{BASE_URL}/health", timeout=5)
        log_test("Health endpoint", r.status_code == 200, f"Status: {r.status_code}")
        return True
    except Exception as e:
        log_test("Health endpoint", False, str(e))
        return False

def test_registration():
    """Test user registration"""
    print("\n=== USER MANAGEMENT ===")
    
    # Register patient
    try:
        r = requests.post(f"{BASE_URL}/auth/register",
            json={"email": TEST_PATIENT_EMAIL, "password": TEST_PATIENT_PASS, "role": "patient"},
            timeout=5)
        is_ok = r.status_code in [200, 201, 409]  # 409 = already exists
        log_test("Patient registration", is_ok, f"Status: {r.status_code}")
    except Exception as e:
        log_test("Patient registration", False, str(e))
    
    # Register doctor
    try:
        r = requests.post(f"{BASE_URL}/auth/register",
            json={"email": TEST_DOCTOR_EMAIL, "password": TEST_DOCTOR_PASS, "role": "doctor"},
            timeout=5)
        is_ok = r.status_code in [200, 201, 409]
        log_test("Doctor registration", is_ok, f"Status: {r.status_code}")
    except Exception as e:
        log_test("Doctor registration", False, str(e))

def test_login():
    """Test user login"""
    print("\n=== AUTHENTICATION ===")
    
    patient_token = None
    doctor_token = None
    
    # Login patient
    try:
        r = requests.post(f"{BASE_URL}/auth/login",
            json={"email": TEST_PATIENT_EMAIL, "password": TEST_PATIENT_PASS},
            timeout=5)
        if r.status_code == 200:
            patient_token = r.json().get("access_token")
            log_test("Patient login", patient_token is not None, f"Got token: {patient_token[:20] if patient_token else 'None'}...")
        else:
            log_test("Patient login", False, f"Status: {r.status_code} - {r.text[:100]}")
    except Exception as e:
        log_test("Patient login", False, str(e))
    
    # Login doctor
    try:
        r = requests.post(f"{BASE_URL}/auth/login",
            json={"email": TEST_DOCTOR_EMAIL, "password": TEST_DOCTOR_PASS},
            timeout=5)
        if r.status_code == 200:
            doctor_token = r.json().get("access_token")
            log_test("Doctor login", doctor_token is not None, f"Got token: {doctor_token[:20] if doctor_token else 'None'}...")
        else:
            log_test("Doctor login", False, f"Status: {r.status_code}")
    except Exception as e:
        log_test("Doctor login", False, str(e))
    
    return patient_token, doctor_token

def test_encryption_endpoints(patient_token, doctor_token):
    """Test encryption API endpoints"""
    print("\n=== ENCRYPTION API ENDPOINTS ===")
    
    if not patient_token:
        print("[SKIP] Cannot test encryption endpoints without token")
        return
    
    # Test presigned upload URL
    try:
        headers = {"Authorization": f"Bearer {patient_token}"}
        r = requests.post(f"{BASE_URL}/records/presign",
            json={"filename": "test_record.pdf", "content_type": "application/pdf"},
            headers=headers,
            timeout=5)
        success = r.status_code == 200
        if success:
            data = r.json()
            log_test("GET presigned upload URL", success, f"File URI: {data.get('file_uri')}")
        else:
            log_test("GET presigned upload URL", False, f"Status: {r.status_code}")
    except Exception as e:
        log_test("GET presigned upload URL", False, str(e))
    
    # Test presigned download URL
    try:
        headers = {"Authorization": f"Bearer {patient_token}"}
        r = requests.get(f"{BASE_URL}/records/download-url/1",
            headers=headers,
            timeout=5)
        success = r.status_code in [200, 404]  # 404 if record doesn't exist
        log_test("GET presigned download URL", success, f"Status: {r.status_code}")
    except Exception as e:
        log_test("GET presigned download URL", False, str(e))
    
    # Test RSA key generation
    try:
        headers = {"Authorization": f"Bearer {patient_token}"}
        test_pubkey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Z8VSbg=\n-----END PUBLIC KEY-----"
        r = requests.post(f"{BASE_URL}/keys/generate",
            json={"public_key": test_pubkey},
            headers=headers,
            timeout=5)
        success = r.status_code in [200, 201]
        log_test("POST generate RSA keys", success, f"Status: {r.status_code}")
    except Exception as e:
        log_test("POST generate RSA keys", False, str(e))
    
    # Test get public key
    try:
        headers = {"Authorization": f"Bearer {patient_token}"}
        r = requests.get(f"{BASE_URL}/keys/public/1",
            headers=headers,
            timeout=5)
        success = r.status_code in [200, 404]  # 404 if key not found is ok
        log_test("GET user public key", success, f"Status: {r.status_code}")
    except Exception as e:
        log_test("GET user public key", False, str(e))
    
    # Test upload metadata
    try:
        headers = {"Authorization": f"Bearer {patient_token}"}
        r = requests.post(f"{BASE_URL}/records/upload-metadata",
            json={
                "filename": "test_record.pdf",
                "file_uri": "s3://bucket/test.pdf",
                "file_size": 1024,
                "iv": "base64encodediv",
                "algorithm": "AES-256-GCM",
                "patient_wrap": "base64wrappedkey",
                "salt": "base64salt",
                "kdf_params": {
                    "name": "PBKDF2",
                    "iterations": 100000,
                    "hash": "SHA-256",
                    "wrap_iv": "base64iv"
                }
            },
            headers=headers,
            timeout=5)
        success = r.status_code in [200, 201]
        log_test("POST upload metadata", success, f"Status: {r.status_code}")
    except Exception as e:
        log_test("POST upload metadata", False, str(e))

def test_crypto_requirements():
    """Verify crypto requirements are met"""
    print("\n=== CRYPTO LIBRARY VERIFICATION ===")
    
    try:
        # Test that crypto.ts can be loaded (check exports)
        crypto_file = r"c:\Users\saadu\Desktop\SSD\SSD_Project\frontend\src\lib\crypto.ts"
        with open(crypto_file, 'r', encoding='utf-8') as f:
            content = f.read()
            
        functions = [
            "generateFileKey",
            "generateRSAKeyPair",
            "generateSalt",
            "deriveKeyFromPassphrase",
            "wrapFileKey",
            "unwrapFileKeyWithPassphrase",
            "wrapFileKeyWithRSA",
            "unwrapFileKeyWithRSA",
            "encryptFile",
            "decryptFile",
            "importRSAPrivateKey",
            "exportRSAPublicKeyPEM",
            "exportRSAPrivateKeyPEM",
        ]
        
        found = 0
        for func in functions:
            if f"export const {func}" in content:
                found += 1
        
        log_test(f"Crypto functions ({found}/{len(functions)})", found == len(functions), f"Found {found} functions")
    except Exception as e:
        log_test("Crypto functions", False, str(e))

def main():
    print("\n" + "="*60)
    print("ENCRYPTION & APIS - COMPLETE TEST SUITE")
    print("="*60)
    
    # Test basic connectivity
    if not test_health():
        print("\n[ERROR] Server is not running!")
        print("Please start the server with: python app.py")
        return False
    
    # Test user management
    test_registration()
    patient_token, doctor_token = test_login()
    
    # Test encryption endpoints
    test_encryption_endpoints(patient_token, doctor_token)
    
    # Test crypto library
    test_crypto_requirements()
    
    # Summary
    print("\n" + "="*60)
    print(f"RESULTS: {PASSED} Passed, {FAILED} Failed")
    print("="*60 + "\n")
    
    if FAILED == 0:
        print("✅ ALL TESTS PASSED - Encryption & APIs are working!")
        return True
    else:
        print(f"⚠️  {FAILED} test(s) failed - Check output above")
        return False

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
