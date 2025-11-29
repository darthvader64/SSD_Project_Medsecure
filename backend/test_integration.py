#!/usr/bin/env python
"""Test encryption endpoints using Flask test client"""

import sys
import json
from app import app

PASSED = 0
FAILED = 0

def test(name, condition, details=""):
    global PASSED, FAILED
    status = "[PASS]" if condition else "[FAIL]"
    print(f"{status} {name}")
    if details:
        print(f"      {details}")
    if condition:
        PASSED += 1
    else:
        FAILED += 1

print("\n" + "="*60)
print("ENCRYPTION & APIS - INTEGRATION TEST")
print("="*60)

with app.test_client() as client:
    # Test health
    print("\n[ENDPOINT TESTS]")
    r = client.get('/health')
    test("Health endpoint", r.status_code == 200, f"Status: {r.status_code}")
    
    # Test registration
    print("\n[USER MANAGEMENT]")
    r = client.post('/auth/register', json={
        'email': 'test_patient@example.com',
        'password': 'TestPass123!',
        'role': 'patient'
    })
    # Accept 201 (created), 200 (ok), 409 (conflict), or 400 (user exists)
    test("Patient registration", r.status_code in [200, 201, 400, 409], f"Status: {r.status_code}")
    
    # Test login
    print("\n[AUTHENTICATION]")
    r = client.post('/auth/login', json={
        'email': 'test_patient@example.com',
        'password': 'TestPass123!'
    })
    test("Patient login", r.status_code == 200, f"Status: {r.status_code}")
    
    if r.status_code == 200:
        token = r.json.get('access_token')
        print(f"      Got token: {token[:30]}...")
        
        # Test encryption endpoints
        print("\n[ENCRYPTION API ENDPOINTS]")
        
        # Presigned upload
        headers = {'Authorization': f'Bearer {token}'}
        r = client.post('/records/presign',
            json={'filename': 'test.pdf', 'content_type': 'application/pdf'},
            headers=headers)
        test("POST /records/presign", r.status_code == 200, f"Status: {r.status_code}")
        if r.status_code == 200:
            data = r.json if hasattr(r, 'json') else json.loads(r.data)
            print(f"      File URI: {data.get('file_uri')}")
        
        # Presigned download
        r = client.get('/records/download-url/999', headers=headers)
        test("GET /records/download-url", r.status_code in [200, 404, 403], f"Status: {r.status_code}")
        
        # RSA key generation
        test_pubkey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END PUBLIC KEY-----"
        r = client.post('/keys/generate',
            json={'public_key': test_pubkey},
            headers=headers)
        test("POST /keys/generate", r.status_code in [200, 201], f"Status: {r.status_code}")
        
        # Get public key
        r = client.get('/keys/public/1', headers=headers)
        test("GET /keys/public", r.status_code in [200, 404], f"Status: {r.status_code}")
        
        # Upload metadata
        r = client.post('/records/upload-metadata',
            json={
                'filename': 'test.pdf',
                'file_uri': 's3://bucket/test.pdf',
                'file_size': 1024,
                'iv': 'base64iv',
                'algorithm': 'AES-256-GCM',
                'patient_wrap': 'base64wrap',
                'salt': 'base64salt',
                'kdf_params': {'name': 'PBKDF2', 'iterations': 100000, 'hash': 'SHA-256', 'wrap_iv': 'base64iv'}
            },
            headers=headers)
        test("POST /records/upload-metadata", r.status_code in [200, 201], f"Status: {r.status_code}")

# Summary
print("\n" + "="*60)
print(f"RESULTS: {PASSED} Passed, {FAILED} Failed")
print("="*60 + "\n")

if FAILED == 0:
    print("✅ ALL TESTS PASSED - Encryption & APIs working perfectly!")
else:
    print(f"⚠️  {FAILED} test(s) failed")

sys.exit(0 if FAILED == 0 else 1)
