# test_audit_endpoint.py
import requests
import json

def test_audit_endpoint():
    base_url = "http://127.0.0.1:5001"
    
    print("🔍 TESTING AUDIT LOGS ENDPOINT")
    print("=" * 50)
    
    # First, try to login or use existing token
    try:
        # Check if we have a token
        token = input("Paste your JWT token (or press enter to skip): ").strip()
        
        if token:
            headers = {"Authorization": f"Bearer {token}"}
            
            # Test audit logs endpoint
            response = requests.get(f"{base_url}/audit-logs", headers=headers)
            
            print(f"Status Code: {response.status_code}")
            print(f"Response: {response.text}")
            
            if response.status_code == 200:
                logs = response.json()
                print(f"✅ Found {len(logs)} audit logs")
                for log in logs:
                    print(f"  - {log['action']} at {log.get('timestamp', 'N/A')}")
            else:
                print(f"❌ Error: {response.status_code} - {response.text}")
                
    except Exception as e:
        print(f"💥 Test failed: {e}")

if __name__ == "__main__":
    test_audit_endpoint()