import base64
import os
import requests
import json
import hashlib
from dotenv import load_dotenv

load_dotenv()
API_KEY=os.getenv("VT_API_KEY")
print(f"loaded api key: {API_KEY}")

HEADERS = {
    "accept": "application/json",
    "x-apikey": API_KEY
}

def parse_vt_response(json_data):
    attributes = json_data.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    
    return {
        "title": attributes.get("names", [attributes.get("url", "Unknown")])[0] if isinstance(attributes.get("names"), list) else attributes.get("names", "Unknown"),
        "detection_stats": {
            "harmless": stats.get("harmless", 0),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "timeout": stats.get("timeout", 0)
        },
        "tags": attributes.get("tags", []),
        "available_attributes": list(attributes.keys()),
        "raw_data": json_data
    }

def scan_file_hash(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    response = requests.get(url, headers=HEADERS)
    if response.status_code == 200:
        return parse_vt_response(response.json())
    return {"error": f"Failed with status code {response.status_code}", "details": response.text}

# def upload_and_scan_file(file_path):
#     if not os.path.exists(file_path):
#         return {"error": "File path does not exist."}
    
#     url = "https://www.virustotal.com/api/v3/files"
#     with open(file_path, "rb") as file_handle:
#         files = {"file": (os.path.basename(file_path), file_handle)}
#         response = requests.post(url, headers=HEADERS, files=files)
    
#     if response.status_code == 200:
#         return response.json()
#     return {"error": f"Failed to upload file. Status code {response.status_code}", "details": response.text}

def get_file_hash(file_path):
    """Calculates the SHA-256 hash of a local file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def scan_url(url_input):
    # Convert URL to VirusTotal base64 URL identifier
    url_id = base64.urlsafe_b64encode(url_input.encode()).decode().strip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    response = requests.get(endpoint, headers=HEADERS)
    
    if response.status_code == 404:
        submit_url = "https://www.virustotal.com/api/v3/urls"
        payload = {"url": url_input}
        submit_response = requests.post(submit_url, headers=HEADERS, data=payload)
        return submit_response.json()
        
    if response.status_code == 200:
        return parse_vt_response(response.json())
        
    return {"error": f"Failed with status code {response.status_code}", "details": response.text}

def main():
    print("--- VirusTotal v3 Scanner ---")
    print("1. Check File (by Path or Hash)")
    print("2. Check URL")
    
    choice = input("Select an option (1 or 2): ").strip()
    
    if choice == "1":
        user_input = input("Enter local file path OR file hash (MD5/SHA256): ").strip()
        if os.path.isfile(user_input):
            print(f"Uploading file '{user_input}' to VirusTotal...")
            result = upload_and_scan_file(user_input)
        else:
            print(f"Checking hash '{user_input}'...")
            result = scan_file_hash(user_input)
            
    elif choice == "2":
        user_input = input("Enter target URL (e.g., https://example.com): ").strip()
        print(f"Checking URL '{user_input}'...")
        result = scan_url(user_input)
    else:
        print("Invalid selection.")
        return

    print("\n--- Results ---")
    print(result)

if __name__ == "__main__":
    main()