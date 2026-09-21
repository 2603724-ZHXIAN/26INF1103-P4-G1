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
    """Parses the raw VT API response into a clean, structured dictionary."""
    attributes = json_data.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    
    malicious_count = stats.get("malicious", 0)
    verdict = "malicious" if malicious_count > 0 else "clean"
    
    categories_dict = attributes.get("categories", {})
    unique_categories = list(set(categories_dict.values()))

    names = attributes.get("names", [])
    title = names[0] if isinstance(names, list) and names else attributes.get("title", "Unknown")

    return {
        "summary": {
            "title": title,
            "url": attributes.get("url", "Unknown"),
            "final_url": attributes.get("last_final_url", "Unknown"),
            "verdict": verdict,
            "reputation": attributes.get("reputation", 0),
            "threat_names": attributes.get("threat_names", []),
            "tags": attributes.get("tags", []),
            "categories": unique_categories,
            "detection_stats": {
                "harmless": stats.get("harmless", 0),
                "malicious": malicious_count,
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "timeout": stats.get("timeout", 0)
            }
        },
        "metadata": {
            "tld": attributes.get("tld", "Unknown"),
            "proxy_country": attributes.get("proxy_country", "Unknown"),
            "http_response_code": attributes.get("last_http_response_code", "Unknown"),
            "times_submitted": attributes.get("times_submitted", 0),
            "first_submission": attributes.get("first_submission_date", "Unknown"),
            "last_submission": attributes.get("last_submission_date", "Unknown")
        }
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
    url_id = base64.urlsafe_b64encode(url_input.encode()).decode().strip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    response = requests.get(endpoint, headers=HEADERS)
    
    if response.status_code == 404:
        return {"error": "URL not found in VirusTotal database. New scans are disabled to save time."}
        
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
        local_hash = ""
        
        if os.path.isfile(user_input):
            print(f"Calculating SHA-256 hash for '{user_input}'...")
            local_hash = get_file_hash(user_input)
            print(f"Checking VirusTotal for existing report (Hash: {local_hash})...")
            result = scan_file_hash(local_hash)
        else:
            local_hash = user_input
            print(f"Checking hash '{local_hash}'...")
            result = scan_file_hash(local_hash)
            
        # Check if we got a 404 (Not Found)
        if "error" in result and "404" in result.get("error", ""):
            print("\n[!] File not found on VirusTotal. Skipping new scan as requested.")
        else:
            print(f"\n🌐 View report on VirusTotal website: https://www.virustotal.com/gui/file/{local_hash}")
            
    elif choice == "2":
        user_input = input("Enter target URL (e.g., https://example.com): ").strip()
        print(f"Checking URL '{user_input}'...")
        result = scan_url(user_input)
        
        if "error" not in result:
            url_id = base64.urlsafe_b64encode(user_input.encode()).decode().strip("=")
            print(f"\n🌐 View report on VirusTotal website: https://www.virustotal.com/gui/url/{url_id}")
            
    else:
        print("Invalid selection.")
        return

    print("\n--- Results ---")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()