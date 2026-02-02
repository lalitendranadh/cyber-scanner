import hashlib
import requests

API_KEY = "PASTE_YOUR_VIRUSTOTAL_API_KEY_HERE"

def check_hash_virustotal(file_path):
    sha256 = hashlib.sha256(open(file_path,'rb').read()).hexdigest()
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": API_KEY}

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        malicious = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
        if malicious > 0:
            return f"[!!!] Malware detected by {malicious} engines for {file_path}\n"
    return ""
