import requests
import hashlib
import time
import json

class VirusTotalScanner:
    def __init__(self, api_key=None):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.enabled = api_key is not None
    
    def calculate_hash(self, filepath):
        sha256 = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except:
            return None
    
    def check_file_hash(self, file_hash):
        if not self.enabled:
            return None
        
        headers = {
            "x-apikey": self.api_key
        }
        
        url = f"{self.base_url}/files/{file_hash}"
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return {
                    'found': True,
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'total_scans': sum(stats.values())
                }
            elif response.status_code == 404:
                return {'found': False}
            else:
                return None
        except Exception as e:
            print(f"[ERROR] VirusTotal API error: {e}")
            return None
    
    def scan_file(self, filepath):
        file_hash = self.calculate_hash(filepath)
        if not file_hash:
            return None
        
        result = self.check_file_hash(file_hash)
        if result:
            result['file_hash'] = file_hash
            result['file'] = filepath
        
        return result
    
    def scan_files_batch(self, filepaths, delay=15):
        results = []
        
        for i, filepath in enumerate(filepaths, 1):
            print(f"[*] Scanning {i}/{len(filepaths)}: {filepath}")
            
            result = self.scan_file(filepath)
            if result:
                results.append(result)
                
                if result.get('found') and result.get('malicious', 0) > 0:
                    print(f"    [!] MALICIOUS: {result['malicious']}/{result['total_scans']} engines")
            
            if i < len(filepaths):
                time.sleep(delay)
        
        return results

def load_virustotal_config(config_file="virustotal_config.json"):
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
            return config.get('api_key')
    except:
        return None

def create_sample_vt_config():
    sample = {
        "api_key": "YOUR_VIRUSTOTAL_API_KEY_HERE",
        "note": "Get your free API key from https://www.virustotal.com/gui/join-us"
    }
    
    with open("virustotal_config.sample.json", 'w') as f:
        json.dump(sample, f, indent=2)
    
    print("[+] Sample VirusTotal config created: virustotal_config.sample.json")
    print("[*] Sign up at https://www.virustotal.com/gui/join-us")
    print("[*] Copy to virustotal_config.json and add your API key")
