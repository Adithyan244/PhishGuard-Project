import urllib.parse
import re
import whois
import dns.resolver
import requests
from datetime import datetime
import base64
import difflib

class URLForensicsEngine:

    def __init__(self, vt_api_key = None):
        # optional API keys added
        self.vt_api_key = vt_api_key
    
    def extract_all_features(self, url):
        # runs CTI and forensic checks on a URL
        print(f"\n--- Analysing: {url} ---")

        # 1. Parse the URL
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc

        # Gathering Intelligence
        features = {
            'url' : url,
            'domain' : domain,
            **self.lexical_analysis(url,domain),
            **self.dns_lookup(domain),
            **self.whois_lookup(domain),
            **self.check_urlhaus(url)
        }
        features['vt_malicious_votes'] = self.check_virustotal(url)
        features['typosquat_target'] = self.check_typosquatting(domain)
        return features
    
    def lexical_analysis(self, url, domain):
        print("Running Lexical Analysis...")
        return {
            'url_length' : len(url),
            'domain_length' : len(domain),
            'num_dots' : url.count('.'),
            'num_hyphens' : url.count('-'),
            'num_at_symbols' : url.count('@'),
            'num_subdirectories' : url.count('/'),
            'is_ip_domain' : 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$",domain) else 0
        }
    
    def dns_lookup(self, domain):
        print("Running DNS Forensics...")
        try:
            answers = dns.resolver.resolve(domain, 'A')
            ip_addresses = [rdata.address for rdata in answers]
            return {'has_dns' : 1, 'resolved_ips' : len(ip_addresses)}
        except Exception:
            # Domain is dead or fake
            return {'has_dns' : 0, 'resolved_ips' : 0}
        
    def whois_lookup(self, domain):
        print(f"Running WHOIS Lookup for {domain}...")
        try:
            rdap_url = f"https://rdap.org/domain/{domain}"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
            response = requests.get(rdap_url, headers = headers, timeout = 5)
            if response.status_code == 200:
                data = response.json()
                for event in data.get('events', []):
                    if event.get('eventAction') == 'registration':
                        date_str = event.get('eventDate')
                        creation_date = datetime.strptime(date_str[:10], '%Y-%m-%d')
                        days_old = (datetime.now() - creation_date).days
                        print(f"[+] RDAP Success: Domain is {days_old} days old.")
                        return {'domain_age_days': days_old}
            print(" [-] RDAP failed")
            return {'domain_age_days': -1}
        except Exception as e:
            print(f" [-] RDAP Exception: {e}")
            return {'domain_age_days': -1}
    
    def check_typosquatting(self, domain):
        print(f"[*] Checking for Typosquatting...")
        main_name = domain.split('.')[0].lower()
        high_value_targets = ['google', 'microsoft', 'apple', 'amazon', 'chase', 'paypal', 'netflix', 'github', 'bankofamerica']
        for target in high_value_targets:
            similarity = difflib.SequenceMatcher(None, main_name, target).ratio()
            if 0.8 <= similarity < 1.0:
                print(f" [!] TYPOSQUAT ALERT: '{main_name}' is spoofing '{target}'")
                return target
        return "None"

    def check_virustotal(self,url):
        print(f"[*] Querying VirusTotal API...")
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        vt_api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {
            "accept": "application/json",
            "x-apikey": "*The api key*"
        }
        try:
            response = requests.get(vt_api_url, headers = headers, timeout = 5)
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                malicious_votes = stats['malicious'] + stats['suspicious']
                print (f" [+] VT found {malicious_votes} malicious votes")
                return malicious_votes
            else:
                return 0
        except Exception:
            return 0

    def check_urlhaus(self, url):
        print("Querying URLhaus API...")
        api_url = "https://urlhaus-api.abuse.ch/v1/url/"
        data = {'url' : url}
        try:
            response = response.post(api_url, data = data, timeout = 5)
            if response.status_code == 200:
                result = response.json()
                if result['query_status'] == 'ok':
                    return {'urlhaus_threat' : 1}
            return {'urlhaus_threat' : 0}
        except Exception:
            return {'urlhaus_threat' : 0}
        
if __name__ == "__main__":
    engine = URLForensicsEngine()
    safe_url = "https://www.github.com/torvalds/linux"
    safe_results = engine.extract_all_features(safe_url)
    print("\nResults for Safe URL: ")
    for key, value in safe_results.items():
        print(f" {key} : {value}")
    bad_url = "http://192.168.1.100/secure/login.php?client_id=xyz"
    bad_results = engine.extract_all_features(bad_url)
    print("\nResults for Suspicious URL: ")
    for key,value in bad_results.items():
        print(f" {key} : {value}")
