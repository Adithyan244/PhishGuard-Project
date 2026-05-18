from fastapi import FastAPI, HTTPException 
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import pandas as pd
from cti_engine import URLForensicsEngine
import urllib.parse
import re

app = FastAPI(title = "PhishGuard Core API", version = "1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins = ["http://localhost:5173","chrome-extension://figghgpkljihjifobomebajcpkjfnpho"],
    allow_credentials = True,
    allow_methods = ["*"],
    allow_headers = ["*"]
)

print("Starting PhishGuard API...")
engine = URLForensicsEngine()

try:
    ml_model = joblib.load('models/phishguard_xgb.pkl')
    print("XGBoost Model loaded Successfully!!")
except Exception as e:
    print(f"CRITICAL ERROR: Could not load model. {e}")

print("Loading Global Allowlist (Tranco Top 100k)...")
try:
    tranco_df = pd.read_csv('data/raw/tranco.csv', names = ['rank', 'domain'], nrows = 100000)
    SAFE_DOMAINS = set(tranco_df['domain'].tolist())
    print(f"Successfully loaded {len(SAFE_DOMAINS)} trusted domains into memory")
except Exception as e:
    print(f"Warning: Could not load Tranco dataset. {e}")
    SAFE_DOMAINS = {"github.com", "google.com", "youtube.com"}
class ScanRequest(BaseModel):
    url: str

@app.post("/scan")
async def scan_url(request: ScanRequest):
    target_url = request.url
    print(f"Incoming scan request for: {target_url}")
    try:
        parsed = urllib.parse.urlparse(target_url)
        domain = parsed.netloc.replace("www.", "")
        if domain in SAFE_DOMAINS:
            print("[*] Domain found in Global Allowlist. Bypassing AI")
            return {
                "target_url": target_url,
                "status": "BENIGN",
                "risk_score_percentage": 0.0,
                "forensics_report": {"note": "Bypassed ML: Domain is Verified"}
            }
        features_dict = engine.extract_all_features(target_url)
        if not features_dict:
            raise HTTPException(status_code = 500, detail = "Feature extraction failed.")
        # 1. MALICIOUS BYPASS: Bare IP Address 
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
            print("[*] Bare IP Address detected (MALICIOUS).")
            features_dict['tripwire_alert'] = "Critical Threat - Bare IP address used instead of domain name."
            return {
                "target_url": target_url, "status": "MALICIOUS", "risk_score_percentage": 99.9, "forensics_report": features_dict
            }
        if "@" in parsed.netloc:
            print("[*] Credential spoofing symbol '@' detected (MALICIOUS).")
            features_dict['tripwire_alert'] = "Critical Threat - Suspicious '@' symbol used to spoof destination."
            return {
                "target_url": target_url, "status": "MALICIOUS", "risk_score_percentage": 99.9, "forensics_report": features_dict
            }
        urlhaus_hits = features_dict.get('urlhaus_hits', 0)
        if urlhaus_hits > 0:
            print(f"[*] URLHaus threat detected ({urlhaus_hits} hits) (MALICIOUS).")
            features_dict['tripwire_alert'] = "Known malicious URL flagged by URLHaus global blocklist."
            return {
                "target_url": target_url, "status": "MALICIOUS", "risk_score_percentage": 99.9, "forensics_report": features_dict
            }
        domain_age = features_dict.get('domain_age_days')
        has_dns = features_dict.get('has_dns', True) 
        
        if (domain_age is not None and domain_age > 600) and has_dns:
            features_dict['tripwire_alert'] = f"Domain is highly established ({domain_age} days old) with no active threat indicators."
            return {
                "target_url": target_url, "status": "BENIGN", "risk_score_percentage": 0.0, "forensics_report": features_dict
            }
        ml_features = {k: v for k, v in features_dict.items() if k not in ['url', 'domain', 'domain_age_days', 'vt_malicious_votes', 'typosquat_target']}
        clean_features = {}
        for key, value in ml_features.items():
            if value is None:
                clean_features[key] = -1.0 
            elif isinstance(value, bool):
                clean_features[key] = int(value) 
            else:
                clean_features[key] = float(value)
        features_df = pd.DataFrame([clean_features])
        if hasattr(ml_model, 'feature_names_in_'):
            features_df = features_df.reindex(columns=ml_model.feature_names_in_, fill_value=-1.0)
        prediction = ml_model.predict(features_df)[0]
        probabilities = ml_model.predict_proba(features_df)[0]
        risk_score = float(round(probabilities[1]*100,2))
        domain_age = features_dict.get('domain_age_days')
        has_dns = features_dict.get('has_dns', True)
        if domain_age is not None and domain_age > 600 and has_dns:
            trust_multiplier = 0.4*600.0 / domain_age
            original_score = risk_score
            risk_score = float(round(risk_score * trust_multiplier, 2))
            features_dict['tripwire_alert'] = f"Trust Weight Applied: Domain age ({domain_age} days) decayed raw AI score by {round((1-trust_multiplier)*100)}%."
        prediction = int(prediction)
        status = "MALICIOUS" if prediction == 1 else "BENIGN"
        # Overriding the AI
        vt_votes = features_dict.get('vt_malicious_votes', 0)
        spoofed_brand = features_dict.get('typosquat_target',"None")
        # VirusTotal Consensus
        if vt_votes >=2:
            status = "MALICIOUS"
            risk_score = max(risk_score, 99.99)
            features_dict['tripwire_alert'] = f"VirusTotal flagged this with {vt_votes} vendor alerts."
        # Typosquatting Detection 
        if spoofed_brand != "None":
            status = "MALICIOUS"
            risk_score = max(risk_score,95.00)
            features_dict['tripwire_alert'] = f"Typosquatting Detected: Attempt to spoof {spoofed_brand.upper()}."
        return{
            "target_url" : target_url,
            "status" : status,
            "risk_score_percentage" : risk_score,
            "forensics_report" : features_dict
        }
    except Exception as e:
        raise HTTPException(status_code = 500, detail = str(e))
    
@app.get("/")
async def root():
    return {"message": "PhishGuard is Online and Protecting."}
