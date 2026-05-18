from fastapi import FastAPI, HTTPException 
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import pandas as pd
from cti_engine import URLForensicsEngine
import urllib.parse

app = FastAPI(title = "PhishGuard Core API", version = "1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins = ["http://localhost:5173"],
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
        ml_features = {k: v for k, v in features_dict.items() if k not in ['url', 'domain', 'domain_age_days', 'vt_malicious_values', 'typosquat_target']}
        features_df = pd.DataFrame([ml_features])
        prediction = ml_model.predict(features_df)[0]
        probabilities = ml_model.predict_proba(features_df)[0]
        risk_score = float(round(probabilities[1]*100,2))
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
