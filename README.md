# 🛡️ PhishGuard AI: Real-Time Threat Intelligence Pipeline

## 📖 Project Overview

PhishGuard AI is an advanced, decoupled threat intelligence platform designed to analyze and classify malicious URLs in real-time. At its core, the system acts as an automated Security Operations Center (SOC). It provides security analysts with a live React-based telemetry dashboard that visualizes network threats, while a highly optimized Python/FastAPI backend handles the heavy computational lifting. 

By combining lexical URL analysis, live DNS/WHOIS forensics, and global threat intelligence (like URLHaus), PhishGuard acts as a comprehensive shield against zero-day phishing attacks, credential spoofing, and malicious infrastructure.

---


## 🛑 The Problem & The PhishGuard Solution

Traditional machine learning models in cybersecurity suffer from a critical flaw: they are computationally expensive and treat trust as a binary outcome. Feeding every single network request into an XGBoost model—including dead domains or globally trusted sites like Google—creates massive latency and wastes CPU resources. Furthermore, standard models struggle to adapt to the nuance of domain age; they either block a site or they don't, lacking the ability to dynamically weight their suspicion.

**PhishGuard solves this by introducing a Waterfall Heuristic Pipeline and a Continuous Trust Decay Engine.** Rather than relying purely on the AI, the architecture filters traffic through sequential, highly optimized layers to handle obvious threats and trusted traffic before the machine learning model is ever invoked.

* **The $O(1)$ Global Gatekeeper:** Incoming telemetry is first checked against an in-memory hash set of the Tranco Top 100k Global Allowlist. Legitimate enterprise domains bypass the AI entirely in $O(1)$ time, instantly returning a 0.0% risk score and saving vital compute resources.
* **Pre-ML Malicious Heuristics:** The engine uses targeted regular expressions (Regex) to catch rudimentary but critical threats. If a URL uses a bare IP address (e.g., `192.168.1.1`), attempts credential spoofing via the `@` symbol, or triggers a URLHaus blocklist hit, it is immediately flagged as a 99.9% critical threat without wasting ML processing power.
* **XGBoost ML Classification:** URLs that pass the gatekeepers are processed by a custom `URLForensicsEngine` which extracts lexical, structural, and network features. Missing data from dead domains is sanitized into integers, and the matrix is evaluated by a trained XGBoost model to return a probabilistic risk score.
---

## ⚙️ Architecture & Tech Stack

The platform is completely decoupled, ensuring the frontend UI remains blisteringly fast regardless of the backend's computational load.

### Frontend (SOC Dashboard)
* **Framework:** React 18 powered by Vite for instant hot-module replacement and optimized builds.
* **Styling:** Tailwind CSS V4 for a responsive, enterprise-grade dark mode interface.
* **Data Visualization:** Recharts for rendering real-time threat distribution metrics.
* **Communication:** Asynchronous JavaScript `fetch` API bridging to the Python backend.

### Backend (Intelligence API)
* **Framework:** FastAPI running on Uvicorn, providing high-performance, asynchronous endpoints.
* **Machine Learning:** XGBoost classification model trained on a comprehensive dataset of phishing indicators. 
* **Data Processing:** Pandas and Joblib for matrix serialization, alongside custom Python data sanitizers to translate missing WHOIS/RDAP data from dead domains into stable numerical inputs for the AI.

---

## 🚀 Local Deployment & Quick Start

To run the PhishGuard AI pipeline locally, you will need to boot both the backend API and the frontend dashboard.

### 1. Clone the Repository
```bash
git clone [https://github.com/yourusername/PhishGuard.git](https://github.com/yourusername/PhishGuard.git)
cd PhishGuard# 🛡️ PhishGuard AI: Real-Time Threat Intelligence Pipeline

![Python](https://img.shields.io/badge/Python-FastAPI-3776AB?logo=python&logoColor=white)
![React](https://img.shields.io/badge/React-Vite-61DAFB?logo=react&logoColor=black)
![XGBoost](https://img.shields.io/badge/Machine_Learning-XGBoost-F37626?logo=xgboost)
![License](https://img.shields.io/badge/License-MIT-green)

> **[Insert a screenshot of your beautiful Tailwind V4 dashboard here]**

## 📖 Project Overview

PhishGuard AI is an advanced, decoupled threat intelligence platform designed to analyze and classify malicious URLs in real-time. At its core, the system acts as an automated Security Operations Center (SOC). It provides security analysts with a live React-based telemetry dashboard that visualizes network threats, while a highly optimized Python/FastAPI backend handles the heavy computational lifting. 

By combining lexical URL analysis, live DNS/WHOIS forensics, and global threat intelligence (like URLHaus), PhishGuard acts as a comprehensive shield against zero-day phishing attacks, credential spoofing, and malicious infrastructure.

---

## 🛑 The Problem & The PhishGuard Solution

Traditional machine learning models in cybersecurity suffer from a critical flaw: they are computationally expensive and treat trust as a binary outcome. Feeding every single network request into an XGBoost model—including dead domains or globally trusted sites like Google—creates massive latency and wastes CPU resources. Furthermore, standard models struggle to adapt to the nuance of domain age; they either block a site or they don't, lacking the ability to dynamically weight their suspicion.

**PhishGuard solves this by introducing a Waterfall Heuristic Pipeline and a Continuous Trust Decay Engine.** Rather than relying purely on the AI, the architecture filters traffic through sequential, highly optimized layers to handle obvious threats and trusted traffic before the machine learning model is ever invoked.

* **The $O(1)$ Global Gatekeeper:** Incoming telemetry is first checked against an in-memory hash set of the Tranco Top 100k Global Allowlist. Legitimate enterprise domains bypass the AI entirely in $O(1)$ time, instantly returning a 0.0% risk score and saving vital compute resources.
* **Pre-ML Malicious Heuristics:** The engine uses targeted regular expressions (Regex) to catch rudimentary but critical threats. If a URL uses a bare IP address (e.g., `192.168.1.1`), attempts credential spoofing via the `@` symbol, or triggers a URLHaus blocklist hit, it is immediately flagged as a 99.9% critical threat without wasting ML processing power.
* **Continuous Trust Decay:** For URLs that require AI analysis, PhishGuard does not blindly accept the raw XGBoost risk score. If a domain has a verified DNS record and is older than 600 days, the engine applies a mathematical decay curve: `Trust Multiplier = 0.4 * (600 / Domain Age)`. This allows the AI to be highly sensitive to newly registered "burner" domains while gracefully scaling back its risk assessment for deeply established infrastructure.

---

## ⚙️ Architecture & Tech Stack

The platform is completely decoupled, ensuring the frontend UI remains blisteringly fast regardless of the backend's computational load.

### Frontend (SOC Dashboard)
* **Framework:** React 18 powered by Vite for instant hot-module replacement and optimized builds.
* **Styling:** Tailwind CSS V4 for a responsive, enterprise-grade dark mode interface.
* **Data Visualization:** Recharts for rendering real-time threat distribution metrics.
* **Communication:** Asynchronous JavaScript `fetch` API bridging to the Python backend.

### Backend (Intelligence API)
* **Framework:** FastAPI running on Uvicorn, providing high-performance, asynchronous endpoints.
* **Machine Learning:** XGBoost classification model trained on a comprehensive dataset of phishing indicators. 
* **Data Processing:** Pandas and Joblib for matrix serialization, alongside custom Python data sanitizers to translate missing WHOIS/RDAP data from dead domains into stable numerical inputs for the AI.

---

## 🚀 Local Deployment & Quick Start

To run the PhishGuard AI pipeline locally, you will need to boot both the backend API and the frontend dashboard.
