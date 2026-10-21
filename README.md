# Automated Web Security Header & CORS Auditor

**Project type:** Educational cybersecurity project  
**Author:** Arya Jaiswal

## Project description
This Python command-line tool checks a website response for six commonly used security headers and makes a simple CORS observation using the test Origin `https://example.com`. It prints a readable report including the HTTP status, HTTPS use, headers present/missing, and selected CORS response values.

**Safety:** Only run this against a website you own or have explicit permission to assess. The tool sends ordinary HTTP GET requests; it does not exploit a vulnerability.

## Technologies used
- Python 3
- `requests` library
- HTTP response headers and basic CORS concepts

## Dataset
No dataset is required. The program checks a live URL supplied by the user. For learning/reference:
- MDN HTTP headers: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers
- OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
- MDN CORS: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS

## Setup
1. Install Python 3.10 or newer.
2. Open a terminal in this project folder.
3. (Recommended) Create and activate a virtual environment:
   - Windows: `python -m venv .venv` then `.venv\Scripts\activate`
   - macOS/Linux: `python3 -m venv .venv` then `source .venv/bin/activate`
4. Install dependencies:
   `pip install -r requirements.txt`

## Run
```bash
python AryaJaiswal_AutomatedWebScanner.py https://example.org
```
Replace `https://example.org` with a site you own or are authorized to test. You may set a timeout:
```bash
python AryaJaiswal_AutomatedWebScanner.py https://example.org --timeout 15
```

## Files
- `AryaJaiswal_AutomatedWebScanner.py` — complete Python source code
- `requirements.txt` — Python dependency list
- `AryaJaiswal_AutomatedWebScanner.ipynb` — notebook version of the code
- `AryaJaiswal_ProjectReport.docx` — project report

## Interpretation and limitations
A missing header is a hardening recommendation, not proof of a vulnerability. CORS behavior depends on the endpoint, browser, authentication, and application logic. The test Origin is only a basic observation. Review results manually and obtain authorization before testing.

## GitHub repository
Create a new public or private repository on https://github.com/new, for example `Automated-Web-Security-Auditor`, then upload all four files. Do not upload passwords, API keys, or private target data.
