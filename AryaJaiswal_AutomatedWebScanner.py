"""
Automated Web Security Header & CORS Auditor
Use only on websites you own or have explicit permission to assess.
This tool makes one normal HTTP GET request and reports common configuration signals.
It does not exploit vulnerabilities or prove that a site is vulnerable.
"""
import argparse
from urllib.parse import urlparse
import requests

SECURITY_HEADERS = {
    "strict-transport-security": "Helps enforce HTTPS in supporting browsers.",
    "content-security-policy": "Helps reduce certain content-injection risks.",
    "x-content-type-options": "Should usually be set to nosniff.",
    "x-frame-options": "Can help prevent clickjacking in older browser contexts.",
    "referrer-policy": "Controls how much referrer information is sent.",
    "permissions-policy": "Restricts use of selected browser features.",
}

def normalize_url(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("Please enter a valid http:// or https:// URL.")
    return url

def audit(url, timeout=10):
    url = normalize_url(url)
    headers = {"User-Agent": "Educational-Web-Security-Auditor/1.0"}
    result = {"url": url, "status_code": None, "final_url": None,
              "https": urlparse(url).scheme == "https", "headers": {},
              "cors": {}, "errors": []}
    try:
        response = requests.get(url, headers=headers, timeout=timeout,
                                allow_redirects=True)
        result["status_code"] = response.status_code
        result["final_url"] = response.url
        response_headers = {k.lower(): v.strip()
                            for k, v in response.headers.items()}
        for header, description in SECURITY_HEADERS.items():
            result["headers"][header] = {
                "present": header in response_headers,
                "value": response_headers.get(header, ""),
                "description": description
            }

        # A single, harmless CORS observation using a test Origin.
        # This is a signal only; it does not establish exploitability.
        cors_headers = {"Origin": "https://example.com",
                        "User-Agent": headers["User-Agent"]}
        cors_response = requests.get(url, headers=cors_headers, timeout=timeout,
                                     allow_redirects=True, stream=True)
        cors = {k.lower(): v.strip()
                for k, v in cors_response.headers.items()}
        cors_response.close()
        allow_origin = cors.get("access-control-allow-origin", "")
        allow_credentials = cors.get("access-control-allow-credentials", "").lower()
        result["cors"] = {
            "test_origin": "https://example.com",
            "access_control_allow_origin": allow_origin or "(not returned)",
            "access_control_allow_credentials": allow_credentials or "(not returned)",
            "wildcard_origin": allow_origin == "*",
            "wildcard_with_credentials_signal": allow_origin == "*" and allow_credentials == "true"
        }
    except requests.RequestException as exc:
        result["errors"].append(str(exc))
    return result

def print_report(result):
    print("\\n=== Automated Web Security Audit ===")
    print("URL:", result["url"])
    print("Final URL:", result["final_url"] or "Not available")
    print("HTTP status:", result["status_code"] if result["status_code"] is not None else "Not available")
    print("HTTPS:", "Yes" if result["https"] else "NO - consider HTTPS")
    print("\\nSecurity headers:")
    for name, info in result["headers"].items():
        status = "PRESENT" if info["present"] else "MISSING"
        print(f"- {name}: {status}")
        if info["present"]:
            print(f"  Value: {info['value']}")
    if result["cors"]:
        print("\\nCORS observation (test Origin: https://example.com):")
        for key, value in result["cors"].items():
            print(f"- {key}: {value}")
        if result["cors"]["wildcard_with_credentials_signal"]:
            print("  NOTE: Review this configuration manually; browser behavior and server details matter.")
    if result["errors"]:
        print("\\nErrors:")
        for error in result["errors"]:
            print("-", error)
    print("\\nLimitations: This is a basic configuration check, not a penetration test.")
    print("A missing header is not automatically a confirmed vulnerability.")

def main():
    parser = argparse.ArgumentParser(
        description="Check common web security headers and observe CORS response headers.")
    parser.add_argument("url", help="Website URL you own or are authorized to test")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    args = parser.parse_args()
    if args.timeout < 1:
        parser.error("--timeout must be at least 1 second")
    print_report(audit(args.url, args.timeout))

if __name__ == "__main__":
    main()
