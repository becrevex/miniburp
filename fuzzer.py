#!/usr/bin/env python3
"""Simple payload fuzzer for injection testing (SQLi, XSS, etc.)."""
import requests
import time
import json

def load_payloads(file_path="payloads.txt"):
    with open(file_path) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

def fuzz_request(base_url, method="GET", params=None, data=None, headers=None, payloads=None, param_to_fuzz=None):
    if payloads is None:
        payloads = load_payloads()
    if param_to_fuzz is None:
        param_to_fuzz = list((params or data or {}).keys())[0] if (params or data) else None

    results = []
    for payload in payloads:
        test_params = (params or {}).copy()
        test_data = (data or {}).copy()

        if param_to_fuzz:
            if params:
                test_params[param_to_fuzz] = payload
            else:
                test_data[param_to_fuzz] = payload

        try:
            if method.upper() == "POST":
                r = requests.post(base_url, data=test_data, headers=headers, timeout=10, verify=False)
            else:
                r = requests.get(base_url, params=test_params, headers=headers, timeout=10, verify=False)

            results.append({
                "payload": payload,
                "status": r.status_code,
                "length": len(r.text),
                "indicators": any(x in r.text.lower() for x in ["error", "sql", "exception", "syntax"])
            })
            print(f"Payload: {payload[:50]}... → Status: {r.status_code} | Len: {len(r.text)}")
            time.sleep(0.2)
        except Exception as e:
            print(f"Error with payload {payload}: {e}")

    return results

# Example usage
if __name__ == "__main__":
    # Capture a request in MiniBurp/mitmweb → export or hardcode here
    base = "http://example.com/search"
    fuzz_request(base, method="GET", params={"q": "test"}, param_to_fuzz="q")
