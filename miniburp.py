#!/usr/bin/env python3
"""
MiniBurp - Minimal Burp Suite clone for OWASP Top 10 testing
Built on mitmproxy. Modular via spec.json.
"""

import json
import logging
import asyncio
from mitmproxy import http, options
from mitmproxy.tools.web import WebMaster

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class RequestLogger:
    """Simple request/response logger (history)."""
    def __init__(self, log_file="miniburp_history.log"):
        self.log_file = log_file

    def response(self, flow: http.HTTPFlow):
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(f"\n{'='*60}\n")
                f.write(f"Time: {flow.request.timestamp_start}\n")
                f.write(f"{flow.request.method} {flow.request.pretty_url}\n")
                f.write(f"Request Headers: {dict(flow.request.headers)}\n")
                if flow.request.content:
                    body = flow.request.content[:1000].decode(errors="ignore")
                    f.write(f"Request Body (truncated): {body}\n")
                if flow.response:
                    f.write(f"Response Status: {flow.response.status_code}\n")
                    f.write(f"Response Headers: {dict(flow.response.headers)}\n")
        except Exception as e:
            logging.error(f"Logger error: {e}")


class PassiveOWASPSanner:
    """Passive scanner for OWASP Top 10 relevant issues."""
    def __init__(self, config):
        self.config = config
        self.sec_headers = config.get("security_headers", [])
        self.check_cookies = config.get("check_cookies", True)

    def response(self, flow: http.HTTPFlow):
        if not flow.response:
            return

        alerts = []

        # Missing security headers (Security Misconfiguration + Crypto)
        if self.config.get("check_security_headers", True):
            for h in self.sec_headers:
                if h not in flow.response.headers:
                    alerts.append(f"Missing: {h}")

        # Insecure cookies (Broken Access Control + Crypto)
        if self.check_cookies and flow.response.cookies:
            for name, cookie in flow.response.cookies.items(multi=True):
                cookie_str = str(cookie).lower()
                if "secure" not in cookie_str and flow.request.scheme == "https":
                    alerts.append(f"Cookie '{name}' missing Secure flag")
                if "httponly" not in cookie_str:
                    alerts.append(f"Cookie '{name}' missing HttpOnly flag")

        # Basic info disclosure / error patterns (Injection / Misconfig)
        if flow.response.content:
            content = flow.response.content.decode(errors="ignore").lower()
            error_patterns = ["sql syntax", "mysql_fetch", "stack trace", "exception", "error in", "warning:"]
            for pattern in error_patterns:
                if pattern in content:
                    alerts.append(f"Potential info disclosure / error message detected")
                    break

        if alerts:
            logging.warning(f"OWASP Alert [{flow.request.pretty_url}]: {alerts}")
            flow.metadata["miniburp_alerts"] = alerts


def main(spec_path="spec.json"):
    with open(spec_path, "r", encoding="utf-8") as f:
        spec = json.load(f)

    proxy = spec.get("proxy", {"host": "127.0.0.1", "port": 8080})
    opts = options.Options(
        listen_host=proxy["host"],
        listen_port=proxy["port"],
    )

    master = WebMaster(opts)

    enabled = spec.get("enabled_modules", [])

    if "request_logger" in enabled:
        log_conf = spec.get("logging", {})
        master.addons.add(RequestLogger(log_conf.get("log_file", "miniburp_history.log")))

    if "passive_owasp_scanner" in enabled:
        pass_conf = spec.get("passive_scanner", {})
        master.addons.add(PassiveOWASPSanner(pass_conf))

    # === Add new modules here ===
    # if "my_new_module" in enabled:
    #     master.addons.add(MyNewAddon(spec.get("my_new_config", {})))

    print(f"\n=== MiniBurp Started ===")
    print(f"Proxy listening on {proxy['host']}:{proxy['port']}")
    print("Web UI: http://127.0.0.1:8081 (default mitmweb port)")
    print("Browser proxy settings: HTTP proxy = 127.0.0.1:8080")
    print("For HTTPS: Install mitmproxy CA certificate (run mitmproxy once or use --set confdir=...)")
    print("Press Ctrl+C to stop.\n")

    asyncio.run(master.run())


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="MiniBurp - Minimal Burp Suite Clone")
    parser.add_argument("--spec", default="spec.json", help="Path to spec.json")
    args = parser.parse_args()
    main(args.spec)
