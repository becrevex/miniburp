MiniBurp is a minimized, modular Python-based intercepting proxy clone of Burp Suite, built on top of the excellent open-source mitmproxy library. It provides just enough core functionality to effectively test the OWASP Top 10 while remaining lightweight and extensible.Key Features (OWASP Top 10 Coverage)Full Proxy + Intercept (like Burp Proxy): HTTP/HTTPS MITM proxy. Intercept, view, edit, forward, or drop requests/responses.
History: Built-in flow history (view all captured traffic).
Repeater (basic): Edit any flow and replay it (manually or in batch via UI/console).
Intruder/Fuzzing (basic): Manual editing + replay in UI; plus a separate automated fuzzer script for payload injection (SQLi, XSS, command injection, etc.).
Passive Scanner: Automatic checks for common issues (missing security headers, insecure cookies, potential info disclosure) — directly helps with Security Misconfiguration, Cryptographic Failures, Broken Access Control, and more.
Active Testing Support: Modify requests on-the-fly for injection, access control bypass, SSRF, etc.
HTTPS Support: Full TLS interception (mitmproxy handles certificate generation).

Built-in mitmweb web UI gives you a Burp-like experience (flows list, request/response viewers, edit/replay).Architecture & ModularityCore = mitmproxy (handles proxying, TLS, UI).
Everything else is addon modules (Python classes).
spec.json controls which modules are enabled and their configuration.
Adding new capabilities/extensions: Add a new addon class + enable it in the spec (or import external scripts). Extremely easy to extend.

How to Use (Like Burp Suite)Run python miniburp.py
Open mitmweb in your browser (http://127.0.0.1:8081)
Configure your browser (or FoxyProxy) to use proxy 127.0.0.1:8080
Browse the target app → traffic appears in mitmweb
Intercept/Modify: Click a flow → Edit → Replay
Passive alerts appear in the terminal (and are stored in flow metadata)
History: All flows saved + logged to file
For automated fuzzing: Use fuzzer.py with a captured request template

Adding New Capabilities / ExtensionsCreate a new class (e.g., class MySSRFChecker: with request() or response() methods).
Add it to enabled_modules in spec.json.
Instantiate and master.addons.add(...) in miniburp.py.
Done — fully modular.

