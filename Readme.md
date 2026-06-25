# MiniBurp

A minimized, modular Python-based intercepting proxy — a lightweight clone of Burp Suite built on top of [mitmproxy](https://mitmproxy.org/). MiniBurp provides just enough core functionality to effectively test the OWASP Top 10 while remaining lightweight and extensible.

---

## Key Features

### Proxy & Interception
- Full HTTP/HTTPS MITM proxy
- Intercept, view, edit, forward, or drop requests and responses
- Built-in flow history — view all captured traffic
- Full TLS interception (certificate generation handled by mitmproxy)

### Repeater
- Edit any captured flow and replay it manually or in batch via the UI or console

### Intruder / Fuzzing
- Manual editing and replay in the UI
- Separate automated fuzzer script (`fuzzer.py`) for payload injection — SQLi, XSS, command injection, and more

### Passive Scanner
Automatically checks for common issues including:
- Missing security headers
- Insecure cookies
- Potential information disclosure

Directly supports coverage of Security Misconfiguration, Cryptographic Failures, Broken Access Control, and related OWASP Top 10 categories.

### Active Testing
- Modify requests on-the-fly for injection testing, access control bypass, SSRF, and more

---

## Architecture & Modularity

| Layer | Description |
|---|---|
| **Core** | `mitmproxy` — handles proxying, TLS, and the web UI |
| **Addons** | Everything else is Python addon modules (classes) |
| **Config** | `spec.json` controls which modules are enabled and their configuration |

The built-in `mitmweb` web UI provides a Burp-like experience — flows list, request/response viewers, edit and replay.

### Adding New Capabilities

1. Create a new addon class with `request()` or `response()` methods
2. Enable it in `spec.json` under `enabled_modules`
3. Instantiate it and call `master.addons.add(...)` in `miniburp.py`

That's it — fully modular, extremely easy to extend.

---

## Usage

```bash
python miniburp.py
```

1. Open the mitmweb UI in your browser: `http://127.0.0.1:8081`
2. Configure your browser (or FoxyProxy) to use proxy `127.0.0.1:8080`
3. Browse the target application — traffic appears in mitmweb
4. **Intercept / Modify** — click any flow → Edit → Replay
5. **Passive alerts** appear in the terminal and are stored in flow metadata
6. **History** — all flows are saved and logged to file

### Automated Fuzzing

Use `fuzzer.py` with a captured request template for automated payload injection.

```bash
python fuzzer.py
```

---

## OWASP Top 10 Coverage

| Capability | OWASP Categories Addressed |
|---|---|
| Passive Scanner | Security Misconfiguration, Cryptographic Failures, Broken Access Control |
| Intercept & Edit | Injection, Broken Access Control, SSRF |
| Fuzzer | Injection (SQLi, XSS, Command Injection) |
| HTTPS Interception | Cryptographic Failures, Insecure Design |
| Flow History & Replay | Insecure Design, Security Logging & Monitoring Failures |
