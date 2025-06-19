# LiveRefXSS Project: Real-Time XSS Vulnerability Detection via Bidirectional HTTP Traffic

This repository contains the prototype implementation and evaluation artifacts for **LiveRefXSS**, a research tool that detects exploitable Cross-Site Scripting (XSS) vulnerabilities by analyzing real-time HTTP traffic.

Unlike traditional scanners or Web Application Firewalls (WAFs), LiveRefXSS confirms **actual exploitability** by identifying reflected input in **executable contexts**—such as `<script>` tags or inline JavaScript events—directly from live request/response flows.

## 🚀 How to Use

1. **Run the LiveRefXSS Proxy**
   Set up the proxy between your scanner (e.g., Burp Suite) and the target application:

```bash
python mimiproxy.py --listen 127.0.0.1:8080 --target https://public-firing-range.appspot.com -s LiveRefXSS.py
```

2. **Configure Burp Suite**
   * Set Burp Suite to use `http://127.0.0.1:8080` as an upstream proxy.
   * Launch an **Active Scan** on [https://public-firing-range.appspot.com](https://public-firing-range.appspot.com) or any vulnerable test app.
    
3. **Analyze Traffic**
   * `LiveRefXSS.py` will log all reflected inputs that appear in executable contexts.
   * Detected vulnerabilities are saved to `xss-report.log` with timestamps and context annotations.
