import time
import requests
from flask import Flask, render_template, request

app = Flask(__name__)

# Function to scan vulnerabilities
def scan_vulnerability(url, payloads, test_func):
    results = []
    for payload in payloads:
        full_url = url + payload
        print(f"Testing URL: {full_url}")  # For debugging
        start = time.time()
        try:
            response = test_func(full_url)
            end = time.time()
            results.append({
                "payload": payload,
                "response": response.text[:100],
                "time_taken": round(end - start, 2),
                "severity": "High",
                "error": None,
                "worked": True if "error" in response.text.lower() or "alert" in response.text.lower() else False
            })
        except requests.exceptions.RequestException as e:
            end = time.time()
            results.append({
                "payload": payload,
                "response": "",
                "time_taken": round(end - start, 2),
                "severity": "High",
                "error": str(e),
                "worked": False
            })
    return results

# Route to home page
@app.route('/')
def home():
    return render_template('index.html')

# Route for scanning individual vulnerabilities
@app.route('/scan', methods=['POST'])
def scan():
    url = request.form.get('url')
    vuln = request.form.get('vulnerability')

    if not url or not vuln:
        return "Error: Missing URL or vulnerability type", 400

    if not url.startswith("http"):
        url = "http://" + url

    results = []

    if vuln == "SQL Injection":
        payloads = ["' OR '1'='1", "' OR 'a'='a", "'; DROP TABLE users; --", "' OR 1=1 --", "1' OR 1=1 --"]
        results = scan_vulnerability(url, payloads, lambda u: requests.get(u))
    elif vuln == "Cross-Site Scripting (XSS)":
        payloads = ["<script>alert(1)</script>", "\"><script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>", "<svg/onload=alert(1)>", "<a href='javascript:alert(1)'>XSS</a>"]
        results = scan_vulnerability(url, payloads, lambda u: requests.get(u))
    elif vuln == "Server-Side Request Forgery (SSRF)":
        payloads = ["http://127.0.0.1:80", "http://localhost:80", "http://169.254.169.254/latest/meta-data", "http://example.com", "ftp://127.0.0.1"]
        results = scan_vulnerability(url, payloads, lambda u: requests.get(u))
    elif vuln == "Open Redirect":
        payloads = ["http://evil.com", "https://evil.com", "http://www.evil.com", "https://www.evil.com", "http://redirect-to.com"]
        results = scan_vulnerability(url, payloads, lambda u: requests.get(u, allow_redirects=False))
    elif vuln == "Command Injection":
        payloads = ["test; ls", "test && whoami", "test | ls", "echo test && id", "id; ls"]
        results = scan_vulnerability(url, payloads, lambda u: requests.get(u))
    elif vuln == "Path Traversal":
        payloads = ['../../../../etc/passwd', '../../../windows/win.ini', '/../etc/passwd', '/..//..//..//etc/passwd', '..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts']
        results = scan_vulnerability(url, payloads, lambda u: requests.get(u))
    elif vuln == "All":
        all_results = []
        all_results.extend(scan_vulnerability(url, ["' OR '1'='1", "' OR 'a'='a", "'; DROP TABLE users; --", "' OR 1=1 --", "1' OR 1=1 --"], lambda u: requests.get(u)))
        all_results.extend(scan_vulnerability(url, ["<script>alert(1)</script>", "\"><script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>", "<svg/onload=alert(1)>", "<a href='javascript:alert(1)'>XSS</a>"], lambda u: requests.get(u)))
        all_results.extend(scan_vulnerability(url, ["http://127.0.0.1:80", "http://localhost:80", "http://169.254.169.254/latest/meta-data", "http://example.com", "ftp://127.0.0.1"], lambda u: requests.get(u)))
        all_results.extend(scan_vulnerability(url, ["http://evil.com", "https://evil.com", "http://www.evil.com", "https://www.evil.com", "http://redirect-to.com"], lambda u: requests.get(u, allow_redirects=False)))
        all_results.extend(scan_vulnerability(url, ["test; ls", "test && whoami", "test | ls", "echo test && id", "id; ls"], lambda u: requests.get(u)))
        all_results.extend(scan_vulnerability(url, ['../../../../etc/passwd', '../../../windows/win.ini', '/../etc/passwd', '/..//..//..//etc/passwd', '..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts'], lambda u: requests.get(u)))
        results = all_results
    else:
        return "Invalid vulnerability type", 400

    return render_template("results.html", results=results)

if __name__ == '__main__':
    app.run(debug=True)
