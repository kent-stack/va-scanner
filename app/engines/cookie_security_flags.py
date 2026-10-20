import requests
from datetime import datetime

def run_cookie_scan(target_url: str, cookies: dict= None, proxies: dict=None, verify_ssl: bool=True) -> list:
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url

    cookie_findings = []
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        response = requests.head(target_url, timeout=10, headers={"User-Agent": "CookieSecurityAuditBot/1.0"}, cookies=cookies, proxies=proxies,
            verify=verify_ssl,
            allow_redirects=True)
    
        if not response.cookies:
            return cookie_findings

        for cookie in response.cookies:
            cookie_name = cookie.name
            
            if not cookie.secure:
                cookie_findings.append({
                    "timestamp": timestamp,
                    "target": target_url,
                    "issue": f"Insecure Cookie Flag: '{cookie_name}' missing 'Secure'",
                    "severity": "Medium",
                    "cvss_score": 5.3,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    "desc": f"Cookie '{cookie_name}' dikirim tanpa flag Secure, sehingga rentan disadap melalui jaringan HTTP yang tidak terenkripsi.",
                    "remediation": f"Tambahkan atribut 'Secure' pada cookie '{cookie_name}' agar hanya dikirim melalui jalur HTTPS."
                })

            rest_attrs = {k.lower(): v for k, v in getattr(cookie, '_rest', {}).items()}
            if 'httponly' not in rest_attrs:
                cookie_findings.append({
                    "timestamp": timestamp,
                    "target": target_url,
                    "issue": f"Insecure Cookie Flag: '{cookie_name}' missing 'HttpOnly'",
                    "severity": "Medium",
                    "cvss_score": 5.0,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                    "desc": f"Cookie '{cookie_name}' tidak memiliki flag HttpOnly, sehingga dapat dibaca atau dicuri oleh skrip berbahaya sisi klien (XSS).",
                    "remediation": f"Tambahkan atribut 'HttpOnly' pada cookie '{cookie_name}' untuk memblokir akses skrip JavaScript terhadap cookie sesi."
                })

            samesite_val = rest_attrs.get('samesite')
            if not samesite_val:
                cookie_findings.append({
                    "timestamp": timestamp,
                    "target": target_url,
                    "issue": f"Missing Cookie Attribute: '{cookie_name}' missing 'SameSite'",
                    "severity": "Low",
                    "cvss_score": 4.3,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                    "desc": f"Cookie '{cookie_name}' tidak mendefinisikan atribut SameSite, meningkatkan risiko eksploitasi Cross-Site Request Forgery (CSRF).",
                    "remediation": f"Konfigurasikan atribut SameSite menjadi 'Lax' atau 'Strict' pada cookie '{cookie_name}'."
                })

    except requests.exceptions.RequestException as e:
        cookie_findings.append({
        "timestamp": timestamp,
        "target": target_url,
        "issue": "Cookie Scan Connection Failure",
        "severity": "High",
        "cvss_score": 7.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "description": f"Gagal mengakses target saat melakukan audit cookie. Error: {str(e)}", # Ubah 'desc' menjadi 'description'
        "remediation": "Pastikan URL target aktif dan dapat dijangkau."
    })

    return cookie_findings