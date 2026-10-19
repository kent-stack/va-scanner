import requests
from datetime import datetime

INFORMATION_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version"]
CACHE_HEADERS = ["Cache-Control", "Pragma", "ETag", "Last-Modified", "Expires"]

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "High", 
        "cvss_score": 6.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "desc": "Mencegah serangan XSS dan data injection.",
        "remediation": "Tambahkan header Content-Security-Policy pada server (contoh: Header set Content-Security-Policy \"default-src 'self'\")."
    },
    "X-Frame-Options": {
        "severity": "Medium", 
        "cvss_score": 4.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "desc": "Mencegah serangan Clickjacking.",
        "remediation": "Atur header X-Frame-Options menjadi SAMEORIGIN atau DENY pada konfigurasi Web Server (Nginx/Apache)."
    },
    "X-Content-Type-Options": {
        "severity": "Low", 
        "cvss_score": 3.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "desc": "Mencegah MIME type sniffing.",
        "remediation": "Tambahkan header X-Content-Type-Options: nosniff."
    },
    "Strict-Transport-Security": {
        "severity": "High", 
        "cvss_score": 7.4,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "desc": "Memaksa koneksi aman HTTPS (HSTS).",
        "remediation": "Aktifkan HSTS dengan menambahkan header Strict-Transport-Security: max-age=31536000; includeSubDomains."
    },
    "Referrer-Policy": {
        "severity": "Info", 
        "cvss_score": 2.6,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "desc": "Mengontrol informasi referrer saat navigasi.",
        "remediation": "Konfigurasikan header Referrer-Policy (misal: strict-origin-when-cross-origin)."
    },
    "Permissions-Policy": {
        "severity": "Low", 
        "cvss_score": 3.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "desc": "Mengontrol fitur browser yang diizinkan (kamera, lokasi, dll).",
        "remediation": "Tentukan kebijakan izin fitur browser menggunakan header Permissions-Policy."
    }
}

def run_custom_scan(target_url: str, cookies: dict = None, proxies: dict = None, verify_ssl: bool = True) -> dict:
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    findings = []
    present_headers = {}
    information_disclosure = {}
    caching_headers = {}
    final_url = target_url

    try:
        response = requests.head(
            target_url, 
            timeout=10, 
            headers={"User-Agent": "SecurityHeaderAuditBot/1.0"},
            cookies=cookies,
            proxies=proxies,
            verify=verify_ssl,
            allow_redirects=True
        )
        
        final_url = response.url
        response_headers = {k.lower(): v for k, v in response.headers.items()}

        target_sec_headers = dict(SECURITY_HEADERS)
        if "content-security-policy" in response_headers and "frame-ancestors" in response_headers.get("content-security-policy").lower():
            target_sec_headers.pop("X-Frame-Options", None)

        for header, info in target_sec_headers.items():
            lheader = header.lower()
            if lheader in response_headers:
                val = response_headers[lheader]
                present_headers[header] = val

                if lheader == 'strict-transport-security' and "max-age=0" in val.lower():
                    findings.append({
                        "timestamp": timestamp,
                        "target": final_url,
                        "issue": f"Insecure Header Value: {header}",
                        "severity": "Medium",
                        "cvss_score": 5.3,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                        "description": f"Header {header} diatur dengan max-age=0, yang menonaktifkan fungsi HSTS.",
                        "remediation": "Perbarui durasi max-age menjadi minimal 1 tahun (contoh: max-age=31536000)."
                    })
            else:
                if lheader == 'strict-transport-security' and not final_url.startswith('https://'):
                    continue

                findings.append({
                    "timestamp": timestamp,
                    "target": final_url,
                    "issue": f"Missing Security Header: {header}",
                    "severity": info["severity"],
                    "cvss_score": info["cvss_score"],
                    "cvss_vector": info["cvss_vector"],
                    "description": info["desc"],
                    "remediation": info["remediation"] 
                })

        for info in INFORMATION_HEADERS:
            linfo = info.lower()
            if linfo in response_headers:
                information_disclosure[info] = response_headers[linfo]

        for cache in CACHE_HEADERS:
            lcache = cache.lower()
            if lcache in response_headers:
                caching_headers[cache] = response_headers[lcache]

    except requests.exceptions.SSLError as e:
        findings.append({
            "timestamp": timestamp,
            "target": target_url,
            "issue": "SSL/TLS Error",
            "severity": "High",
            "cvss_score": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "description": f"Terjadi kesalahan sertifikat SSL/TLS saat mencoba mengakses target. Error: {str(e)}",
            "remediation": "Periksa sertifikat SSL/TLS target, pastikan valid, tidak kedaluwarsa, atau atur parameter verify_ssl=False jika di lingkungan development."
        })
        
    except requests.exceptions.RequestException as e:
        findings.append({
            "timestamp": timestamp,
            "target": target_url,
            "issue": "Connection Failure",
            "severity": "Critical",
            "cvss_score": 9.0,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "description": f"Gagal terhubung ke target. Error: {str(e)}",
            "remediation": "Periksa kembali koneksi internet, pastikan URL aktif, atau cek apakah target dilindungi WAF/firewall."
        })

    return {
        "target": target_url,
        "final_url": final_url,
        "findings": findings,
        "present_headers": present_headers,
        "information_disclosure": information_disclosure,
        "caching_headers": caching_headers
    }