from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

# Mengimpor modul dengan nama file yang baru
from app.engines.security_headers_audit import run_custom_scan
from app.engines.cookie_security_flags import run_cookie_scan

app = FastAPI()

templates = Jinja2Templates(directory="app/templates")

scan_results_history = []

@app.get("/", response_class=HTMLResponse)
async def read_dashboard(request: Request):
    stats = {
        "total_scans": len(scan_results_history),
        "critical": sum(1 for r in scan_results_history if r["severity"] == "Critical"),
        "high": sum(1 for r in scan_results_history if r["severity"] == "High"),
        "medium": sum(1 for r in scan_results_history if r["severity"] == "Medium"),
        "low": sum(1 for r in scan_results_history if r["severity"] in ["Low", "Info"])
    }
    return templates.TemplateResponse(request, "dashboard.html", {
        "stats": stats,
        "results": scan_results_history
    })

@app.post("/start-scan", response_class=HTMLResponse)
async def start_scan(request: Request, target_url: str = Form(...)):
    # 1. Jalankan pemindaian Security Headers dari file baru
    header_result = run_custom_scan(target_url)

    header_findings = header_result.get("findings", [])
    
    # 2. Jalankan pemindaian Cookie Security Flags
    cookie_findings = run_cookie_scan(target_url)
    
    # Gabungkan semua temuan
    all_findings = header_findings + cookie_findings
    
    for finding in all_findings:
        scan_results_history.insert(0, finding)
        
    stats = {
        "total_scans": len(scan_results_history),
        "critical": sum(1 for r in scan_results_history if r["severity"] == "Critical"),
        "high": sum(1 for r in scan_results_history if r["severity"] == "High"),
        "medium": sum(1 for r in scan_results_history if r["severity"] == "Medium"),
        "low": sum(1 for r in scan_results_history if r["severity"] in ["Low", "Info"])
    }
    
    return templates.TemplateResponse(request, "dashboard.html", {
        "stats": stats,
        "results": scan_results_history,
        "message": f"Hybrid scan (Headers & Cookies) untuk target '{target_url}' berhasil diselesaikan!"
    })