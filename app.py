import base64, os, time
from ai_rules import analyze_local
from database import get_cache, save_cache, add_live, get_live as get_live_db
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
import requests

from ai_service import explain_with_ai
from ai_client import chat_with_tamman # <-- أضفنا الشات

app = FastAPI(title="طَمّن AI Global")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

VT_API_KEY = os.getenv("VT_API_KEY")

def mask_url(u):
    c = u.replace('https://','').replace('http://','').replace('www.','')
    return c[:6]+"****"+c[-4:] if len(c)>12 else c[:2]+"****"

class URLCheck(BaseModel):
    url: str

def check_virustotal(url_to_scan: str):
    if not VT_API_KEY:
        return 0, 0
    try:
        headers = {"x-apikey": VT_API_KEY}
        url_id = base64.urlsafe_b64encode(url_to_scan.encode()).decode().strip("=")
        res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=15)
        if res.status_code == 429:
            return 0, 0
        if res.status_code == 200:
            stats = res.json()['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious',0)+stats.get('suspicious',0)
            return malicious, sum(stats.values())
        time.sleep(2)
        res = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url_to_scan}, timeout=15)
        if res.status_code == 429 or res.status_code!= 200:
            return 0,0
        analysis_id = res.json()['data']['id']
        time.sleep(6)
        report = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers, timeout=15).json()
        stats = report['data']['attributes']['stats']
        return stats.get('malicious',0)+stats.get('suspicious',0), sum(stats.values())
    except Exception as e:
        print(f"VT error: {e}")
        return 0,0

@app.get("/")
def serve_index():
    return FileResponse("index.html")

@app.get("/api/live")
def get_live():
    return get_live_db()

@app.get("/api")
def home():
    return {"status":"Tamman AI + Saudi AI Section + Chat ✅"}

@app.post("/check")
def check_url(data: URLCheck):
    url_raw = data.url.strip()
    cached = get_cache(url_raw)
    if cached:
        add_live(mask_url(url_raw), url_raw, cached["is_phishing"])
        return cached

    score, reasons, is_phishing_local = analyze_local(url_raw)
    vt_malicious, vt_total = check_virustotal(url_raw)
    vt_str = f"{vt_malicious}/{vt_total}"

    # التعديل المهم: كان عندك > 3 صارت >= 3
    if vt_malicious >= 3:
        score += 50
        reasons.append(f"VirusTotal كشفه ({vt_malicious}/{vt_total})")
        is_phishing_local = True

    is_phishing = is_phishing_local or score >= 45
    ai_data = explain_with_ai(url_raw, score, reasons if reasons else ["لا يوجد مؤشرات"], vt_str)

    result = {
        "url": url_raw,
        "is_phishing": is_phishing,
        "score": min(score, 100),
        "risk": "عالي 🔴" if is_phishing else "آمن 🟢",
        "reasons": reasons if reasons else ["لا يوجد مؤشرات تصيد"],
        "virustotal": {"malicious": vt_malicious, "total": vt_total},
        "ai_analysis": ai_data,
        "time": time.time()
    }

    save_cache(url_raw, result)
    add_live(mask_url(url_raw), url_raw, is_phishing)
    return result

# --- هذا هو قسم الشات الجديد ---
@app.post("/ai-chat")
def ai_chat_endpoint(data: dict):
    message = data.get("message", "")
    history = data.get("history", [])
    if not message.strip():
        return {"reply": "اكتب شي طيب 😅"}
    reply = chat_with_tamman(message, history)
    return {"reply": reply}
