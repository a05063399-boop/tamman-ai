import base64, os, time, json
from ai_rules import analyze_local, get_gemini_prompt
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
import requests
import google.generativeai as genai

app = FastAPI(title="طَمّن AI Global")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

VT_API_KEY = os.getenv("VT_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    gemini_model = genai.GenerativeModel('gemini-1.5-flash')
else:
    gemini_model = None

DB_FILE = "db.json"
if not os.path.exists(DB_FILE):
    with open(DB_FILE, 'w', encoding='utf-8') as f:
        json.dump({"live": [], "cache": {}}, f)

def read_db():
    try:
        with open(DB_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except:
        return {"live": [], "cache": {}}

def write_db(data):
    with open(DB_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

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
        if res.status_code == 200:
            stats = res.json()['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious',0)+stats.get('suspicious',0)
            return malicious, sum(stats.values())
        res = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url_to_scan}, timeout=15)
        if res.status_code!= 200:
            return 0,0
        analysis_id = res.json()['data']['id']
        time.sleep(5)
        report = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers, timeout=15).json()
        stats = report['data']['attributes']['stats']
        return stats.get('malicious',0)+stats.get('suspicious',0), sum(stats.values())
    except Exception as e:
        print(f"VT error: {e}")
        return 0,0

def get_ai_reply(url, score, reasons, vt_str):
    if not gemini_model:
        return "آمن 🟢" if score < 50 else f"مشبوه 🔴 - {', '.join(reasons[:2])}"
    try:
        prompt = get_gemini_prompt(url, score, reasons, vt_str)
        r = gemini_model.generate_content(prompt)
        return r.text.strip()
    except Exception as e:
        print(f"Gemini error: {e}")
        return "آمن 🟢" if score < 50 else f"مشبوه 🔴 {', '.join(reasons[:2])}"

@app.get("/")
def serve_index():
    return FileResponse("index.html")

@app.get("/api/live")
def get_live():
    db = read_db()
    db["live"] = [x for x in db["live"] if time.time() - x["time"] < 60][:5]
    write_db(db)
    return db["live"]

@app.get("/api")
def home():
    return {"status":"Tamman AI + Local Rules ✅"}

@app.post("/check")
def check_url(data: URLCheck):
    url_raw = data.url.strip()
    db = read_db()

    if url_raw in db["cache"] and time.time() - db["cache"][url_raw]["time"] < 604800:
        cached = db["cache"][url_raw]
        db["live"].insert(0, {"url": mask_url(url_raw), "full": url_raw, "isBad": cached["is_phishing"], "time": time.time()})
        db["live"] = [x for x in db["live"] if time.time() - x["time"] < 60][:5]
        write_db(db)
        return cached

    # ✅ هنا صار يستخدم ملف ai_rules.py
    score, reasons, is_phishing_local = analyze_local(url_raw)
    
    vt_malicious, vt_total = check_virustotal(url_raw)
    vt_str = f"{vt_malicious}/{vt_total}"
    
    if vt_malicious > 0:
        score += 50
        reasons.append(f"VirusTotal كشفه ({vt_malicious}/{vt_total})")
        is_phishing_local = True

    is_phishing = is_phishing_local or score >= 50
    ai_text = get_ai_reply(url_raw, score, reasons if reasons else ["لا يوجد مؤشرات"], vt_str)

    result = {
        "url": url_raw,
        "is_phishing": is_phishing,
        "score": min(score, 100),
        "risk": "عالي 🔴" if is_phishing else "آمن 🟢",
        "reasons": reasons if reasons else ["لا يوجد مؤشرات تصيد"],
        "virustotal": {"malicious": vt_malicious, "total": vt_total},
        "ai_analysis": ai_text,
        "time": time.time()
    }

    db["cache"][url_raw] = result
    db["live"].insert(0, {"url": mask_url(url_raw), "full": url_raw, "isBad": is_phishing, "time": time.time()})
    db["live"] = [x for x in db["live"] if time.time() - x["time"] < 60][:5]
    write_db(db)
    return result
