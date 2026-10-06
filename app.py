from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import re
import os
import requests
import time
from openai import OpenAI

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLCheck(BaseModel):
    url: str

client = None
try:
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
except:
    pass

# --- كود VirusTotal الجديد ---
VT_API_KEY = os.getenv("VT_API_KEY")

def check_virustotal(url_to_scan):
    try:
        if not VT_API_KEY:
            return 0, 0
        h = {"x-apikey": VT_API_KEY}
        r = requests.post("https://www.virustotal.com/api/v3/urls", headers=h, data={"url": url_to_scan}, timeout=20)
        if r.status_code!= 200:
            return 0, 0
        aid = r.json()['data']['id']
        time.sleep(4)
        rep = requests.get(f"https://www.virustotal.com/api/v3/analyses/{aid}", headers=h, timeout=20).json()
        s = rep['data']['attributes']['stats']
        mal = s.get('malicious', 0) + s.get('suspicious', 0)
        tot = sum(s.values())
        return mal, tot
    except:
        return 0, 0

def get_ai_reply(url, score, reasons):
    if not client:
        return "تم التحليل بدون الذكاء الاصطناعي (أضيفي مفتاح OPENAI_API_KEY للتفعيل)"
    try:
        prompt = f"الرابط: {url}, درجة الخطورة: {score}, الأسباب: {reasons}. اشرحي باللهجة السعودية هل هو آمن ولا تصيد، باختصار ومطمئن."
        r = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "انت طَمّن، خبير أمن سيبراني سعودي، تشرح بلهجة سعودية بسيطة ومطمئنة."},
                {"role": "user", "content": prompt}
            ]
        )
        return r.choices[0].message.content
    except Exception as e:
        return str(e)

@app.get("/api")
def home():
    return {"status": "Tamman AI is running"}

@app.post("/check")
def check_url(data: URLCheck):
    url = data.url.lower()
    score = 0
    reasons = []
    if re.search(r"@|\.tk|\.ml|\.ga|bit\.ly|tinyurl", url):
        score += 40
        reasons.append("رابط مختصر أو مشبوه")
    if url.count("-") > 3 or url.count(".") > 4:
        score += 30
        reasons.append("عدد كبير من الشرطات والنقاط")
    if re.search(r"login|verify|bank|secure|update|free|gift", url) and not any(x in url for x in ["tamman.sa", "google.com"]):
        score += 30
        reasons.append("كلمات تصيد (login, verify, bank)")
    if len(url) > 75:
        score += 20
        reasons.append("رابط طويل جداً")
    if re.search(r"\d+\.\d+\.\d+\.\d+", url):
        score += 50
        reasons.append("يستخدم عنوان IP مباشر")

    # --- فحص VirusTotal الجديد ---
    vt_mal, vt_total = check_virustotal(data.url)
    if vt_mal > 0:
        score += 40
        reasons.append(f"تم كشفه من {vt_mal} شركة حماية من أصل {vt_total} في VirusTotal 🔴")

    is_phishing = score >= 50
    ai_text = get_ai_reply(data.url, score, reasons)
    return {
        "url": data.url,
        "is_phishing": is_phishing,
        "score": score,
        "risk": "عالي 🔴" if is_phishing else "آمن 🟢",
        "reasons": reasons if reasons else ["لا يوجد مؤشرات تصيد"],
        "ai_analysis": ai_text,
        "virustotal": {"malicious": vt_mal, "total": vt_total}
    }

@app.get("/")
def serve_index():
    return FileResponse("index.html")
