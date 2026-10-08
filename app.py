import base64, os, time
from ai_rules import analyze_local, get_gemini_prompt
# تأكد اسماء الدوال في database.py هي نفسها
from database import get_cache, save_cache, add_live, get_live as get_live_db
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
import requests
import google.generativeai as genai

app = FastAPI(title="طَمّن AI Global")

# السماح للموقع يشتغل من اي مكان
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

VT_API_KEY = os.getenv("VT_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# اعداد جيميناي
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    gemini_model = genai.GenerativeModel('gemini-1.5-flash')
else:
    gemini_model = None

def mask_url(u):
    # القانون: اخفاء الرابط في اللايف عشان الخصوصية
    c = u.replace('https://','').replace('http://','').replace('www.','')
    return c[:6]+"****"+c[-4:] if len(c)>12 else c[:2]+"****"

class URLCheck(BaseModel):
    url: str

def check_virustotal(url_to_scan: str):
    # القانون: اذا ما فيه مفتاح نرجع 0 بدون ما نعلق
    if not VT_API_KEY:
        return 0, 0
    try:
        headers = {"x-apikey": VT_API_KEY}
        # تحويل الرابط لـ base64 عشان فايروس توتال يفهمه
        url_id = base64.urlsafe_b64encode(url_to_scan.encode()).decode().strip("=")
        
        # 1- نحاول نجيب نتيجة قديمة (ما تستهلك كوتا)
        res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=15)
        
        # القانون: اذا قال Rate limit نوقف ونعتمد على الفحص المحلي فقط
        if res.status_code == 429:
            print("VT Rate limit - نستخدم المحلي فقط")
            return 0, 0
            
        if res.status_code == 200:
            stats = res.json()['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious',0)+stats.get('suspicious',0)
            return malicious, sum(stats.values())
        
        # 2- اذا ما فيه نتيجة قديمة نرسل الرابط جديد
        # هنا لازم ننتظر عشان لا نتجاوز 4 طلبات في الدقيقة
        time.sleep(2) 
        res = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url_to_scan}, timeout=15)
        
        if res.status_code == 429:
            return 0, 0
        if res.status_code!= 200:
            return 0,0
            
        analysis_id = res.json()['data']['id']
        time.sleep(6) # ننتظر التحليل
        
        report = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers, timeout=15).json()
        stats = report['data']['attributes']['stats']
        return stats.get('malicious',0)+stats.get('suspicious',0), sum(stats.values())
        
    except Exception as e:
        print(f"VT error: {e}")
        return 0,0

def get_ai_reply(url, score, reasons, vt_str):
    # اذا ما فيه جيميناي نرجع رد محلي بسيط
    if not gemini_model:
        return "آمن 🟢" if score < 45 else f"مشبوه 🔴 - {', '.join(reasons[:2])}"
    try:
        prompt = get_gemini_prompt(url, score, reasons, vt_str)
        r = gemini_model.generate_content(prompt)
        return r.text.strip()
    except Exception as e:
        print(f"Gemini error: {e}")
        return "آمن 🟢" if score < 45 else f"مشبوه 🔴 {', '.join(reasons[:2])}"

@app.get("/")
def serve_index():
    return FileResponse("index.html")

@app.get("/api/live")
def get_live():
    return get_live_db()

@app.get("/api")
def home():
    return {"status":"Tamman AI + SQLite Free DB + RateLimit Fix ✅"}

@app.post("/check")
def check_url(data: URLCheck):
    url_raw = data.url.strip()

    # القانون 1: شيك الكاش من SQLite قبل لا تروح لفايروس توتال
    # هذا يوفر لك 500 فحص في اليوم
    cached = get_cache(url_raw)
    if cached:
        add_live(mask_url(url_raw), url_raw, cached["is_phishing"])
        return cached

    # القانون 2: فحص محلي من ai_rules.py (22 قانون)
    score, reasons, is_phishing_local = analyze_local(url_raw)
    
    # القانون 3: فحص فايروس توتال (يجي بعد المحلي عشان نوفر الكوتا)
    vt_malicious, vt_total = check_virustotal(url_raw)
    vt_str = f"{vt_malicious}/{vt_total}"
    
    # اذا فايروس توتال كشفه نرفع الخطورة +50
    if vt_malicious > 0:
        score += 50
        reasons.append(f"VirusTotal كشفه ({vt_malicious}/{vt_total})")
        is_phishing_local = True

    # القانون الأخير: التوحيد - اي سكور فوق 45 نعتبره تصيد (نفس ai_rules.py)
    is_phishing = is_phishing_local or score >= 45
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

    # القانون 4: حفظ في SQLite عشان المرة الجاية ما نستهلك كوتا
    save_cache(url_raw, result)
    add_live(mask_url(url_raw), url_raw, is_phishing)
    
    return result

    # 3- حفظ في SQLite
    save_cache(url_raw, result)
    add_live(mask_url(url_raw), url_raw, is_phishing)
    
    return result
