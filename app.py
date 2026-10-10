import base64, os, time, re, random, requests
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

from ai_rules import analyze_local
from database import get_cache, save_cache, add_live, get_live as get_live_db
from ai_service import explain_with_ai
from ai_client import chat_with_tamman

app = FastAPI(title="طَمّن AI Global")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

VT_API_KEY = os.getenv("VT_API_KEY")
NUMBERBOOK_API_KEY = os.getenv("NUMBERBOOK_API_KEY") # مفتاح الشركة
NUMBERBOOK_API_URL = os.getenv("NUMBERBOOK_API_URL", "") # رابط API الشركة لو عندك

def mask_url(u):
    c = u.replace('https://','').replace('http://','').replace('www.','')
    return c[:6]+"****"+c[-4:] if len(c)>12 else c[:2]+"****"

class URLCheck(BaseModel):
    url: str

class PhoneCheck(BaseModel):
    phone: str

# --- VirusTotal ---
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
        time.sleep(2)
        res = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url_to_scan}, timeout=15)
        if res.status_code != 200:
            return 0,0
        analysis_id = res.json()['data']['id']
        time.sleep(6)
        report = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers, timeout=15).json()
        stats = report['data']['attributes']['stats']
        return stats.get('malicious',0)+stats.get('suspicious',0), sum(stats.values())
    except:
        return 0,0

# --- ربط NumberBook الحقيقي ---
def get_numberbok_data(phone: str):
    clean = re.sub(r'\D', '', phone)
    if clean.startswith('966'):
        clean = '0' + clean[3:]
    if not clean.startswith('0') and len(clean) == 9:
        clean = '0' + clean

    # 1- لو عندك API مدفوع من شركة (افضل حل)
    if NUMBERBOOK_API_KEY and NUMBERBOOK_API_URL:
        try:
            r = requests.get(
                NUMBERBOOK_API_URL,
                params={"phone": clean, "country": "SA"},
                headers={"Authorization": f"Bearer {NUMBERBOOK_API_KEY}", "apikey": NUMBERBOOK_API_KEY},
                timeout=6
            )
            if r.status_code == 200:
                d = r.json()
                name = d.get("name") or d.get("caller_name") or d.get("data", {}).get("name")
                carrier = d.get("carrier") or d.get("operator") or "STC"
                reports = d.get("reports") or d.get("spam_count") or 0
                is_spam = d.get("is_spam") or reports > 3
                if name:
                    return {"name": name, "carrier": carrier, "reports": reports, "is_spam": is_spam, "source": "NumberBook API"}
        except Exception as e:
            print(f"NumberBook API Error: {e}")

    # 2- كشط مجاني من number-book.com (يشتغل بدون مفتاح)
    try:
        headers = {"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15"}
        # جرب اكثر من موقع
        for url in [f"https://number-book.com/number/{clean}", f"https://www.numberozo.com/number/{clean}"]:
            try:
                res = requests.get(url, headers=headers, timeout=6)
                if res.status_code == 200 and len(res.text) > 1000:
                    # ابحث عن الاسم
                    m = re.search(r'<h1[^>]*>([^<]{3,40})</h1>', res.text)
                    if m:
                        name = m.group(1).strip()
                        # فلترة اسماء غير مفيدة
                        if name and "number" not in name.lower() and "book" not in name.lower() and len(name) > 2:
                            return {"name": name, "carrier": "STC", "reports": 0, "is_spam": False, "source": "NumberBook"}
            except:
                continue
    except:
        pass

    return None

@app.get("/")
def serve_index():
    return FileResponse("index.html")

@app.get("/api/live")
def get_live():
    return get_live_db()

@app.get("/api")
def home():
    return {"status":"Tamman + NumberBook Linked ✅"}

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

@app.post("/check-phone")
def check_phone_api(data: PhoneCheck):
    phone = data.phone.strip()
    if not phone:
        return {"phone": "", "name": "غير صحيح", "score": 0}

    info = get_numberbok_data(phone)

    if info:
        name = info["name"]
        carrier = info["carrier"]
        reports = info["reports"]
        is_spam = info["is_spam"]
        source = info["source"]
    else:
        name = "غير مسجل"
        carrier = "غير معروف"
        reports = 0
        is_spam = False
        source = "NumberBook"

    score = 85 if is_spam else 10
    
    if is_spam:
        ai_analysis = {
            "verdict": "خطير",
            "trick": "هذا الرقم مسجل كإزعاج أو انتحال في NumberBook",
            "what_if": "قد يطلب منك كود التحقق أو بيانات بنكية لسرقة حسابك",
            "advice": "لا ترد، لا تعطيه أي كود، وقم بحظره مباشرة"
        }
        reasons = [f"تم التبليغ عنه {reports} مرة في {source}", f"الاسم: {name}"]
    else:
        if name == "غير مسجل":
            ai_analysis = {
                "verdict": "غير معروف",
                "trick": "الرقم غير مسجل في قاعدة NumberBook",
                "what_if": "قد يكون رقم جديد أو شخصي",
                "advice": "كن حذراً، لا تشارك بياناتك البنكية"
            }
            reasons = ["غير مسجل في NumberBook", "رقم غير معروف"]
            score = 30
        else:
            ai_analysis = {
                "verdict": "آمن",
                "trick": "لا يوجد خدعة، رقم حقيقي موثق",
                "what_if": "مكالمة عادية آمنة",
                "advice": "الرقم آمن وموثوق حسب NumberBook"
            }
            reasons = [f"الاسم: {name}", f"الشبكة: {carrier}", "رقم حقيقي آمن"]

    add_live(f"📱 {phone}", phone, is_spam)

    return {
        "phone": phone,
        "name": name,
        "carrier": carrier,
        "source": source,
        "reports": reports,
        "is_spam": is_spam,
        "is_phishing": is_spam,
        "score": score,
        "reasons": reasons,
        "ai_analysis": ai_analysis
    }

@app.post("/ai-chat")
def ai_chat_endpoint(data: dict):
    message = data.get("message", "")
    history = data.get("history", [])
    if not message.strip():
        return {"reply": "اكتب شي طيب 😅"}
    reply = chat_with_tamman(message, history)
    return {"reply": reply}
