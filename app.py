import base64, os, time, re, random, requests
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from functools import lru_cache

from ai_rules import analyze_local
from database import get_cache, save_cache, add_live, get_live as get_live_db
from ai_service import explain_with_ai
from ai_client import chat_with_tamman

app = FastAPI(title="طَمّن AI Global - بلا حدود")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

VT_API_KEY = os.getenv("VT_API_KEY")
NUMBERBOOK_API_KEY = os.getenv("NUMBERBOOK_API_KEY")
NUMBERBOOK_API_URL = os.getenv("NUMBERBOOK_API_URL", "")
VERIPHONE_KEY = os.getenv("VERIPHONE_KEY")
RAPIDAPI_KEY = os.getenv("RAPIDAPI_KEY")

def mask_url(u):
    c = u.replace('https://','').replace('http://','').replace('www.','')
    return c[:6]+"****"+c[-4:] if len(c)>12 else c[:2]+"****"

class URLCheck(BaseModel):
    url: str

class PhoneCheck(BaseModel):
    phone: str

# --- VirusTotal (نفس كودك الأصلي ما لمسته) ---
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

# --- Veriphone (نفس كودك الأصلي) ---
@lru_cache(maxsize=10000)
def check_veriphone_api(phone: str):
    if not VERIPHONE_KEY:
        return None
    clean = re.sub(r'\D', '', phone)
    if clean.startswith('0'):
        clean = '+966' + clean[1:]
    elif not clean.startswith('+'):
        clean = '+966' + clean.lstrip('9660')
    try:
        url = "https://api.veriphone.io/v2/verify"
        r = requests.get(url, params={"key": VERIPHONE_KEY, "phone": clean}, timeout=8)
        if r.status_code == 200:
            d = r.json()
            return {
                "valid": d.get("phone_valid", True),
                "carrier": d.get("carrier", "STC"),
                "type": d.get("phone_type", "mobile"),
                "country": d.get("country", "SA")
            }
    except Exception as e:
        print(f"Veriphone Error: {e}")
    return None

# --- NumberBook القوي - هنا فقط التحسين ---
def get_numberbok_data(phone: str):
    clean = re.sub(r'\D', '', phone)
    sa_original = clean
    if clean.startswith('966'):
        clean = '0' + clean[3:]
    if not clean.startswith('0') and len(clean) == 9:
        clean = '0' + clean

    # 1- Truecaller4
    if RAPIDAPI_KEY:
        try:
            for host, endpoint in [
                ("truecaller4.p.rapidapi.com", f"https://truecaller4.p.rapidapi.com/v1/lookup?phone={sa_original}&country=SA"),
                ("truecaller-data2.p.rapidapi.com", f"https://truecaller-data2.p.rapidapi.com/Search/{sa_original}")
            ]:
                try:
                    r = requests.get(endpoint, headers={"X-RapidAPI-Key": RAPIDAPI_KEY, "X-RapidAPI-Host": host}, timeout=6)
                    if r.status_code == 200:
                        d = r.json()
                        name = d.get("name") or d.get("Name") or d.get("data", {}).get("name")
                        if name and len(name) > 2:
                            return {"name": name, "carrier": d.get("carrier","STC"), "reports": d.get("spamScore",0), "is_spam": d.get("isSpam", False), "source": "Truecaller4"}
                except:
                    continue
        except:
            pass

    # 2- API مدفوع
    if NUMBERBOOK_API_KEY and NUMBERBOOK_API_URL:
        try:
            r = requests.get(NUMBERBOOK_API_URL, params={"phone": clean, "country": "SA"}, headers={"Authorization": f"Bearer {NUMBERBOOK_API_KEY}", "apikey": NUMBERBOOK_API_KEY}, timeout=6)
            if r.status_code == 200:
                d = r.json()
                name = d.get("name") or d.get("caller_name") or d.get("data", {}).get("name")
                if name:
                    return {"name": name, "carrier": d.get("carrier","STC"), "reports": d.get("reports",0), "is_spam": d.get("is_spam", False), "source": "NumberBook API"}
        except Exception as e:
            print(f"NumberBook API Error: {e}")

    # 3- كشط مجاني - تم تقويته من موقعين الى 5 مواقع
    try:
        headers = {"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)", "Accept-Language": "ar-SA,ar;q=0.9"}
        # ضفت 3 مواقع جديدة قوية
        urls_to_try = [
            f"https://number-book.com/number/{clean}",
            f"https://www.numberozo.com/number/{clean}",
            f"https://sa.number-book.com/{clean}",
            f"https://www.daleelaljoalat.com/sa/{clean}",
            f"https://numberozo.com/saudi-arabia/{clean}"
        ]
        for url in urls_to_try:
            try:
                res = requests.get(url, headers=headers, timeout=6)
                if res.status_code == 200 and len(res.text) > 1000:
                    # جرب اكثر من نمط
                    for pat in [r'<h1[^>]*>([^<]{3,40})</h1>', r'<title>([^<]{3,50}) - Number Book', r'"name"\s*:\s*"([^"]{3,50})"']:
                        m = re.search(pat, res.text, re.I)
                        if m:
                            name = m.group(1).strip()
                            if name and "number" not in name.lower() and len(name) > 2 and not name.replace(" ","").isdigit():
                                return {"name": name, "carrier": "STC", "reports": 0, "is_spam": False, "source": "NumberBook Free"}
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
    return {"status":"Tamman + Veriphone 1000 + NumberBook Linked ✅"}

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
        "url": url_raw, "is_phishing": is_phishing, "score": min(score, 100),
        "risk": "عالي 🔴" if is_phishing else "آمن 🟢",
        "reasons": reasons if reasons else ["لا يوجد مؤشرات تصيد"],
        "virustotal": {"malicious": vt_malicious, "total": vt_total},
        "ai_analysis": ai_data, "time": time.time()
    }
    save_cache(url_raw, result)
    add_live(mask_url(url_raw), url_raw, is_phishing)
    return result

@app.post("/check-phone")
def check_phone_api(data: PhoneCheck):
    phone = data.phone.strip()
    if not phone:
        return {"phone": "", "name": "غير صحيح", "score": 0}
    cache_key = f"PHONE_{re.sub(r'\\D','',phone)}"
    cached = get_cache(cache_key)
    if cached:
        add_live(f"📱 {phone} (cache)", phone, cached.get("is_spam", False))
        return cached
    v_info = check_veriphone_api(phone)
    info = get_numberbok_data(phone)
    if info:
        name = info["name"]
        carrier = v_info["carrier"] if v_info and v_info.get("carrier") != "غير معروف" else info["carrier"]
        reports = info["reports"]
        is_spam = info["is_spam"]
        source = info["source"] + (" + Veriphone" if v_info else "")
    else:
        name = "غير مسجل"
        carrier = v_info["carrier"] if v_info else "غير معروف"
        reports = 0
        is_spam = False
        source = "Veriphone" if v_info else "غير معروف"
    if v_info and not v_info.get("valid"):
        is_spam = True
        name = "رقم غير صالح"
    score = 85 if is_spam else 10
    if is_spam:
        ai_analysis = {
            "verdict": "خطير",
            "trick": f"هذا الرقم مسجل كإزعاج في {source}",
            "what_if": "قد يطلب منك كود التحقق أو بيانات بنكية",
            "advice": "لا ترد، لا تعطيه أي كود، وقم بحظره"
        }
        reasons = [f"تم التبليغ {reports} مرة في {source}", f"الاسم: {name}", f"الشبكة: {carrier}"]
    else:
        if name == "غير مسجل":
            ai_analysis = {
                "verdict": "غير معروف",
                "trick": "الرقم غير مسجل لكنه صالح حسب Veriphone",
                "what_if": "قد يكون رقم جديد",
                "advice": "كن حذراً"
            }
            reasons = [f"الشبكة: {carrier} - صالح: {v_info['valid'] if v_info else 'نعم'}", "غير مسجل في NumberBook"]
            score = 30
        else:
            ai_analysis = {
                "verdict": "آمن",
                "trick": "لا يوجد خدعة، رقم حقيقي موثق",
                "what_if": "مكالمة عادية آمنة",
                "advice": "الرقم آمن"
            }
            reasons = [f"الاسم: {name}", f"الشبكة: {carrier}", f"المصدر: {source}"]
    result = {
        "phone": phone, "name": name, "carrier": carrier,
        "source": source, "reports": reports, "is_spam": is_spam,
        "is_phishing": is_spam, "score": score, "reasons": reasons,
        "ai_analysis": ai_analysis,
        "veriphone": v_info
    }
    save_cache(cache_key, result)
    add_live(f"📱 {phone}", phone, is_spam)
    return result

@app.post("/ai-chat")
def ai_chat_endpoint(data: dict):
    message = data.get("message", "")
    history = data.get("history", [])
    if not message.strip():
        return {"reply": "اكتب شي طيب 😅"}
    reply = chat_with_tamman(message, history)
    return {"reply": reply}
