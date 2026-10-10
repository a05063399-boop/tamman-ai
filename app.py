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
        if res.status_code!= 200:
            return 0,0
        analysis_id = res.json()['data']['id']
        time.sleep(6)
        report = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers, timeout=15).json()
        stats = report['data']['attributes']['stats']
        return stats.get('malicious',0)+stats.get('suspicious',0), sum(stats.values())
    except:
        return 0,0

# --- Veriphone 1000 مجاني ---
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

# --- NumberBook القوي - يجيب 5 أسماء ---
def get_numberbok_data(phone: str):
    clean = re.sub(r'\D', '', phone)
    sa_country = clean
    if clean.startswith('0'):
        sa_country = '966' + clean[1:]
    elif not clean.startswith('966'):
        sa_country = '966' + clean.lstrip('0')

    if clean.startswith('966'):
        clean = '0' + clean[3:]
    if len(clean) == 9:
        clean = '0' + clean

    all_names = []

    # 1- Truecaller4 (الأفضل يجيب 5 أسماء)
    if RAPIDAPI_KEY:
        try:
            for host, endpoint in [
                ("truecaller4.p.rapidapi.com", f"https://truecaller4.p.rapidapi.com/v1/lookup?phone={sa_country}&country=SA"),
            ]:
                try:
                    r = requests.get(endpoint, headers={"X-RapidAPI-Key": RAPIDAPI_KEY, "X-RapidAPI-Host": host}, timeout=6)
                    if r.status_code == 200:
                        d = r.json()
                        if isinstance(d.get("data"), list):
                            for item in d["data"][:5]:
                                if item.get("name"):
                                    all_names.append(item["name"])
                        else:
                            name = d.get("name") or d.get("Name") or d.get("data",{}).get("name")
                            if name: all_names.append(name)
                        if all_names:
                            all_names = list(dict.fromkeys(all_names))[:5]
                            return {"names": all_names, "name": all_names[0], "carrier": "STC", "reports": len(all_names), "is_spam": False, "source": "Truecaller4", "count": len(all_names)}
                except:
                    continue
        except:
            pass

    # 2- API مدفوع لو عندك
    if NUMBERBOOK_API_KEY and NUMBERBOOK_API_URL:
        try:
            r = requests.get(NUMBERBOOK_API_URL, params={"phone": clean, "country": "SA"}, headers={"apikey": NUMBERBOOK_API_KEY}, timeout=6)
            if r.status_code == 200:
                d = r.json()
                name = d.get("name") or d.get("caller_name")
                if name:
                    return {"names": [name], "name": name, "carrier": d.get("carrier","STC"), "reports": 1, "is_spam": False, "source": "NumberBook API", "count": 1}
        except:
            pass

    # 3- كشط مجاني 3 مواقع - مع فلتر يمنع Home
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml",
        "Referer": "https://number-book.com/",
        "Accept-Language": "ar-SA,ar;q=0.9"
    }
    urls = [
        f"https://number-book.com/number/{clean}",
        f"https://sa.number-book.com/{clean}",
        f"https://www.daleelaljoalat.com/sa/{clean}",
    ]
    for url in urls:
        try:
            res = requests.get(url, headers=headers, timeout=8)
            text = res.text
            if res.status_code!= 200 or len(text) < 1000: continue
            # لو الصفحة بلوك
            if "Home" in text[:600] and "STC" not in text[:2000] and len(text) < 3000:
                continue

            patterns = [
                r'<div[^>]*class="[^"]*name[^"]*"[^>]*>([^<]{3,40})</div>',
                r'<span[^>]*class="[^"]*caller[^"]*"[^>]*>([^<]{3,40})</span>',
                r'<li[^>]*>([^<]{3,35})</li>',
                r'<h2[^>]*>([^<]{3,40})</h2>',
            ]
            found = []
            for pat in patterns:
                for m in re.findall(pat, text, re.I):
                    name = m.strip()
                    bad = ["home","number","book","search","دليل","الرئيسية","caller","unknown","page"]
                    if len(name)>=3 and len(name)<=35 and not any(b in name.lower() for b in bad) and not name.replace(" ","").isdigit() and "http" not in name.lower():
                        name = re.sub(r'^\d+\s*-\s*','',name).strip()
                        if name and name not in found and len(name)>2:
                            found.append(name)
            if found:
                all_names = list(dict.fromkeys(found))[:5]
                return {"names": all_names, "name": all_names[0], "carrier": "STC", "reports": len(all_names), "is_spam": False, "source": "NumberBook", "count": len(all_names)}
        except:
            continue
    return None

@app.get("/")
def serve_index():
    return FileResponse("index.html")

@app.get("/api/live")
def get_live():
    return get_live_db()

@app.get("/api")
def home():
    return {"status":"Tamman + Veriphone + NumberBook 5 أسماء ✅"}

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
        add_live(f"📱 {phone} (ذاكرة)", phone, cached.get("is_spam", False))
        return cached

    v_info = check_veriphone_api(phone)
    info = get_numberbok_data(phone)

    if info:
        names = info.get("names", [info["name"]])
        name = info["name"]
        names_display = "، ".join(names[:5])
        carrier = v_info["carrier"] if v_info and v_info.get("carrier")!= "غير معروف" else info["carrier"]
        reports = info.get("count", len(names))
        is_spam = info["is_spam"]
        source = info["source"] + (" + Veriphone" if v_info else "")
        extra_names = names
    else:
        name = "غير مسجل"
        names_display = "غير مسجل"
        extra_names = []
        carrier = v_info["carrier"] if v_info else "غير معروف"
        reports = 0
        is_spam = False
        source = "Veriphone" if v_info else "غير معروف"

    if v_info and not v_info.get("valid"):
        is_spam = True
        name = "رقم غير صالح"
        names_display = "رقم غير صالح"

    score = 85 if is_spam else (10 if info else 30)

    if is_spam:
        ai_analysis = {
            "verdict": "خطير",
            "trick": f"هذا الرقم مسجل كإزعاج في {source}",
            "what_if": "قد يطلب منك كود التحقق أو بيانات بنكية",
            "advice": "لا ترد، لا تعطيه أي كود، وقم بحظره"
        }
        reasons = [f"تم التبليغ {reports} مرة في {source}", f"الاسم: {name}", f"الشبكة: {carrier}"]
    else:
        if info:
            ai_analysis = {
                "verdict": "آمن",
                "trick": f"لا يوجد خدعة، رقم حقيقي موثق عند {reports} أشخاص",
                "what_if": "مكالمة عادية آمنة",
                "advice": f"الرقم مسجل عند {reports} أشخاص باسم {name}"
            }
            reasons = [f"الاسم الرئيسي: {name}", f"كل الأسماء: {names_display}", f"الشبكة: {carrier}", f"المصدر: {source} - مسجل عند {reports} أشخاص"]
        else:
            ai_analysis = {
                "verdict": "غير معروف",
                "trick": "الرقم غير مسجل لكنه صالح حسب Veriphone",
                "what_if": "قد يكون رقم جديد",
                "advice": "كن حذراً"
            }
            reasons = [f"الشبكة: {carrier} - صالح: {v_info['valid'] if v_info else 'نعم'}", "غير مسجل في NumberBook"]
            score = 30

    result = {
        "phone": phone,
        "name": name,
        "all_names": extra_names,
        "names_display": names_display,
        "names_count": reports,
        "carrier": carrier,
        "source": source,
        "reports": reports,
        "is_spam": is_spam,
        "is_phishing": is_spam,
        "score": score,
        "reasons": reasons,
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
