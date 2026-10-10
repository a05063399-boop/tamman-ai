import base64, os, time, re, requests
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

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

VT_API_KEY = os.getenv("VT_API_KEY")
VERIPHONE_KEY = os.getenv("VERIPHONE_KEY")
RAPIDAPI_KEY = os.getenv("RAPIDAPI_KEY") # حط هنا 10 مفاتيح مفصولة بفاصلة

def mask_url(u):
    c = u.replace('https://','').replace('http://','').replace('www.','')
    return c[:6]+"****"+c[-4:] if len(c)>12 else c[:2]+"****"

class URLCheck(BaseModel):
    url: str
class PhoneCheck(BaseModel):
    phone: str

def check_virustotal(url_to_scan: str):
    if not VT_API_KEY: return 0,0
    try:
        headers = {"x-apikey": VT_API_KEY}
        url_id = base64.urlsafe_b64encode(url_to_scan.encode()).decode().strip("=")
        res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=15)
        if res.status_code == 200:
            stats = res.json()['data']['attributes']['last_analysis_stats']
            return stats.get('malicious',0)+stats.get('suspicious',0), sum(stats.values())
    except: pass
    return 0,0

@lru_cache(maxsize=10000)
def check_veriphone_api(phone: str):
    if not VERIPHONE_KEY: return None
    clean = re.sub(r'\D', '', phone)
    if clean.startswith('0'): clean = '+966' + clean[1:]
    elif not clean.startswith('+'): clean = '+966' + clean.lstrip('9660')
    try:
        r = requests.get("https://api.veriphone.io/v2/verify", params={"key": VERIPHONE_KEY, "phone": clean}, timeout=8)
        if r.status_code == 200:
            d = r.json()
            return {"valid": d.get("phone_valid", True), "carrier": d.get("carrier","STC"), "type": d.get("phone_type","mobile"), "country": d.get("country","SA")}
    except: pass
    return None

# --- النسخة النهائية - 10 مفاتيح + قراءة صحيحة ---
def get_numberbok_data(phone: str):
    clean = re.sub(r'\D', '', phone)
    if not clean: return None

    # تحويل لصيغة 966
    if clean.startswith('0'):
        sa_country = '966' + clean[1:]
    elif clean.startswith('966'):
        sa_country = clean
    else:
        sa_country = '966' + clean.lstrip('0')

    if not RAPIDAPI_KEY:
        return None

    # يدعم 10 مفاتيح مفصولة بفاصلة
    keys = [k.strip() for k in RAPIDAPI_KEY.split(',') if k.strip()]

    for key in keys:
        try:
            url = f"https://truecaller4.p.rapidapi.com/v1/lookup?phone={sa_country}&country=SA"
            r = requests.get(url, headers={"X-RapidAPI-Key": key, "X-RapidAPI-Host": "truecaller4.p.rapidapi.com"}, timeout=8)

            if r.status_code == 429: # المفتاح خلص، جرب اللي بعده
                print(f"Key {key[:8]} finished, trying next")
                continue

            if r.status_code == 200:
                j = r.json()
                # ردك الحقيقي داخل data
                data = j.get("data", j)
                if not isinstance(data, dict):
                    continue

                basic = data.get("basicInfo", {})
                name_obj = basic.get("name", {})
                full_name = name_obj.get("fullName") or name_obj.get("altName")

                if not full_name or len(full_name.strip()) < 2:
                    continue

                # جمع الأسماء الإضافية
                all_names = [full_name.strip()]
                for sug in data.get("communitySuggestions", [])[:4]:
                    if isinstance(sug, dict):
                        n = sug.get("name") or sug.get("fullName")
                        if n and n not in all_names and len(n) > 2:
                            all_names.append(n)

                all_names = list(dict.fromkeys(all_names))[:5]
                carrier = data.get("phoneInfo", {}).get("carrier", "STC")
                spam_reports = data.get("spamInfo", {}).get("spamStats", {}).get("numReports", 0)

                return {
                    "names": all_names,
                    "name": all_names[0],
                    "carrier": carrier,
                    "reports": spam_reports,
                    "is_spam": spam_reports > 5,
                    "source": f"Truecaller4 ({key[:6]}..)",
                    "count": len(all_names)
                }
        except Exception as e:
            print(f"Error key {key[:6]}: {e}")
            continue

    return None

@app.get("/")
def serve_index(): return FileResponse("index.html")
@app.get("/api/live")
def get_live(): return get_live_db()
@app.get("/api")
def home(): return {"status": f"Tamman + {len(RAPIDAPI_KEY.split(',')) if RAPIDAPI_KEY else 0} keys ✅"}

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
        score+=50; is_phishing_local=True; reasons.append(f"VirusTotal ({vt_malicious}/{vt_total})")
    is_phishing = is_phishing_local or score>=45
    ai_data = explain_with_ai(url_raw, score, reasons if reasons else ["لا يوجد مؤشرات"], vt_str)
    result = {"url": url_raw, "is_phishing": is_phishing, "score": min(score,100), "risk": "عالي 🔴" if is_phishing else "آمن 🟢", "reasons": reasons if reasons else ["لا يوجد مؤشرات"], "virustotal": {"malicious": vt_malicious, "total": vt_total}, "ai_analysis": ai_data, "time": time.time()}
    save_cache(url_raw, result); add_live(mask_url(url_raw), url_raw, is_phishing)
    return result

@app.post("/check-phone")
def check_phone_api(data: PhoneCheck):
    phone = data.phone.strip()
    if not phone: return {"phone": "", "name": "غير صحيح", "score": 0}
    cache_key = f"PHONE_{re.sub(r'\\D','',phone)}"
    cached = get_cache(cache_key)
    if cached:
        add_live(f"📱 {phone} (ذاكرة)", phone, cached.get("is_spam", False))
        return cached

    v_info = check_veriphone_api(phone)
    info = get_numberbok_data(phone)

    if info:
        names = info.get("names", [info["name"]])
        name = info["name"]; names_display = "، ".join(names[:5])
        carrier = v_info["carrier"] if v_info and v_info.get("carrier")!="غير معروف" else info["carrier"]
        reports = info.get("count", len(names)); is_spam = info["is_spam"]
        source = info["source"] + (" + Veriphone" if v_info else ""); extra_names = names
    else:
        name = "غير مسجل"; names_display = "غير مسجل"; extra_names = []
        carrier = v_info["carrier"] if v_info else "غير معروف"; reports=0; is_spam=False
        source = "Veriphone" if v_info else "غير معروف"

    if v_info and not v_info.get("valid"):
        is_spam=True; name="رقم غير صالح"; names_display="رقم غير صالح"

    score = 85 if is_spam else (10 if info else 30)

    if is_spam:
        ai_analysis = {"verdict": "خطير", "trick": f"مسجل كإزعاج في {source}", "what_if": "قد يطلب كود", "advice": "احظره"}
        reasons = [f"الاسم: {name}", f"الشبكة: {carrier}"]
    else:
        if info:
            ai_analysis = {"verdict": "آمن", "trick": f"موثق عند {reports} أشخاص", "what_if": "مكالمة عادية", "advice": f"مسجل عند {reports} أشخاص باسم {name}"}
            reasons = [f"الاسم الرئيسي: {name}", f"كل الأسماء: {names_display}", f"الشبكة: {carrier}", f"المصدر: {source}"]
        else:
            ai_analysis = {"verdict": "غير معروف", "trick": "صالح لكن غير مسجل", "what_if": "رقم جديد", "advice": "كن حذر"}
            reasons = [f"الشبكة: {carrier}", "غير مسجل"]
            score=30

    result = {"phone": phone, "name": name, "all_names": extra_names, "names_display": names_display, "names_count": reports, "carrier": carrier, "source": source, "reports": reports, "is_spam": is_spam, "is_phishing": is_spam, "score": score, "reasons": reasons, "ai_analysis": ai_analysis, "veriphone": v_info}
    save_cache(cache_key, result); add_live(f"📱 {phone}", phone, is_spam)
    return result

@app.post("/ai-chat")
def ai_chat_endpoint(data: dict):
    message = data.get("message",""); history = data.get("history",[])
    if not message.strip(): return {"reply": "اكتب شي 😅"}
    return {"reply": chat_with_tamman(message, history)}
