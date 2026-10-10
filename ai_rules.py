import re
from urllib.parse import urlparse
import sqlite3
import time

TRUSTED_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "twitter.com", "x.com",
    "apple.com", "microsoft.com", "github.com", "wikipedia.org",
    "gov.sa", "absher.sa", "stc.com.sa", "alrajhibank.com.sa", "alahli.com",
    "riyadbank.com", "my.gov.sa", "saudi.gov.sa"
]

BRANDS = ["apple", "google", "microsoft", "facebook", "netflix", "paypal", "amazon", "stc", "alrajhi", "alahli", "absher", "tamara", "tabby"]
SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz", ".click", ".country", ".live", ".online", ".shop", ".work", ".fit", ".date", ".loan"]
SHORTENERS = ["bit.ly", "tinyurl.com", "cutt.ly", "t.me", "is.gd", "ow.ly", "buff.ly", "rebrand.ly", "tiny.cc"]
FREE_HOSTING = ["weebly.com", "wixsite.com", "000webhostapp.com", "blogspot.com", "sites.google.com", "webflow.io", "netlify.app", "vercel.app", "pages.dev"]
PHISHING_WORDS = ["login", "verify", "secure", "update", "bank", "account", "signin", "password", "confirm", "free", "gift", "bonus", "prize", "urgent", "suspended", "locked"]
SAUDI_TRICKS = ["دعم", "حساب المواطن", "مكافأة", "مخالفة", "ناجز", "ابشر", "راتب", "مساعدة"]

def smart_brain(url: str):
    try:
        conn = sqlite3.connect("tamman.db", timeout=10)
        c = conn.cursor()
        c.execute("SELECT COUNT(*), SUM(is_bad) FROM live WHERE full_url=? AND time >?", (url, time.time() - 604800))
        count, bad_sum = c.fetchone()
        conn.close()
        if count and count >= 3:
            bad_rate = (bad_sum or 0) / count
            if bad_rate >= 0.7:
                return 40, f"🧠 العقل الجماعي: {count} فحص {int(bad_rate*100)}% تصيد"
    except:
        pass
    return 0, None

def analyze_local(url: str):
    url_lower = url.lower().strip()
    score = 0
    reasons = []
    try:
        parsed = urlparse(url_lower if "://" in url_lower else "http://"+url_lower)
        domain = parsed.netloc
        path = parsed.path + "?" + parsed.query
    except:
        domain = url_lower
        path = ""

    if "@" in url_lower:
        score += 30
        reasons.append("🟡 خطر @ - اللي قبله وهمي")
    if re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", url_lower):
        score += 75
        reasons.append("🔴 عنوان IP بدل اسم موقع")
    if re.search(r"0x[0-9a-f]+\.0x[0-9a-f]+", url_lower):
        score += 75
        reasons.append("🔴 IP مشفر")
    if url_lower.startswith("data:") or "blob:" in url_lower:
        score += 70
        reasons.append("🔴 ملف داخل الرابط")
    if "xn--" in url_lower:
        score += 65
        reasons.append("🔴 حروف مزورة")
    if re.search(r":\d{2,5}", domain):
        score += 60
        reasons.append("🔴 منفذ غير طبيعي")
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 25
            reasons.append(f"🟡 نطاق رخيص: {tld}")
            break
    for free in FREE_HOSTING:
        if free in domain:
            score += 45
            reasons.append(f"🟠 استضافة مجانية: {free}")
    for s in SHORTENERS:
        if s in domain:
            score += 40
            reasons.append(f"🟠 رابط مختصر: {s}")
    if domain.count(".") >= 4:
        score += 40
        reasons.append(f"🟠 نقاط كثيرة {domain.count('.')}")
    if domain.count("-") >= 3:
        score += 35
        reasons.append(f"🟠 شرطات كثيرة {domain.count('-')}")
    for brand in BRANDS:
        if brand in domain:
            if not any(brand in t and t in domain for t in TRUSTED_DOMAINS):
                if any(w in url_lower for w in PHISHING_WORDS):
                    score += 50
                    reasons.append(f"🟠 انتحال {brand}")
                    break
    if re.search(r"(g[o0]{2}gle|paypa[l1]|micr[o0]s[o0]ft|app[l1]e|faceb[o0]{2}k)", domain):
        score += 55
        reasons.append("🟠 تقليد اسم شركة")
    phishing_in_domain = sum(1 for w in PHISHING_WORDS if w in domain)
    if phishing_in_domain >= 2:
        score += 45
        reasons.append(f"🟠 كلمات تصيد: {phishing_in_domain}")
    if len(re.findall(r"\d", domain)) >= 5:
        score += 30
        reasons.append("🟠 أرقام كثيرة")
    if len(url_lower) > 100:
        score += 25
        reasons.append(f"🟡 رابط طويل {len(url_lower)}")
    elif len(url_lower) > 75:
        score += 15
        reasons.append("🟡 رابط أطول من الطبيعي")
    if any(w in path for w in PHISHING_WORDS):
        score += 15
        reasons.append("🟡 كلمات حساسة في المسار")
    for trick in SAUDI_TRICKS:
        if trick in url_lower:
            score += 35
            reasons.append(f"🟠 استهداف سعودي: {trick}")
    if url_lower.startswith("http://") and any(b in url_lower for b in ["bank", "login", "password"]):
        score += 30
        reasons.append("🟡 بدون https")
    if url_lower.count("%") > 3 or url_lower.count("=") > 3:
        score += 20
        reasons.append("🟡 ترميز كثير")
    if url_lower.count("//") > 1:
        score += 30
        reasons.append("🟡 // مشبوه")
    if "." not in domain or len(domain.split(".")[-1]) < 2:
        score += 40
        reasons.append("🟡 بدون امتداد")

    brain_score, brain_reason = smart_brain(url)
    if brain_score > 0:
        score += brain_score
        reasons.append(brain_reason)

    if score < 30:
        for trusted in TRUSTED_DOMAINS:
            if domain == trusted or domain.endswith("."+trusted):
                if "@" not in url_lower and domain.count(".") <= 3:
                    return 0, [f"موثوق ✅ {trusted}"], False

    is_phishing = score >= 45
    final = reasons[:3] if score >= 45 else (reasons[:2] if reasons else ["آمن"])
    return min(score, 100), final, is_phishing

def get_gemini_prompt(url, score, reasons, vt_str):
    level = "آمن" if score < 45 else "مشبوه" if score < 75 else "خطير"
    return f"""
انت طَمّن خبير أمني.
الرابط: {url}
النتيجة: {score}/100 ({level})
الأدلة: {'; '.join(reasons)}
VirusTotal: {vt_str}
رد 3 أسطر فقط:
1. الحكم
2. الخدعة
3. لو دخلت وش بيصير؟
"""
