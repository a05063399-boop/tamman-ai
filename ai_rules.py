import re
from urllib.parse import urlparse

# ========== القوائم البيضاء والسوداء ==========

# المواقع الموثوقة 100% - اذا الرابط منها نعتبره آمن مباشرة
TRUSTED_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "twitter.com", "x.com",
    "apple.com", "microsoft.com", "github.com", "wikipedia.org",
    "gov.sa", "absher.sa", "stc.com.sa", "alrajhibank.com.sa", "alahli.com",
    "riyadbank.com", "my.gov.sa", "saudi.gov.sa"
]

# أسماء الشركات اللي الهكر ينتحلها كثير
BRANDS = ["apple", "google", "microsoft", "facebook", "netflix", "paypal", "amazon", "stc", "alrajhi", "alahli", "absher", "tamara", "tabby"]

# النطاقات الرخيصة اللي سعرها دولار واحد ويستخدمها الهكر للتصيد
SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz", ".click", ".country", ".live", ".online", ".shop", ".work", ".fit", ".date", ".loan"]

# مواقع اختصار الروابط - الهكر يستخدمها عشان يخفي الرابط الحقيقي
SHORTENERS = ["bit.ly", "tinyurl.com", "cutt.ly", "t.me", "is.gd", "ow.ly", "buff.ly", "rebrand.ly", "tiny.cc"]

# مواقع الاستضافة المجانية - أي هكر يقدر يسوي موقع تصيد فيها ببلاش
FREE_HOSTING = ["weebly.com", "wixsite.com", "000webhostapp.com", "blogspot.com", "sites.google.com", "webflow.io", "netlify.app", "vercel.app", "pages.dev"]

# كلمات التصيد المشهورة عالمياً - اذا شفناها في الرابط نرفع الخطورة
PHISHING_WORDS = ["login", "verify", "secure", "update", "bank", "account", "signin", "password", "confirm", "free", "gift", "bonus", "prize", "urgent", "suspended", "locked"]

# كلمات تصيد خاصة بالسعودية - الهكر يستهدفها عشان يخدع المواطنين
SAUDI_TRICKS = ["دعم", "حساب المواطن", "مكافأة", "مخالفة", "ناجز", "ابشر", "راتب", "مساعدة"]

def analyze_local(url: str):
    original_url = url
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

    # ============================================================
    # المستوى الأحمر - قوانين خطيرة جداً (+60 الى +80)
    # أي قانون هنا لحاله يخلي الرابط تصيد
    # ============================================================

    # القانون 1: كشف حركة الـ @
    # الشرح: الهكر يكتب google.com@evil.com - المتصفح يروح لـ evil.com لكن المستخدم يشوف google.com
    # الحل: اللي قبل @ وهمي، اللي بعد @ هو الموقع الحقيقي
    if "@" in url_lower:
        score += 80
        reasons.append("🔴 خطر عالي: يستخدم @ لخداعك (اللي قبل @ وهمي)")

    # القانون 2: كشف الـ IP المباشر
    # الشرح: المواقع الطبيعية لها اسم مثل google.com، الهكر يستخدم 185.12.45.67 عشان ما ينكشف
    if re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", url_lower):
        score += 75
        reasons.append("🔴 يستخدم عنوان IP بدل اسم موقع - حيلة هكر")

    # القانون 3: كشف الـ IP المشفر Hex
    # الشرح: الهكر يحول الـ IP الى حروف 0x12.0x34 عشان برامج الحماية ما تكشفه
    if re.search(r"0x[0-9a-f]+\.0x[0-9a-f]+", url_lower):
        score += 75
        reasons.append("🔴 يستخدم IP مشفر لإخفاء الهوية")

    # القانون 4: كشف ملفات data: و blob:
    # الشرح: الرابط يكون data:text/html;base64 وهذا يعني الصفحة كلها فيروس داخل الرابط نفسه
    if url_lower.startswith("data:") or "blob:" in url_lower:
        score += 70
        reasons.append("🔴 ملف خطير داخل الرابط نفسه")

    # القانون 5: كشف Punycode - الحروف المزورة
    # الشرح: الهكر يستخدم xn-- وهذا يعني حرف روسي يشبه الحرف الانجليزي مثل а بدل a
    if "xn--" in url_lower:
        score += 65
        reasons.append("🔴 يستخدم حروف مزورة تشبه الأصلية")

    # القانون 6: كشف المنفذ الغريب
    # الشرح: المواقع الطبيعية تستخدم 443، اذا شفنا :8080 أو :3000 هذا سيرفر هكر
    if re.search(r":\d{2,5}", domain):
        score += 60
        reasons.append("🔴 يستخدم منفذ غير طبيعي")

    # ============================================================
    # المستوى البرتقالي - قوانين متوسطة الخطورة (+30 الى +55)
    # ============================================================

    # القانون 7: النطاقات الرخيصة المشبوهة
    # الشرح:.tk سعره مجاني، الشركات الحقيقية ما تستخدمه
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 50
            reasons.append(f"🟠 نطاق مشبوه رخيص: {tld}")
            break

    # القانون 8: مواقع الاستضافة المجانية
    # الشرح: weebly و wix مجانية، أي واحد يقدر يسوي موقع تصيد فيها
    for free in FREE_HOSTING:
        if free in domain:
            score += 45
            reasons.append(f"🟠 موقع مجاني يستخدم للتصيد: {free}")

    # القانون 9: الروابط المختصرة
    # الشرح: bit.ly يخفي الرابط الأصلي، ما تعرف وين بيوديك
    for s in SHORTENERS:
        if s in domain:
            score += 40
            reasons.append(f"🟠 رابط مختصر يخفي الوجهة: {s}")

    # القانون 10: كثرة النقاط في الدومين
    # الشرح: google.com.evil.com.login.tk - نقاط كثيرة عشان يخليك تظن انه جوجل
    if domain.count(".") >= 4:
        score += 40
        reasons.append(f"🟠 نقاط كثيرة ({domain.count('.')}) - نطاقات فرعية وهمية")

    # القانون 11: كثرة الشرطات في الدومين
    # الشرح: alrajhi-bank-secure-login-update.com - شرطات كثيرة لتقليد البنك
    if domain.count("-") >= 3:
        score += 35
        reasons.append(f"🟠 شرطات كثيرة ({domain.count('-')}) لتقليد المواقع")

    # القانون 12: انتحال العلامات التجارية
    # الشرح: اذا شفنا اسم apple + كلمة login في دومين غير apple.com هذا انتحال
    for brand in BRANDS:
        if brand in domain:
            if not any(brand in t and t in domain for t in TRUSTED_DOMAINS):
                if any(w in url_lower for w in PHISHING_WORDS):
                    score += 50
                    reasons.append(f"🟠 انتحال: يستخدم اسم {brand} مع كلمة تصيد")
                    break

    # القانون 13: الأخطاء الإملائية المتعمدة Typosquatting
    # الشرح: g00gle بدل google، paypa1 بدل paypal - حرف 0 بدل o
    if re.search(r"(g[o0]{2}gle|paypa[l1]|micr[o0]s[o0]ft|app[l1]e|faceb[o0]{2}k)", domain):
        score += 55
        reasons.append("🟠 يحاول تقليد اسم شركة بحروف مشابهة")

    # القانون 14: كلمتين تصيد في الدومين نفسه
    # الشرح: secure-login-bank.com - دومين كله كلمات تصيد
    phishing_in_domain = sum(1 for w in PHISHING_WORDS if w in domain)
    if phishing_in_domain >= 2:
        score += 45
        reasons.append(f"🟠 الدومين فيه كلمات تصيد: {phishing_in_domain} كلمات")

    # القانون 15: أرقام كثيرة في الدومين
    # الشرح: alrajhi12345secure.com - مواقع حقيقية ما تحط أرقام كثيرة
    if len(re.findall(r"\d", domain)) >= 5:
        score += 30
        reasons.append("🟠 أرقام كثيرة في اسم الموقع - موقع عشوائي")

    # ============================================================
    # المستوى الأصفر - قوانين خفيفة (+10 الى +25)
    # ============================================================

    # القانون 16: طول الرابط المريب
    # الشرح: الرابط الطبيعي 30 حرف، اذا صار 120 حرف يعني فيه بيانات مسروقة
    if len(url_lower) > 100:
        score += 25
        reasons.append(f"🟡 الرابط طويل جداً ({len(url_lower)} حرف)")
    elif len(url_lower) > 75:
        score += 15
        reasons.append("🟡 رابط أطول من الطبيعي")

    # القانون 17: كلمات تصيد في المسار
    # الشرح: /login/secure/update - المسار فيه كلمات تطلب بياناتك
    if any(w in path for w in PHISHING_WORDS):
        score += 15
        reasons.append("🟡 المسار فيه كلمات حساسة (login/secure)")

    # القانون 18: استهداف سعودي خاص
    # الشرح: حساب المواطن، ناجز، أبشر - كلمات يستخدمها الهكر لخداع السعوديين
    for trick in SAUDI_TRICKS:
        if trick in url_lower:
            score += 35
            reasons.append(f"🟠 يستهدف سعوديين: {trick}")

    # القانون 19: http بدون تشفير في موقع بنكي
    # الشرح: أي بنك لازم https، اذا http معناه مزور
    if url_lower.startswith("http://") and any(b in url_lower for b in ["bank", "login", "password"]):
        score += 30
        reasons.append("🟡 موقع بنكي بدون تشفير https")

    # القانون 20: ترميز كثير %
    # الشرح: %20%2F%3D - ترميز كثير عشان يخفي الكلمات الخطيرة
    if url_lower.count("%") > 3 or url_lower.count("=") > 3:
        score += 20
        reasons.append("🟡 ترميز كثير لإخفاء الرابط")

    # القانون 21: // في مكان غلط
    # الشرح: https://google.com//evil.com - // ثانية في الوسط حيلة قديمة
    if url_lower.count("//") > 1:
        score += 30
        reasons.append("🟡 // في مكان مشبوه")

    # القانون 22: دومين بدون امتداد صحيح
    # الشرح: http://login-bank - ما فيه.com ولا.sa معناه شبكة داخلية للهكر
    if "." not in domain or len(domain.split(".")[-1]) < 2:
        score += 40
        reasons.append("🟡 دومين بدون امتداد صحيح")

    # ========== القانون الأخير: فحص المواقع الموثوقة ==========
    # اذا ما فيه أي خطر وكان الدومين موثوق نرجعه آمن فوراً
    if score < 30:
        for trusted in TRUSTED_DOMAINS:
            if domain == trusted or domain.endswith("."+trusted):
                if "@" not in url_lower and domain.count(".") <= 3:
                    return 0, [f"موقع رسمي موثوق ✅ {trusted}"], False

    is_phishing = score >= 45
    final = reasons[:3] if score >= 45 else (reasons[:2] if reasons else ["لا يوجد مؤشرات تصيد"])
    return min(score, 100), final, is_phishing

def get_gemini_prompt(url, score, reasons, vt_str):
    # هذا البرومبت اللي نرسله لـ Gemini عشان يشرح للمستخدم
    level = "آمن" if score < 45 else "مشبوه" if score < 75 else "خطير جداً"
    return f"""
انت طَمّن، خبير أمن سيبراني سعودي لهجتك عامية بسيطة.
الرابط: {url}
التقييم المحلي: {score}/100 ({level})
VirusTotal: {vt_str}
المؤشرات: {'; '.join(reasons)}
المطلوب: سطرين فقط باللهجة السعودية.
"""
