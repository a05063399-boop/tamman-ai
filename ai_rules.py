# ai_rules.py - قاعدة بيانات طمّن الذكية
# هذا الملف هو عقل طمّن

TRUSTED_DOMAINS = [
    "google.com", "youtube.com", "apple.com", "microsoft.com",
    "amazon.com", "facebook.com", "instagram.com", "twitter.com",
    "tiktok.com", "linkedin.com", "gov.sa", "saudi", "absher.sa"
]

SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".top", ".xyz", ".click"]

PHISHING_KEYWORDS = {
    "login": 15, "verify": 20, "secure": 15, "account": 15,
    "update": 20, "confirm": 20, "bank": 25, "free": 15,
    "gift": 20, "apple": 20, "paypal": 25, "wallet": 25,
    "absher": 25, "rajhi": 25, "stc": 20
}

DANGER_PATTERNS = [
    (r"\d+\.\d+\.\d+\.\d+", 50, "يستخدم عنوان IP مباشر وهذه حركة هاكرز"),
    (r"@.*", 40, "فيه علامة @ وهذا تمويه"),
    (r"bit\.ly|tinyurl|t\.me", 30, "رابط مختصر يخفي الرابط الحقيقي"),
    (r"-{3,}", 20, "شرطات كثيرة لتقليد موقع مشهور"),
]

def analyze_local(url: str):
    url_lower = url.lower()
    score = 0
    reasons = []

    # 1- هل هو موقع موثوق؟
    for trusted in TRUSTED_DOMAINS:
        if trusted in url_lower and url_lower.count(".") <= 3:
            return 0, ["موقع رسمي وموثوق ✅"], False

    # 2- فحص النطاقات المشبوهة
    for tld in SUSPICIOUS_TLDS:
        if tld in url_lower:
            score += 40
            reasons.append(f"نطاق مشبوه جداً ({tld})")

    # 3- كلمات التصيد
    for word, points in PHISHING_KEYWORDS.items():
        if word in url_lower:
            score += points
            reasons.append(f"يحتوي كلمة خطيرة '{word}'")

    # 4- الأنماط الخطيرة
    import re
    for pattern, points, msg in DANGER_PATTERNS:
        if re.search(pattern, url_lower):
            score += points
            reasons.append(msg)

    # 5- الطول
    if len(url) > 75:
        score += 15
        reasons.append("الرابط طويل بشكل مريب")
    
    if url.count(".") > 4:
        score += 20
        reasons.append("نقاط كثيرة لتقليد موقع")

    is_phishing = score >= 50
    return min(score, 100), reasons, is_phishing

def get_gemini_prompt(url, score, reasons, vt_result):
    return f"""
انت طمّن، خبير أمن سيبراني سعودي، تحلل الروابط للمستخدمين السعوديين.
مهمتك: احكم على الرابط التالي هل هو تصيد أم لا.

الرابط: {url}
نتيجة الفحص المحلي: {score}/100 - {', '.join(reasons)}
نتيجة VirusTotal: {vt_result}

المطلوب:
- رد سطرين فقط باللهجة السعودية العامية
- اذا آمن قل آمن 🟢 وعلل
- اذا مشبوه قل مشبوه 🔴 واذكر السبب الرئيسي (مثل نطاق tk مجاني، او كلمة verify)
- لا تكثر كلام
"""
