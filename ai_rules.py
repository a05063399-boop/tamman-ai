import re
from urllib.parse import urlparse
import sqlite3
import time

TRUSTED_DOMAINS = ["google.com", "youtube.com", "facebook.com", "twitter.com", "x.com", "apple.com", "microsoft.com", "github.com", "wikipedia.org", "gov.sa", "absher.sa", "stc.com.sa", "alrajhibank.com.sa", "alahli.com", "riyadbank.com", "my.gov.sa", "saudi.gov.sa"]
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
                return 40, f"Collective: {count} checks {int(bad_rate*100)}% phishing"
    except: pass
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
        reasons.append("Fake @ detected")
    if re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", url_lower):
        score += 75
        reasons.append("IP address instead of domain")
    if "xn--" in url_lower:
        score += 65
        reasons.append("Fake letters xn--")
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 25
            reasons.append(f"Cheap TLD: {tld}")
            break
    for free in FREE_HOSTING:
        if free in domain:
            score += 45
            reasons.append(f"Free hosting: {free}")
    for s in SHORTENERS:
        if s in domain:
            score += 40
            reasons.append(f"Short link: {s}")
    if domain.count(".") >= 4:
        score += 40
        reasons.append(f"Many dots {domain.count('.')}")
    if domain.count("-") >= 3:
        score += 35
        reasons.append(f"Many dashes {domain.count('-')}")
    brain_score, brain_reason = smart_brain(url)
    if brain_score > 0:
        score += brain_score
        reasons.append(brain_reason)
    if score < 30:
        for trusted in TRUSTED_DOMAINS:
            if domain == trusted or domain.endswith("."+trusted):
                return 0, [f"Trusted {trusted}"], False
    is_phishing = score >= 45
    final = reasons[:3] if score >= 45 else (reasons[:2] if reasons else ["Safe"])
    return min(score, 100), final, is_phishing

def get_gemini_prompt(url, score, reasons, vt_str):
    level = "safe" if score < 45 else "suspicious" if score < 75 else "dangerous"
    reasons_str = "; ".join(reasons)
    prompt = (
        f"You are Tamman security expert.\n"
        f"URL: {url}\n"
        f"Score: {score}/100 ({level})\n"
        f"Evidence: {reasons_str}\n"
        f"VirusTotal: {vt_str}\n"
        f"Reply in Arabic, 3 lines only:\n"
        f"1. Verdict\n2. Trick\n3. What happens if you enter?"
    )
    return prompt
