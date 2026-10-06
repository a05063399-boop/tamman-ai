from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
import re
from urllib.parse import urlparse

app = FastAPI()

class Req(BaseModel):
    url: str

def analyze_url(u: str):
    u = u.strip()
    if not u.startswith('http'): u = 'https://' + u
    domain = urlparse(u).netloc.lower()
    score = 100; reasons = []; level = "منخفض"
    if any(domain.endswith(t) for t in ['.tk','.ml','.ga','.cf','.gq','.xyz','.top']):
        score -= 40; reasons.append("الدومين يستخدم امتداد مشبوه يكثر فيه النصب")
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
        score -= 50; reasons.append("الرابط يستخدم IP مباشر بدل اسم موقع، حركة تصيد واضحة")
    if domain.count('-')>=3 or domain.count('.')>=4:
        score -= 20; reasons.append("اسم الدومين فيه شرطات ونقاط كثيرة يحاول يقلد موقع ثاني")
    if any(k in u.lower() for k in ['secure','bank','login','verify','gift','prize']):
        score -= 25; reasons.append("الرابط فيه كلمات إغراء مثل bank أو gift عشان يخليك تضغط")
    if '@' in u: score -= 40; reasons.append("فيه علامة @ داخل الرابط، تصيد 100%")
    if not reasons: reasons.append("ما لقينا علامات تصيد واضحة، الدومين شكله نظيف")
    if score < 50: level = "عالي"
    elif score < 80: level = "متوسط"
    score = max(0, min(100, score))
    reason_text = "، ".join(reasons) + "."
    if level=="عالي": reason_text = "انتبه لا تضغط! " + reason_text + " نصيحتي احذفه."
    elif level=="متوسط": reason_text = "الرابط مريب شوي، " + reason_text
    else: reason_text = "الرابط يبدو سليم، " + reason_text
    return {"level": level, "score": score, "reason": reason_text, "domain": domain}

@app.get("/", response_class=HTMLResponse)
def home():
    with open("index.html","r",encoding="utf-8") as f: return f.read()

@app.post("/check")
def check(req: Req):
    return JSONResponse(analyze_url(req.url))
