from fastapi import FastAPI
from pydantic import BaseModel
import re, os
from openai import OpenAI

app = FastAPI(title="Tamman AI - طمّن")
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

class UrlCheck(BaseModel):
    url: str

def rule_score(url):
    score=0; reasons=[]
    if re.search(r"\.tk|\.ml|\.ga|\.cf|\.gq|bit\.ly|tinyurl", url):
        score+=40; reasons.append("رابط مختصر أو مشبوه")
    if re.search(r"login|verify|bank|secure|free|gift", url, re.I):
        score+=30; reasons.append("كلمات تصيد (login, verify, bank)")
    if url.count("-")>2 or "@" in url:
        score+=20; reasons.append("تركيب رابط غير طبيعي")
    return score, reasons

@app.get("/")
def home():
    return {"message": "Tamman AI شغال"}

@app.post("/check")
def check_url(data: UrlCheck):
    score, reasons = rule_score(data.url)
    is_phishing = score >= 50
    risk = "عالي 🔴" if score>=70 else "متوسط 🟡" if score>=40 else "آمن 🟢"

    ai_text = "AI غير مفعل - حطي المفتاح في Render"
    try:
        if os.getenv("OPENAI_API_KEY"):
            r = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role":"system","content":"انت خبير امن سيبراني، حلل هل الرابط تصيد؟ جاوب بالعربي بجملة واحدة."},
                    {"role":"user","content":data.url}
                ],
                max_tokens=120
            )
            ai_text = r.choices[0].message.content
    except Exception as e:
        ai_text = f"خطأ: {e}"

    return {"url": data.url, "is_phishing": is_phishing, "score": score, "risk": risk, "reasons": reasons, "ai_analysis": ai_text}
