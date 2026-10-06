from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import re
import os
from openai import OpenAI

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLCheck(BaseModel):
    url: str

client = None
try:
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
except:
    pass

def get_ai_reply(url, score, reasons):
    if not client:
        return "تم التحليل بدون الذكاء الاصطناعي (أضيفي مفتاح OPENAI_API_KEY للتفعيل)"
    try:
        prompt = f"الرابط: {url}, درجة الخطورة: {score}, الأسباب: {reasons}. اشرحي باللهجة السعودية هل هو آمن ولا تصيد، باختصار ومطمئن."
        r = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "انت طَمّن، خبير أمن سيبراني سعودي، تشرح بلهجة سعودية بسيطة ومطمئنة."},
                {"role": "user", "content": prompt}
            ]
        )
        return r.choices[0].message.content
    except Exception as e:
        return str(e)

@app.get("/api")
def home():
    return {"status": "Tamman AI is running"}

@app.post("/check")
def check_url(data: URLCheck):
    url = data.url.lower()
    score = 0
    reasons = []
    if re.search(r"@|\.tk|\.ml|\.ga|bit\.ly|tinyurl", url):
        score += 40
        reasons.append("رابط مختصر أو مشبوه")
    if url.count("-") > 3 or url.count(".") > 4:
        score += 30
        reasons.append("عدد كبير من الشرطات والنقاط")
    if re.search(r"login|verify|bank|secure|update|free|gift", url) and not any(x in url for x in ["tamman.sa", "google.com"]):
        score += 30
        reasons.append("كلمات تصيد (login, verify, bank)")
    if len(url) > 75:
        score += 20
        reasons.append("رابط طويل جداً")
    if re.search(r"\d+\.\d+\.\d+\.\d+", url):
        score += 50
        reasons.append("يستخدم عنوان IP مباشر")
    is_phishing = score >= 50
    ai_text = get_ai_reply(data.url, score, reasons)
    return {
        "url": data.url,
        "is_phishing": is_phishing,
        "score": score,
        "risk": "عالي 🔴" if is_phishing else "آمن 🟢",
        "reasons": reasons if reasons else ["لا يوجد مؤشرات تصيد"],
        "ai_analysis": ai_text
    }

@app.get("/")
def serve_index():
    return FileResponse("index.html")
