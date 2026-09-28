from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import re

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLCheck(BaseModel):
    url: str

@app.get("/")
def home():
    return {"status": "Tamman AI is running"}

@app.post("/check")
def check_url(data: URLCheck):
    url = data.url.lower()
    score = 0
    reasons = []
    
    # قواعد كشف التصيد البسيطة
    if re.search(r"@|\.tk|\.ml|\.ga|bit\.ly|tinyurl", url):
        score += 40
        reasons.append("رابط مختصر أو مشبوه")
    if url.count("-") > 3 or url.count(".") > 4:
        score += 30
        reasons.append("عدد كبير من الشرطات والنقاط")
    if re.search(r"login|verify|bank|secure|update|free|gift", url) and not any(x in url for x in ["tamman.sa", "gov.sa"]):
        score += 30
        reasons.append("كلمات تصيد (login, verify, bank)")
    if len(url) > 75:
        score += 20
        reasons.append("رابط طويل جداً")
    if re.search(r"\d+\.\d+\.\d+\.\d+", url):
        score += 50
        reasons.append("يستخدم عنوان IP مباشر")

    is_phishing = score >= 50
    return {
        "url": data.url,
        "is_phishing": is_phishing,
        "score": score,
        "risk": "عالي 🔴" if is_phishing else "آمن 🟢",
        "reasons": reasons if reasons else ["لا يوجد مؤشرات تصيد"]
    }
