from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import re, os
from openai import OpenAI

app = FastAPI(title="Tamman AI - طمّن")

# هذا يحل مشكلة الربط مع موقعك
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

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

# واجهة الموقع الجديدة
@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <html dir="rtl" lang="ar">
    <head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>طمّن - كاشف الروابط</title>
    <style>
    body{font-family:Tahoma;background:#0f172a;color:white;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}
   .box{background:#1e293b;padding:30px;border-radius:20px;width:90%;max-width:500px;text-align:center;box-shadow:0 10px 30px rgba(0,0,0,.5)}
    input{width:100%;padding:15px;border-radius:10px;border:none;margin:15px 0;font-size:16px}
    button{background:#22c55e;color:white;padding:12px 30px;border:none;border-radius:10px;font-size:18px;cursor:pointer;width:100%}
    #result{margin-top:20px;padding:15px;border-radius:10px;background:#0f172a;text-align:right;white-space:pre-wrap}
    </style></head>
    <body>
    <div class="box">
    <h1>🛡️ طمّن</h1><p>الصق الرابط المشبوه هنا ونتحقق لك</p>
    <input id="url" placeholder="https://example.com">
    <button onclick="check()">افحص الآن</button>
    <div id="result"></div>
    </div>
    <script>
    async function check(){
      let url=document.getElementById('url').value;
      let r=document.getElementById('result');
      if(!url){r.innerText='حط رابط أول';return}
      r.innerText='جاري الفحص...';
      let res=await fetch('/check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:url})});
      let data=await res.json();
      r.innerHTML=`<b>الرابط:</b> ${data.url}<br><b>الخطورة:</b> ${data.risk}<br><b>النقاط:</b> ${data.score}<br><b>الأسباب:</b> ${data.reasons.join(', ')||'لا يوجد'}<br><br><b>تحليل AI:</b> ${data.ai_analysis}`;
    }
    </script></body></html>
    """

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
