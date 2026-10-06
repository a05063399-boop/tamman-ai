import base64
import os
import re
import time
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from openai import OpenAI
from pydantic import BaseModel
import requests

# 1. تهيئة التطبيق والإعدادات
app = FastAPI(title="طَمَّن AI - فاحص الروابط")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# مفاتيح API من البيئة
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")

client = None
if OPENAI_API_KEY:
    try:
        client = OpenAI(api_key=OPENAI_API_KEY)
    except Exception as e:
        print(f"خطأ في تهيئة OpenAI client: {e}")

# 2. النماذج (Pydantic Models)
class URLCheck(BaseModel):
    url: str

# 3. الدوال المساعدة (Helper Functions)
def check_virustotal(url_to_scan: str):
    """فحص الرابط عبر API الخاص بـ VirusTotal"""
    if not VT_API_KEY:
        print("تنبيه: مفتاح VT_API_KEY غير متوفر!")
        return 0, 0
    try:
        headers = {"x-apikey": VT_API_KEY}
        # تشفير الرابط حسب متطلبات VirusTotal Base64
        url_id = base64.urlsafe_b64encode(url_to_scan.encode()).decode().strip("=")
        
        # المحاولة الأولى: الحصول على تقرير سابق (أسرع)
        res = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}", 
            headers=headers, 
            timeout=20
        )
        if res.status_code == 200:
            stats = res.json()['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0) + stats.get('suspicious', 0)
            total = sum(stats.values())
            print(f"تقرير VT قديم: {malicious}/{total}")
            return malicious, total

        # المحاولة الثانية: طلب فحص جديد
        res = requests.post(
            "https://www.virustotal.com/api/v3/urls", 
            headers=headers, 
            data={"url": url_to_scan}, 
            timeout=20
        )
        if res.status_code != 200:
            print(f"فشل إرسال الطلب لـ VT: {res.text}")
            return 0, 0
            
        analysis_id = res.json()['data']['id']
        time.sleep(6)  # الانتظار حتى اكتمال الفحص
        
        report = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", 
            headers=headers, 
            timeout=20
        ).json()
        stats = report['data']['attributes']['stats']
        malicious = stats.get('malicious', 0) + stats.get('suspicious', 0)
        total = sum(stats.values())
        return malicious, total

    except Exception as e:
        print(f"خطأ في VirusTotal: {e}")
        return 0, 0

def get_ai_reply(url: str, score: int, reasons: list, vt_result: str):
    """توليد التقرير باللهجة السعودية باستخدام OpenAI"""
    if not client:
        return "تم التحليل بدون الذكاء الاصطناعي (أضف مفتاح OPENAI_API_KEY للتفعيل)"
    try:
        prompt = (
            f"الرابط: {url}\n"
            f"درجة الخطورة: {score}\n"
            f"الأسباب: {', '.join(reasons)}\n"
            f"نتيجة VirusTotal: {vt_result}\n"
            "اشرح باللهجة السعودية هل هو آمن ولا تصيد، باختصار ومطمئن."
        )
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system", 
                    "content": "أنت طَمّن، خبير أمن سيبراني سعودي، تشرح بلهجة سعودية بسيطة ومطمئنة."
                },
                {"role": "user", "content": prompt}
            ]
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"تعذر الحصول على تحليل الذكاء الاصطناعي: {str(e)}"

# 4. مسارات API (Routes)
@app.get("/")
def serve_index():
    return FileResponse("index.html")

@app.get("/api")
def home():
    return {"status": "Tamman AI is running"}

@app.post("/check")
def check_url(data: URLCheck):
    url = data.url.lower()
    score = 0
    reasons = []

    # 1. فحص القواعد الأسلوبية (Heuristic Rules)
    if re.search(r"@|\.tk|\.ml|\.ga|bit\.ly|tinyurl", url):
        score += 40
        reasons.append("رابط مختصر أو نطاق مشبوه")
        
    if url.count("-") > 3 or url.count(".") > 4:
        score += 30
        reasons.append("عدد كبير من الشرطات والنقاط")
        
    if re.search(r"login|verify|bank|secure|update|free|gift", url) and not any(x in url for x in ["tamman.sa", "google.com"]):
        score += 30
        reasons.append("حتوي على كلمات تصيد شائعة (login, verify, bank...)")
        
    if len(url) > 75:
        score += 20
        reasons.append("عنوان الرابط طويل جداً")
        
    if re.search(r"\d+\.\d+\.\d+\.\d+", url):
        score += 50
        reasons.append("يستخدم عنوان IP مباشر بدلاً من اسم نطاق")

    # 2. فحص VirusTotal
    vt_malicious, vt_total = check_virustotal(data.url)
    vt_summary = "لم يتم اكتشاف تهديدات"
    if vt_malicious > 0:
        score += 50
        vt_summary = f"تم تصنيفه ضار بواسطة {vt_malicious} من أصل {vt_total} محرك فحص"
        reasons.append(f"مُصنف كـ تهديد في VirusTotal ({vt_malicious}/{vt_total})")

    # 3. تحديد النتيجة النهائية
    is_phishing = score >= 50
    ai_text = get_ai_reply(
        url=data.url, 
        score=score, 
        reasons=reasons if reasons else ["لا يوجد مؤشرات تصيد ظاهرة"], 
        vt_result=vt_summary
    )

    return {
        "url": data.url,
        "is_phishing": is_phishing,
        "score": score,
        "risk": "عالي 🔴" if is_phishing else "آمن 🟢",
        "reasons": reasons if reasons else ["لا يوجد مؤشرات تصيد"],
        "virustotal": {
            "malicious": vt_malicious,
            "total": vt_total
        },
        "ai_analysis": ai_text
    }
