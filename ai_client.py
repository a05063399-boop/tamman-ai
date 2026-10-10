import os
import google.generativeai as genai

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
model = None
chat_model = None

if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel("gemini-1.5-flash")
    chat_model = genai.GenerativeModel(
        "gemini-1.5-flash",
        system_instruction="""
انت طمّن AI - مساعد سعودي ذكي وودود جداً.

شخصيتك:
- لهجتك سعودية عامية خفيفة، محترمة ومرحة.
- ذكي جداً، تجاوب على كل شي: أمان سيبراني، تقنية، معلومات عامة، سوالف، نكت.
- لا تكرر نفس الرد أبداً. كل رد لازم يكون جديد.

تعليمات الرد:
- اذا قال "كيف احمي نفسي": اشرح 4 خطوات عملية مختصرة مع ايموجي.
- اذا قال "عطني معلومات": اسأله وش نوع المعلومات واعطه قيمة.
- اذا قال "احبك": رد بلطف وذكاء: "وانا احبك أكثر ❤️ بس لا تعطي قلبك ولا بياناتك لنصاب 😅"
- اذا سأل عن رابط: قله يحطه في تبويب الروابط فوق.
- ردودك قصيرة 2-4 أسطر، مفيدة، وفيها لمسة ذكاء.

ممنوع تكرر: "حياك! أنا مساعد طمّن اسألني عن الحماية من النصب"
"""
    )

def ask_gemini(prompt: str) -> str:
    if not model:
        return ""
    try:
        res = model.generate_content(prompt)
        return res.text.strip()
    except Exception as e:
        print(f"Gemini error: {e}")
        return ""

def chat_with_tamman(user_message: str, history=[]):
    if not chat_model:
        return fallback_smart(user_message)
    try:
        # نستبعد اخر رسالة عشان لا تتكرر
        chat_history = []
        for h in history[:-1][-8:]:
            role = "user" if h["role"] == "user" else "model"
            chat_history.append({"role": role, "parts": [h["content"]]})
        chat = chat_model.start_chat(history=chat_history)
        res = chat.send_message(user_message)
        return res.text.strip()
    except Exception as e:
        print(f"Gemini chat error: {e}")
        return fallback_smart(user_message)

def fallback_smart(msg):
    ml = msg.lower()
    if "احمي" in ml:
        return "حمايتك بسيطة 🛡️\n1- لا تفتح أي رابط غريب حتى من صديقك\n2- فعل التحقق بخطوتين\n3- لا تشارك كود OTP أبداً\n4- أي شي شاك فيه افحصه في طمّن فوق"
    if "احبك" in ml or "حبك" in ml:
        return "حبيبي والله وأنا أحبك أكثر ❤️ بس انتبه، النصابين يستغلون الطيبة، لا تعطي معلوماتك لأحد 😉"
    if "معلومات" in ml:
        return "أبشر! أنا أعرف عن الأمان، التقنية، البرمجة، وحتى معلومات عامة. وش الموضوع اللي ودك تعرف عنه؟"
    if "هلا" in ml or "سلام" in ml:
        return "هلااا والله وغلا فيك 👋 نورت طمّن! تبيني أفحص لك رابط ولا أعطيك نصيحة تحميك؟"
    return "حياك يا بطل! أنا طمّن AI 🤖 أقدر أساعدك في الحماية، التقنية، وأي سؤال يخطر ببالك. وش عندك؟"
