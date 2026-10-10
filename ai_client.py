import os
import google.generativeai as genai

# يقرا المفتاح من Render فقط
RAW_KEYS = os.getenv("GEMINI_API_KEY", "")
GEMINI_KEYS = [k.strip() for k in RAW_KEYS.split(",") if k.strip()]
current_key_index = 0

model = None
chat_model = None

def init_gemini():
    global model, chat_model, current_key_index
    if not GEMINI_KEYS:
        print("No GEMINI_API_KEY found")
        return False
    try:
        key = GEMINI_KEYS[current_key_index % len(GEMINI_KEYS)]
        genai.configure(api_key=key)
        model = genai.GenerativeModel("gemini-1.5-flash")
        chat_model = genai.GenerativeModel(
            "gemini-1.5-flash",
            system_instruction="""
انت طمّن AI - مساعد سعودي ذكي وودود جداً.
لهجتك سعودية عامية خفيفة، محترمة ومرحة.
ذكي جداً، تجاوب على كل شي: أمان سيبراني، تقنية، معلومات عامة، سوالف.
لا تكرر نفس الرد أبداً.
- اذا قال "كيف احمي نفسي": اشرح 4 خطوات عملية مختصرة مع ايموجي.
- اذا قال "احبك": "وانا احبك أكثر ❤️ بس لا تعطي قلبك ولا بياناتك لنصاب 😅"
- اذا سأل عن رابط: قله يحطه في تبويب الروابط فوق.
- ردودك قصيرة 2-4 أسطر.
"""
        )
        return True
    except Exception as e:
        print(f"Gemini init error: {e}")
        return False

init_gemini()

def ask_gemini(prompt: str) -> str:
    global current_key_index
    if not GEMINI_KEYS:
        return ""
    for _ in range(len(GEMINI_KEYS)):
        try:
            if not model:
                init_gemini()
            res = model.generate_content(prompt)
            return res.text.strip()
        except Exception as e:
            print(f"Gemini error key {current_key_index}: {e}")
            current_key_index = (current_key_index + 1) % len(GEMINI_KEYS)
            init_gemini()
    return ""

def chat_with_tamman(user_message: str, history=[]):
    global current_key_index
    if not GEMINI_KEYS:
        return fallback_smart(user_message)
    for _ in range(len(GEMINI_KEYS)):
        try:
            if not chat_model:
                init_gemini()
            chat_history = []
            for h in history[:-1][-8:]:
                role = "user" if h["role"] == "user" else "model"
                chat_history.append({"role": role, "parts": [h["content"]]})
            chat = chat_model.start_chat(history=chat_history)
            res = chat.send_message(user_message)
            return res.text.strip()
        except Exception as e:
            print(f"Gemini chat error key {current_key_index}: {e}")
            current_key_index = (current_key_index + 1) % len(GEMINI_KEYS)
            init_gemini()
    return fallback_smart(user_message)

def fallback_smart(msg):
    ml = msg.lower()
    if "احمي" in ml:
        return "حمايتك بسيطة 🛡️\n1- لا تفتح أي رابط غريب\n2- فعل التحقق بخطوتين\n3- لا تشارك كود OTP أبداً\n4- افحص أي شي شاك فيه في طمّن فوق"
    if "احبك" in ml or "حبك" in ml:
        return "حبيبي وأنا أحبك أكثر ❤️ بس انتبه لا تعطي معلوماتك لأحد 😉"
    if "هلا" in ml or "سلام" in ml:
        return "هلااا والله وغلا فيك 👋 نورت طمّن! تبيني أفحص لك رابط ولا أعطيك نصيحة؟"
    return "حياك يا بطل! أنا طمّن AI 🤖 أقدر أساعدك في الحماية وأي سؤال. وش عندك؟"
