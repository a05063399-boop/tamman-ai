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
        system_instruction="انت مساعد طمّن، مساعد أمن سيبراني سعودي. لهجتك عامية خفيفة ومفيدة. تساعد الناس تحمي نفسها من النصب. تجاوب باختصار ومباشرة. اذا سألوك عن رابط قل لهم يحطونه فوق في الفحص."
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

# --- الجديد للشات ---
def chat_with_tamman(user_message: str, history=[]):
    if not chat_model:
        return fallback_chat(user_message)
    
    try:
        # نحول history لصيغة جيميني
        chat_history = []
        for h in history[-6:]:
            role = "user" if h["role"] == "user" else "model"
            chat_history.append({"role": role, "parts": [h["content"]]})

        chat = chat_model.start_chat(history=chat_history)
        res = chat.send_message(user_message)
        return res.text.strip()
    except Exception as e:
        print(f"Gemini chat error: {e}")
        return fallback_chat(user_message)

def fallback_chat(msg):
    msg = msg.lower()
    if "سلام" in msg or "هلا" in msg:
        return "هلا والله حياك في طمّن! 👋 كيف أقدر أساعدك؟"
    if "نصب" in msg or "رابط" in msg:
        return "أي رابط مشبوه انسخه وحطه فوق في فحص الروابط وأنا أفحصه لك 🔍"
    return "حياك! أنا مساعد طمّن 🤖 اسألني عن الحماية من النصب أو أي شي ثاني."
