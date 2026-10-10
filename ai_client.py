import os
import google.generativeai as genai

RAW_KEYS = os.getenv("GEMINI_API_KEY", "")
GEMINI_KEYS = [k.strip() for k in RAW_KEYS.split(",") if k.strip()]
current_key_index = 0

model = None
chat_model = None

def init_gemini():
    global model, chat_model, current_key_index
    if not GEMINI_KEYS:
        return False
    try:
        key = GEMINI_KEYS[current_key_index % len(GEMINI_KEYS)]
        genai.configure(api_key=key)
        
        generation_config = {
            "temperature": 0.9,
            "top_p": 0.95,
            "top_k": 40,
            "max_output_tokens": 1500,
        }
        
        # غيرنا لـ 2.0-flash أذكى وأسرع وما ينحظر بسرعة
        model = genai.GenerativeModel(
            "gemini-2.0-flash",
            generation_config=generation_config
        )
        
        chat_model = genai.GenerativeModel(
            "gemini-2.0-flash",
            generation_config=generation_config,
            system_instruction="""
انت طمّن AI - خبير أمن سيبراني سعودي ومساعد ذكي خارق.

ذكاءك:
- تفهم النية حتى لو الكلام ملخبط
- تجاوب بذكاء، تحلل، تعطي أمثلة حقيقية وخطوات عملية
- لهجتك سعودية عامية بيضاء، ذكية، مرحة، مو روبوتية
- تعرف: اختراق، احتيال، روابط، تقنية، برمجة، حياة عامة، نكت، سوالف

قوانينك:
1- لا تكرر نفس الجملة أبداً - كل رد مختلف ومخصص
2- اذا سأل "كيف احمي نفسي" اعطيه خطة ذكية حسب سؤاله مو نسخ لصق
3- اذا سأل سؤال تقني اشرح السبب والحل بمثال
4- كن ودود كأنك صديقه المقرب
5- ممنوع تقول: "حياك! أنا مساعد طمّن اسألني عن الحماية"
"""
        )
        return True
    except Exception as e:
        print(f"Init error: {e}")
        return False

init_gemini()

def ask_gemini(prompt: str) -> str:
    global current_key_index
    if not GEMINI_KEYS: return ""
    for _ in range(len(GEMINI_KEYS)):
        try:
            if not model: init_gemini()
            res = model.generate_content(prompt)
            return res.text.strip()
        except Exception as e:
            print(f"Error: {e}")
            current_key_index = (current_key_index + 1) % len(GEMINI_KEYS)
            init_gemini()
    return ""

def chat_with_tamman(user_message: str, history=[]):
    global current_key_index
    if not GEMINI_KEYS:
        return "هلا والله! المفتاح مو مضبوط في Render، تأكد من GEMINI_API_KEY"
    for _ in range(len(GEMINI_KEYS)):
        try:
            if not chat_model: init_gemini()
            chat_history = []
            # صلحنا مشكلة النسيان - صار يتذكر 12 رسالة
            for h in history[-12:]:
                role = "user" if h.get("role") == "user" else "model"
                chat_history.append({"role": role, "parts": [h.get("content","")]})
            chat = chat_model.start_chat(history=chat_history)
            res = chat.send_message(user_message)
            return res.text.strip()
        except Exception as e:
            print(f"Chat error: {e}")
            current_key_index = (current_key_index + 1) % len(GEMINI_KEYS)
            init_gemini()
    return "معليش صار ضغط على الذكاء الاصطناعي، جرب بعد ثواني 🙏"
