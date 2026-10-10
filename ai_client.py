import os
from google import genai

RAW_KEYS = os.getenv("GEMINI_API_KEY", "")
GEMINI_KEYS = [k.strip() for k in RAW_KEYS.split(",") if k.strip()]
current_key_index = 0

SYSTEM_PROMPT = """
انت طمّن AI - خبير أمن سيبراني سعودي ومساعد ذكي خارق.
ذكاءك:
- تفهم النية حتى لو الكلام ملخبط
- تجاوب بذكاء، تحلل، تعطي أمثلة حقيقية وخطوات عملية
- لهجتك سعودية عامية بيضاء، ذكية، مرحة، مو روبوتية
- تعرف: اختراق، احتيال، روابط، تقنية، برمجة، حياة عامة، نكت، سوالف
قوانينك:
1- لا تكرر نفس الجملة أبداً
2- اذا سأل "كيف احمي نفسي" اعطيه خطة ذكية حسب سؤاله
3- اذا سأل سؤال تقني اشرح السبب والحل بمثال
4- كن ودود كأنك صديقه المقرب
"""

def get_client():
    global current_key_index
    if not GEMINI_KEYS:
        return None, None
    for i in range(len(GEMINI_KEYS)):
        idx = (current_key_index + i) % len(GEMINI_KEYS)
        key = GEMINI_KEYS[idx]
        try:
            client = genai.Client(api_key=key)
            current_key_index = idx
            return client, key
        except Exception as e:
            print(f"Key init failed: {e}")
            continue
    return None, None

def ask_gemini(prompt: str) -> str:
    global current_key_index
    if not GEMINI_KEYS:
        return ""
    last_error = None
    for _ in range(len(GEMINI_KEYS)):
        client, key = get_client()
        if not client:
            break
        try:
            print(f"Trying key...{key[-6:]}")
            res = client.models.generate_content(
                model="gemini-2.0-flash",
                contents=prompt
            )
            return res.text.strip()
        except Exception as e:
            last_error = e
            print(f"Error with key...{key[-6:]}: {e}")
            current_key_index = (current_key_index + 1) % len(GEMINI_KEYS)
            continue
    print(f"All keys failed: {last_error}")
    return ""

def chat_with_tamman(user_message: str, history=[]):
    if not GEMINI_KEYS:
        return "هلا والله! المفتاح مو مضبوط في Render، تأكد من GEMINI_API_KEY"

    # نبني المحادثة كاملة
    contents = SYSTEM_PROMPT + "\n\n"
    for h in history[-12:]:
        role = "المستخدم" if h.get("role") == "user" else "المساعد"
        contents += f"{role}: {h.get('content','')}\n"
    contents += f"المستخدم: {user_message}\nالمساعد:"

    result = ask_gemini(contents)
    if not result:
        return "معليش صار ضغط على الذكاء الاصطناعي، جرب بعد ثواني 🙏"
    return result
