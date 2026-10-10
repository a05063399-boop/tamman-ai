import os
import google.generativeai as genai

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
model = None

if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel("gemini-1.5-flash")

def ask_gemini(prompt: str) -> str:
    if not model:
        return ""
    try:
        res = model.generate_content(prompt)
        return res.text.strip()
    except Exception as e:
        print(f"Gemini error: {e}")
        return ""
