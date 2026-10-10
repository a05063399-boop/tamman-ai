import json
from ai_client import ask_gemini
from ai_prompts import build_saudi_prompt

def explain_with_ai(url, score, reasons, vt_str):
    fallback = {
        "verdict": "خطير 🔴" if score >= 75 else "مشبوه 🟡" if score >=45 else "آمن 🟢",
        "trick": reasons[0] if reasons else "ما فيه خدعة واضحة",
        "what_if": "ممكن تنسرق بياناتك" if score>=45 else "ما فيه خطر",
        "advice": "لا تدخل الرابط واحذفه" if score>=45 else "الرابط سليم"
    }

    prompt = build_saudi_prompt(url, score, reasons, vt_str)
    raw = ask_gemini(prompt)

    if not raw:
        return fallback

    try:
        cleaned = raw.replace("```json","").replace("```","").strip()
        data = json.loads(cleaned)
        return {
            "verdict": data.get("verdict", fallback["verdict"]),
            "trick": data.get("trick", fallback["trick"]),
            "what_if": data.get("what_if", fallback["what_if"]),
            "advice": data.get("advice", fallback["advice"])
        }
    except:
        return fallback
