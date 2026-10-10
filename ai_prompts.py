def build_saudi_prompt(url, score, reasons, vt_str):
    reasons_str = "; ".join(reasons[:3]) if reasons else "ما فيه أدلة واضحة"
    level = "آمن" if score < 45 else "مشبوه" if score < 75 else "خطير مرة"

    return f"""
أنت طَمّن، خبير أمن سيبراني سعودي، تشرح باللهجة السعودية البيضاء البسيطة.

الرابط: {url}
الخطورة: {score}/100 ({level})
الأدلة: {reasons_str}
فحص VirusTotal: {vt_str}

رجع JSON فقط بهالشكل:
{{
  "verdict": "آمن 🟢 أو مشبوه 🟡 أو خطير 🔴",
  "trick": "وش الخدعة بجملة عامية",
  "what_if": "لو دخلت وش بيصير؟",
  "advice": "وش تسوي الآن؟"
}}
"""
