# database.py - قاعدة بيانات مجانية وسريعة لطمن
import sqlite3
import time
import os

DB_PATH = "tamman.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # جدول الكاش (يحفظ النتائج 7 ايام)
    c.execute('''CREATE TABLE IF NOT EXISTS cache
                 (url TEXT PRIMARY KEY, result TEXT, time REAL)''')
    # جدول اللايف (آخر 50 رابط تم فحصه)
    c.execute('''CREATE TABLE IF NOT EXISTS live
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, url_mask TEXT, full_url TEXT, is_bad INTEGER, time REAL)''')
    conn.commit()
    conn.close()

def get_cache(url):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT result, time FROM cache WHERE url=?", (url,))
    row = c.fetchone()
    conn.close()
    if row:
        import json
        result_text, t = row
        # اذا اقدم من 7 ايام احذفه
        if time.time() - t < 604800:
            return json.loads(result_text)
    return None

def save_cache(url, result):
    import json
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO cache (url, result, time) VALUES (?,?,?)",
              (url, json.dumps(result, ensure_ascii=False), time.time()))
    conn.commit()
    conn.close()

def add_live(url_mask, full_url, is_bad):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO live (url_mask, full_url, is_bad, time) VALUES (?,?,?,?)",
              (url_mask, full_url, 1 if is_bad else 0, time.time()))
    # احذف القديم وخلي 50 بس
    c.execute("DELETE FROM live WHERE id NOT IN (SELECT id FROM live ORDER BY time DESC LIMIT 50)")
    conn.commit()
    conn.close()

def get_live():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # جيب اللي قبل دقيقة بس
    c.execute("SELECT url_mask, full_url, is_bad, time FROM live WHERE time >? ORDER BY time DESC LIMIT 5",
              (time.time() - 60,))
    rows = c.fetchall()
    conn.close()
    return [{"url": r[0], "full": r[1], "isBad": bool(r[2]), "time": r[3]} for r in rows]

# شغلها اول مرة
init_db()
