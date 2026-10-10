import sqlite3
import time
import json

DB_PATH = "tamman.db"

def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn

def init_db():
    conn = get_conn()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS cache
                 (url TEXT PRIMARY KEY, result TEXT, time REAL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS live
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, url_mask TEXT, full_url TEXT, is_bad INTEGER, time REAL)''')
    conn.commit()
    conn.close()

def get_cache(url):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT result, time FROM cache WHERE url=?", (url,))
    row = c.fetchone()
    conn.close()
    if row:
        result_text, t = row
        if time.time() - t < 604800: # 7 ايام
            return json.loads(result_text)
    return None

def save_cache(url, result):
    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO cache (url, result, time) VALUES (?,?,?)",
              (url, json.dumps(result, ensure_ascii=False), time.time()))
    conn.commit()
    conn.close()

def add_live(url_mask, full_url, is_bad):
    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT INTO live (url_mask, full_url, is_bad, time) VALUES (?,?,?,?)",
              (url_mask, full_url, 1 if is_bad else 0, time.time()))
    c.execute("DELETE FROM live WHERE id NOT IN (SELECT id FROM live ORDER BY time DESC LIMIT 50)")
    conn.commit()
    conn.close()

def get_live():
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT url_mask, full_url, is_bad, time FROM live WHERE time >? ORDER BY time DESC LIMIT 5",
              (time.time() - 60,))
    rows = c.fetchall()
    conn.close()
    return [{"url": r[0], "full": r[1], "isBad": bool(r[2]), "time": r[3]} for r in rows]

init_db()
