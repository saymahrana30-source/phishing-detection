"""SQLite storage. All queries are parameterised (prevents SQL injection)."""
import sqlite3, json, os
from collections import Counter

DB_PATH = os.environ.get("DB_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "analyses.db"))


def _conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with _conn() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT DEFAULT (datetime('now')),
            sender TEXT, subject TEXT, body_preview TEXT,
            risk_score INTEGER, classification TEXT,
            indicators TEXT, keywords TEXT)""")


def save(sender, subject, body, r):
    with _conn() as c:
        c.execute("INSERT INTO analyses (sender,subject,body_preview,risk_score,classification,indicators,keywords)"
                  " VALUES (?,?,?,?,?,?,?)",
                  (sender, subject, (body or "")[:200], r["risk_score"], r["classification"],
                   json.dumps([i["indicator"] for i in r["indicators"]]), json.dumps(r["keywords"])))


def history(limit=100):
    with _conn() as c:
        rows = c.execute("SELECT id,created_at,sender,subject,risk_score,classification FROM analyses "
                         "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


def clear():
    with _conn() as c:
        c.execute("DELETE FROM analyses")


def stats():
    with _conn() as c:
        rows = [dict(r) for r in c.execute("SELECT * FROM analyses").fetchall()]
    total = len(rows)
    classes = Counter(r["classification"] for r in rows)
    inds, kws, trend = Counter(), Counter(), Counter()
    buckets = [0] * 5  # 0-19, 20-39, ...
    for r in rows:
        inds.update(json.loads(r["indicators"] or "[]"))
        kws.update(json.loads(r["keywords"] or "[]"))
        trend[r["created_at"][:10]] += 1
        buckets[min(r["risk_score"] // 20, 4)] += 1
    flagged = classes["SUSPICIOUS"] + classes["HIGH RISK / LIKELY PHISHING"]
    return {
        "total": total,
        "high_risk": classes["HIGH RISK / LIKELY PHISHING"],
        "suspicious": classes["SUSPICIOUS"],
        "low_risk": classes["LOW RISK"],
        "safe": classes["SAFE"],
        "avg_score": round(sum(r["risk_score"] for r in rows) / total, 1) if total else 0,
        "phishing_vs_legit": {"flagged": flagged, "not_flagged": total - flagged},
        "top_indicators": inds.most_common(6),
        "top_keywords": kws.most_common(8),
        "score_buckets": buckets,
        "trend": sorted(trend.items()),
    }
