"""Flask backend: serves the dashboard and a small JSON API."""
import os
from email import policy
from email.parser import BytesParser
from flask import Flask, jsonify, render_template, request

import db
from ml.predict import load_predictor
from services.risk_engine import analyze_email

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024          # reject uploads > 200 KB
MAX_BODY = int(os.environ.get("MAX_BODY_CHARS", 20000))
db.init_db()
predictor = load_predictor()                            # None if model not trained


@app.route("/")
def index():
    return render_template("index.html", ml_enabled=predictor is not None)


@app.post("/api/analyze")
def analyze():
    data = request.get_json(silent=True) or {}
    sender = str(data.get("sender", ""))[:320]
    subject = str(data.get("subject", ""))[:300]
    body = str(data.get("body", ""))[:MAX_BODY]
    attachment = str(data.get("attachment", ""))[:200]
    if not (sender.strip() or subject.strip() or body.strip()):
        return jsonify(error="Provide at least a sender, subject or body."), 400
    result = analyze_email(sender, subject, body, attachment, predictor)
    db.save(sender, subject, body, result)
    return jsonify(result)


@app.post("/api/parse-eml")
def parse_eml():
    """Extract sender/subject/body from an uploaded .eml/.txt (parsed as text only)."""
    f = request.files.get("file")
    if not f or not f.filename.lower().endswith((".eml", ".txt")):
        return jsonify(error="Upload a .eml or .txt file."), 400
    msg = BytesParser(policy=policy.default).parsebytes(f.read())
    part = msg.get_body(preferencelist=("plain", "html"))
    body = part.get_content() if part else (msg.get_payload() if not msg.is_multipart() else "")
    return jsonify(sender=str(msg["from"] or ""), subject=str(msg["subject"] or ""), body=str(body)[:MAX_BODY])


@app.get("/api/history")
def history():
    return jsonify(db.history())


@app.delete("/api/history")
def clear_history():
    db.clear()
    return jsonify(ok=True)


@app.get("/api/stats")
def stats():
    return jsonify(db.stats())


if __name__ == "__main__":
    # debug=False and localhost-only: safe default for a local learning project
    app.run(host="127.0.0.1", port=5000, debug=False)
