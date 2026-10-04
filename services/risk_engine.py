"""Risk engine: combines all analyzers into one score, class, explanation, advice.
Hybrid mode: if a trained ML model exists, final = 70% rules + 30% ML probability."""
from services.sender_analyzer import analyze_sender
from services.content_analyzer import analyze_content
from services.url_analyzer import analyze_urls
from services.attachment_analyzer import analyze_attachment

RULE_WEIGHT, ML_WEIGHT = 0.7, 0.3

ADVICE = {
    "SAFE": ["No strong phishing signs found. Still, never share passwords by email."],
    "LOW RISK": ["Few weak signals. Double-check the sender before clicking anything.",
                 "Hover over links to preview the real destination."],
    "SUSPICIOUS": ["Do not click links or open attachments.",
                   "Verify the request through the official website or a known phone number.",
                   "Report it to your IT/security team."],
    "HIGH RISK / LIKELY PHISHING": ["Do NOT click links, open attachments or reply.",
                                    "Never enter credentials; if you did, change your password and enable MFA.",
                                    "Report as phishing and delete the email."],
}


def classify(score: int) -> str:
    if score < 15:
        return "SAFE"
    if score < 35:
        return "LOW RISK"
    if score < 60:
        return "SUSPICIOUS"
    return "HIGH RISK / LIKELY PHISHING"


def analyze_email(sender, subject, body, attachment="", ml_predict=None) -> dict:
    s = analyze_sender(sender)
    c = analyze_content(subject, body)
    urls = analyze_urls(body)
    a = analyze_attachment(attachment)

    findings = []
    for src, items in (("Sender", s["findings"]), ("Content", c["findings"]), ("Attachment", a)):
        findings += [dict(f, source=src) for f in items]
    for u in urls:
        findings += [dict(f, source="URL", detail=f"{f['detail']} ({u['host'] or u['url'][:30]})")
                     for f in u["findings"]]

    rule_score = min(100, sum(f["points"] for f in findings))
    # Several independent categories firing together is stronger evidence
    categories = {f["source"] for f in findings}
    if len(categories) >= 3:
        rule_score = min(100, rule_score + 10)

    ml_prob, score = None, rule_score
    if ml_predict:
        ml_prob = ml_predict(f"{subject or ''} {body or ''}")
        score = round(RULE_WEIGHT * rule_score + ML_WEIGHT * ml_prob * 100)

    label = classify(score)
    findings.sort(key=lambda f: f["points"], reverse=True)
    return {
        "risk_score": int(score), "rule_score": int(rule_score),
        "ml_probability": None if ml_prob is None else round(ml_prob, 3),
        "classification": label, "indicators": findings,
        "sender": s, "urls": urls, "keywords": c["keywords"],
        "recommendations": ADVICE[label],
        "explanation": (f"{len(findings)} indicator(s) across {len(categories)} categor"
                        f"{'y' if len(categories) == 1 else 'ies'}. Top: "
                        + (", ".join(f['indicator'] for f in findings[:3]) or "none") + "."),
    }
