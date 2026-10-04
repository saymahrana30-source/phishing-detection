"""Content analysis: urgency, credential/financial requests, threats, greeting."""
import re

GROUPS = {
    "Urgency language": (10, ["urgent", "immediately", "act now", "within 24 hours", "expires today",
                              "final notice", "last warning", "right away", "asap"]),
    "Credential request": (18, ["password", "verify your account", "confirm your identity", "login details",
                                "security code", "otp", "sign in to verify", "update your credentials"]),
    "Financial request": (14, ["wire transfer", "gift card", "invoice attached", "payment failed",
                               "bank details", "refund", "update your billing", "bitcoin"]),
    "Threatening language": (12, ["account will be suspended", "account suspended", "legal action",
                                  "will be closed", "permanently locked", "unauthorized activity"]),
    "Too-good-to-be-true offer": (10, ["you have won", "congratulations", "claim your prize",
                                       "free gift", "lottery", "selected winner"]),
}
GENERIC_GREETING = re.compile(r"\b(dear (customer|user|member|client|account holder)|valued customer)\b", re.I)


def analyze_content(subject: str, body: str) -> dict:
    text = f"{subject or ''}\n{body or ''}".lower()
    findings, keywords = [], []

    for name, (pts, words) in GROUPS.items():
        hits = [w for w in words if w in text]
        if hits:
            keywords += hits
            # more hits in one group = slightly higher, capped
            extra = min(len(hits) - 1, 2) * pts // 4
            findings.append({"indicator": name, "points": pts + extra,
                             "detail": "Matched: " + ", ".join(hits[:4])})

    if GENERIC_GREETING.search(text):
        findings.append({"indicator": "Generic greeting", "points": 6,
                         "detail": "Impersonal greeting instead of your real name."})

    letters = [c for c in (subject or "") + (body or "") if c.isalpha()]
    if len(letters) > 20 and sum(c.isupper() for c in letters) / len(letters) > 0.35:
        findings.append({"indicator": "Excessive capitals", "points": 6,
                         "detail": "Large share of ALL-CAPS text (pressure tactic)."})
    if (subject or "").count("!") + (body or "").count("!") >= 3:
        findings.append({"indicator": "Excessive exclamation marks", "points": 4,
                         "detail": "Three or more '!' used."})
    if not (subject or "").strip():
        findings.append({"indicator": "Empty subject", "points": 4, "detail": "No subject line."})
    if not (body or "").strip():
        findings.append({"indicator": "Empty body", "points": 4, "detail": "Email body is empty."})
    return {"findings": findings, "keywords": keywords}
