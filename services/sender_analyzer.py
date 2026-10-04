"""Sender analysis: checks the From address for common spoofing patterns."""
import re

BRANDS = ["paypal", "microsoft", "google", "amazon", "apple", "netflix",
          "bank", "dhl", "fedex", "facebook", "instagram", "linkedin"]
SUSPICIOUS_TLDS = {"xyz", "top", "click", "zip", "work", "loan", "support", "icu", "gq", "tk"}
FREE_MAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "proton.me"}
LOOKALIKE = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "7": "t"})
ADDR_RE = re.compile(r"^[\w.+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)$")


def analyze_sender(sender: str) -> dict:
    """Return {'domain': str, 'findings': [{'indicator','points','detail'}]}."""
    findings = []
    sender = (sender or "").strip()
    # Pull the address out of  "Display Name <addr@domain>"
    m = re.search(r"<([^>]+)>", sender)
    display = sender.split("<")[0].strip().strip('"').lower() if m else ""
    address = m.group(1).strip() if m else sender

    def add(name, pts, detail):
        findings.append({"indicator": name, "points": pts, "detail": detail})

    match = ADDR_RE.match(address)
    if not match:
        add("Invalid sender address", 15, "Sender is missing or not a valid email address.")
        return {"domain": "", "findings": findings}

    domain = match.group(1).lower()
    labels = domain.split(".")
    tld = labels[-1]
    main = labels[-2]

    if tld in SUSPICIOUS_TLDS:
        add("Suspicious TLD", 12, f"Domain ends in .{tld}, often abused in phishing.")
    if len(labels) > 3:
        add("Excessive subdomains", 8, f"'{domain}' has many subdomain levels.")
    if re.search(r"\d", main) and any(b in main.translate(LOOKALIKE) for b in BRANDS):
        add("Look-alike domain", 25, f"'{main}' imitates a known brand using digits.")
    elif any(b in main for b in BRANDS) and "-" in main:
        add("Brand + hyphen domain", 15, f"'{main}' mixes a brand name with extra words.")
    if display and any(b in display for b in BRANDS) and not any(b in main for b in BRANDS):
        add("Display-name mismatch", 20,
            f"Display name '{display}' claims a brand but the domain is '{domain}'.")
    if domain in FREE_MAIL and any(w in display for w in ("support", "security", "billing", "admin", "hr")):
        add("Free mail posing as official", 12, "Official-sounding name sent from a free mail service.")
    if sum(c.isdigit() for c in address.split("@")[0]) >= 4:
        add("Many digits in address", 5, "Local part contains many digits (auto-generated look).")
    return {"domain": domain, "findings": findings}
