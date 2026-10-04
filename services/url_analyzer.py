"""URL analysis. URLs are only PARSED as text - they are never opened or fetched."""
import re
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.I)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly"}
SUSPICIOUS_TLDS = {"xyz", "top", "click", "zip", "work", "loan", "support", "icu", "gq", "tk"}
BAD_WORDS = ["login", "verify", "secure", "update", "account", "confirm", "password", "signin", "banking"]
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def analyze_url(url: str) -> dict:
    findings = []
    p = urlparse(url)
    host = (p.hostname or "").lower()

    def add(name, pts, detail):
        findings.append({"indicator": name, "points": pts, "detail": detail})

    if IP_RE.match(host):
        add("Raw IP address URL", 20, "Link uses an IP address instead of a domain name.")
    if p.scheme != "https":
        add("Non-HTTPS link", 8, "Link is not encrypted (http://).")
    if host in SHORTENERS:
        add("URL shortener", 10, f"{host} hides the real destination.")
    if "@" in p.netloc:
        add("'@' in URL", 15, "Text before '@' can disguise the real host.")
    if host.startswith("xn--") or ".xn--" in host:
        add("Punycode domain", 15, "May be a look-alike using foreign characters.")
    labels = host.split(".")
    if len(labels) > 4:
        add("Excessive subdomains", 8, f"{len(labels)} domain levels in '{host}'.")
    if labels and labels[-1] in SUSPICIOUS_TLDS:
        add("Suspicious TLD", 10, f"Ends in .{labels[-1]}.")
    hits = [w for w in BAD_WORDS if w in url.lower()]
    if hits:
        add("Suspicious keywords in URL", min(5 * len(hits), 15), "Contains: " + ", ".join(hits))
    if host.count("-") >= 3:
        add("Many hyphens in domain", 6, "Hyphen-heavy domains are common in fake sites.")
    if len(url) > 100:
        add("Very long URL", 5, "Long URLs can hide the real destination.")
    return {"url": url, "host": host, "findings": findings,
            "score": sum(f["points"] for f in findings)}


def analyze_urls(text: str) -> list:
    urls = list(dict.fromkeys(URL_RE.findall(text or "")))[:20]  # de-dupe, cap at 20
    return [analyze_url(u) for u in urls]
