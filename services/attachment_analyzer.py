"""Attachment analysis by FILENAME only (files are never opened or executed)."""
DANGEROUS = {"exe", "scr", "bat", "cmd", "js", "vbs", "ps1", "jar", "msi", "com", "lnk"}
MACRO = {"docm", "xlsm", "pptm"}
ARCHIVE = {"zip", "rar", "7z", "iso"}
DOC_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "txt", "jpg", "png"}


def analyze_attachment(filename: str) -> list:
    name = (filename or "").strip().lower()
    if not name:
        return []
    parts = name.split(".")
    ext = parts[-1] if len(parts) > 1 else ""
    out = []
    if len(parts) > 2 and parts[-2] in DOC_EXT and ext in DANGEROUS | ARCHIVE | MACRO:
        out.append({"indicator": "Double file extension", "points": 25,
                    "detail": f"'{name}' pretends to be a .{parts[-2]} file."})
    elif ext in DANGEROUS:
        out.append({"indicator": "Executable attachment", "points": 25, "detail": f".{ext} files can run code."})
    elif ext in MACRO:
        out.append({"indicator": "Macro-enabled document", "points": 15, "detail": f".{ext} can contain macros."})
    elif ext in ARCHIVE:
        out.append({"indicator": "Archive attachment", "points": 8, "detail": f".{ext} can hide malicious files."})
    return out
