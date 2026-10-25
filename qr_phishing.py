"""QR-code phishing ("quishing") analysis. Heuristic only: nothing is fetched or visited,
so there is no SSRF risk and no verdict of maliciousness is claimed."""
import ipaddress
import re
from urllib.parse import parse_qs, urlsplit

from typosquatting import generate_variants

MAX_IMAGE_BYTES = 2_000_000
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "ow.ly", "rebrand.ly",
              "buff.ly", "shorturl.at", "tiny.cc", "rb.gy", "qr.io", "qrco.de", "l.ead.me"}
RISKY_TLDS = {"zip", "mov", "top", "xyz", "click", "link", "support", "rest", "cam", "work",
              "tk", "ml", "ga", "cf", "gq", "country", "icu", "buzz"}
KEYWORDS = ("login", "signin", "sign-in", "verify", "update", "secure", "account", "password",
            "wallet", "invoice", "payment", "mfa", "reset", "unlock", "auth", "billing", "refund")
REDIRECT_PARAMS = {"url", "redirect", "redirect_uri", "next", "continue", "dest", "destination",
                   "target", "return", "returnurl", "goto", "link"}
NON_URL_SCHEMES = ("wifi:", "tel:", "sms:", "smsto:", "mailto:", "begin:vcard", "geo:", "bitcoin:")


def decode_qr(data: bytes) -> list[str]:
    """Decode every QR code found in an image. Needs opencv-python-headless."""
    if len(data) > MAX_IMAGE_BYTES:
        raise ValueError("Image too large (max 2 MB).")
    import cv2
    import numpy as np
    img = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("Not a readable image.")
    h, w = img.shape[:2]
    if max(h, w) > 3000:  # bound CPU cost
        scale = 3000 / max(h, w)
        img = cv2.resize(img, (int(w * scale), int(h * scale)))
    det = cv2.QRCodeDetector()
    texts: list[str] = []
    try:
        ok, decoded, _, _ = det.detectAndDecodeMulti(img)
        if ok:
            texts = [t for t in decoded if t]
    except cv2.error:
        pass
    if not texts:
        text, _, _ = det.detectAndDecode(img)
        if text:
            texts = [text]
    return list(dict.fromkeys(texts))[:5]


def defang(url: str) -> str:
    return url.replace("http", "hxxp", 1).replace(".", "[.]")


def _registered(host: str) -> str:
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def analyze_payload(text: str, brand_domain: str = "") -> dict:
    text = (text or "").strip()[:2048]
    result = {"payload": text[:300], "type": "text", "signals": [], "verdict": "no_signals",
              "risk_score": None,
              "note": "Heuristic signals only. The URL was not visited; manually verify with trusted sources."}
    low = text.lower()
    if low.startswith(NON_URL_SCHEMES):
        result["type"] = "non_url"
        result["signals"].append({"signal": "non_http_payload",
                                  "detail": "QR contains a non-web action (e.g. Wi-Fi join, call, SMS, contact)."})
        result["verdict"] = "some_signals"
        return result
    candidate = text if re.match(r"^[a-z][a-z0-9+.-]*://", low) else ("http://" + text if "." in text and " " not in text else "")
    if not candidate:
        return result
    try:
        parts = urlsplit(candidate)
        host = (parts.hostname or "").lower().rstrip(".")
    except ValueError:
        host = ""
    if parts.scheme not in ("http", "https") or not host:
        result["type"] = "other_scheme"
        result["signals"].append({"signal": "unusual_scheme", "detail": f"Scheme '{parts.scheme}' is not http(s)."})
        result["verdict"] = "some_signals"
        return result

    result.update(type="url", url_defanged=defang(candidate), host=host)
    sig = result["signals"]
    add = lambda s, d: sig.append({"signal": s, "detail": d})

    try:
        ipaddress.ip_address(host)
        add("ip_host", "URL uses a raw IP address instead of a domain name.")
        is_ip = True
    except ValueError:
        is_ip = False
    result["host_is_ip"] = is_ip
    if parts.scheme == "http":
        add("no_tls", "Plain http (no TLS).")
    if parts.username or "@" in parts.netloc:
        add("userinfo_in_url", "URL contains user info before the host, a common disguise.")
    if parts.port and parts.port not in (80, 443):
        add("odd_port", f"Non-standard port {parts.port}.")
    if not is_ip:
        labels = host.split(".")
        if any(l.startswith("xn--") for l in labels) or not host.isascii():
            add("idn_or_punycode", "Internationalized/punycode host: possible homograph lookalike.")
        if host in SHORTENERS or _registered(host) in SHORTENERS:
            add("url_shortener", "Known shortener/QR redirector hides the real destination.")
        if labels[-1] in RISKY_TLDS:
            add("risky_tld", f"TLD '.{labels[-1]}' is frequently abused.")
        if len(labels) > 4:
            add("deep_subdomains", "Many subdomain levels, often used to bury the real domain.")
        if host.count("-") >= 3:
            add("many_hyphens", "Host contains many hyphens.")
    path_q = (parts.path + "?" + parts.query).lower()
    hits = [k for k in KEYWORDS if k in path_q or k in host]
    if hits:
        add("credential_keywords", "Contains account/credential wording: " + ", ".join(hits[:5]))
    for k, vals in parse_qs(parts.query).items():
        if k.lower() in REDIRECT_PARAMS and any(v.lower().startswith(("http", "//")) for v in vals):
            add("open_redirect_param", f"Query parameter '{k}' carries another URL.")
            break
    if len(candidate) > 200:
        add("very_long_url", "Unusually long URL.")
    brand = (brand_domain or "").strip().lower()
    if brand and not is_ip:
        try:
            variants = set(generate_variants(brand))
        except ValueError:
            variants = set()
        reg = _registered(host)
        if reg in variants:
            add("lookalike_of_brand", f"Registered domain {reg} is a generated lookalike of {brand}.")
        elif reg != _registered(brand) and brand.split(".")[0] in host:
            add("brand_in_foreign_domain", f"Host mentions '{brand.split('.')[0]}' but belongs to {reg}.")
    result["verdict"] = ("no_signals" if not sig else "some_signals" if len(sig) < 3 else "multiple_signals")
    return result
