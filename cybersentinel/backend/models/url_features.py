"""
URL Feature Extraction Module - Layer 2
Extracts 15+ features from URLs for Logistic Regression
"""

import re
import math
import ipaddress
from urllib.parse import urlparse, parse_qs
from typing import Dict, List, Tuple
import numpy as np


FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "subdomain_depth",
    "has_ip_host",
    "has_at_sign",
    "has_double_slash",
    "has_dash_in_domain",
    "has_port",
    "digit_ratio",
    "special_char_count",
    "dot_count",
    "slash_count",
    "has_https",
    "has_encoding",
    "has_unicode",
    "path_depth",
    "has_suspicious_tld",
    "has_credential_keyword",
    "query_param_count",
    "has_fragment",
    "entropy",
    "consecutive_digits",
    "subdomain_contains_ip_pattern",
]

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
    ".online", ".site", ".website", ".win", ".bid", ".loan",
    ".download", ".stream", ".racing", ".review",
}

CREDENTIAL_KEYWORDS = [
    "paypal", "ebay", "amazon", "google", "microsoft", "apple",
    "bank", "secure", "login", "signin", "verify", "update",
    "account", "password", "confirm", "webscr", "billing",
]


def _url_entropy(url: str) -> float:
    """Shannon entropy of URL string."""
    if not url:
        return 0.0
    freq = {}
    for c in url:
        freq[c] = freq.get(c, 0) + 1
    total = len(url)
    return -sum((f / total) * math.log2(f / total) for f in freq.values())


def extract_features(url: str) -> Tuple[np.ndarray, Dict[str, float]]:
    """
    Extract numerical features from a URL.
    Returns (feature_vector, feature_dict)
    """
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
    except Exception:
        parsed = urlparse("http://invalid.url")

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""
    full_url = url

    # Core length features
    url_length = len(full_url)
    hostname_length = len(hostname)
    path_length = len(path)
    query_length = len(query)

    # Subdomain analysis
    hostname_parts = hostname.split(".") if hostname else []
    subdomain_depth = max(0, len(hostname_parts) - 2)

    # IP host detection
    has_ip_host = 0
    try:
        ipaddress.ip_address(hostname)
        has_ip_host = 1
    except (ValueError, TypeError):
        # Check for IP-like subdomain patterns
        if re.match(r"\d{1,3}[-_.]\d{1,3}[-_.]\d{1,3}[-_.]\d{1,3}", hostname):
            has_ip_host = 0.5

    # Special character features
    has_at_sign = 1 if "@" in full_url else 0
    has_double_slash = 1 if "//" in full_url[full_url.find("//") + 2:] else 0
    has_dash_in_domain = 1 if "-" in hostname else 0
    has_port = 1 if parsed.port and parsed.port not in (80, 443) else 0

    # Character ratio features
    digits = sum(c.isdigit() for c in full_url)
    digit_ratio = digits / max(len(full_url), 1)
    special_chars = sum(c in "!@#$%^&*()=+[]{}|\\;:'\",<>?" for c in full_url)
    dot_count = full_url.count(".")
    slash_count = full_url.count("/")

    # Protocol
    has_https = 1 if parsed.scheme == "https" else 0

    # Encoding
    has_encoding = 1 if re.search(r"%[0-9a-fA-F]{2}", full_url) else 0
    has_unicode = 1 if re.search(r"%u[0-9a-fA-F]{4}|xn--", full_url, re.I) else 0

    # Path analysis
    path_segments = [s for s in path.split("/") if s]
    path_depth = len(path_segments)

    # TLD suspiciousness
    tld = "." + hostname_parts[-1] if hostname_parts else ""
    has_suspicious_tld = 1 if tld.lower() in SUSPICIOUS_TLDS else 0

    # Credential keywords
    url_lower = full_url.lower()
    has_credential_keyword = min(1, sum(kw in url_lower for kw in CREDENTIAL_KEYWORDS) * 0.5)

    # Query parameters
    try:
        params = parse_qs(query)
        query_param_count = len(params)
    except Exception:
        query_param_count = 0

    # Fragment
    has_fragment = 1 if fragment else 0

    # Entropy
    entropy = _url_entropy(full_url)

    # Consecutive digits
    consecutive_digits = len(max(re.findall(r"\d+", full_url) or [""], key=len))

    # Subdomain contains IP pattern
    subdomain_contains_ip_pattern = 1 if re.search(
        r"\d{1,3}[.\-]\d{1,3}[.\-]\d{1,3}", hostname
    ) else 0

    feature_dict = {
        "url_length": url_length,
        "hostname_length": hostname_length,
        "path_length": path_length,
        "query_length": query_length,
        "subdomain_depth": subdomain_depth,
        "has_ip_host": has_ip_host,
        "has_at_sign": has_at_sign,
        "has_double_slash": has_double_slash,
        "has_dash_in_domain": has_dash_in_domain,
        "has_port": has_port,
        "digit_ratio": digit_ratio,
        "special_char_count": special_chars,
        "dot_count": dot_count,
        "slash_count": slash_count,
        "has_https": has_https,
        "has_encoding": has_encoding,
        "has_unicode": has_unicode,
        "path_depth": path_depth,
        "has_suspicious_tld": has_suspicious_tld,
        "has_credential_keyword": has_credential_keyword,
        "query_param_count": query_param_count,
        "has_fragment": has_fragment,
        "entropy": entropy,
        "consecutive_digits": consecutive_digits,
        "subdomain_contains_ip_pattern": subdomain_contains_ip_pattern,
    }

    feature_vector = np.array([feature_dict[f] for f in FEATURE_NAMES], dtype=float)
    return feature_vector, feature_dict


def get_triggered_features(feature_dict: Dict[str, float], threshold: float = 0.5) -> List[str]:
    """Return list of features that indicate suspicious activity."""
    triggered = []
    checks = {
        "has_ip_host": ("IP address used as hostname", 0.4),
        "has_at_sign": ("@ symbol in URL (credential harvesting)", 0.5),
        "has_double_slash": ("Double slash obfuscation", 0.5),
        "has_encoding": ("URL encoding/obfuscation detected", 0.5),
        "has_unicode": ("Unicode spoofing characters", 0.5),
        "has_suspicious_tld": ("Suspicious top-level domain", 0.5),
        "has_credential_keyword": ("Credential/brand keyword mimicry", 0.3),
        "has_port": ("Non-standard port used", 0.5),
        "subdomain_contains_ip_pattern": ("IP-like subdomain pattern", 0.5),
    }
    for key, (desc, thresh) in checks.items():
        if feature_dict.get(key, 0) >= thresh:
            triggered.append(desc)

    if feature_dict.get("url_length", 0) > 100:
        triggered.append(f"Abnormally long URL ({int(feature_dict['url_length'])} chars)")
    if feature_dict.get("subdomain_depth", 0) > 2:
        triggered.append(f"Deep subdomain nesting (depth {int(feature_dict['subdomain_depth'])})")
    if feature_dict.get("digit_ratio", 0) > 0.3:
        triggered.append(f"High digit ratio ({feature_dict['digit_ratio']:.0%})")
    if feature_dict.get("entropy", 0) > 4.5:
        triggered.append(f"High URL entropy ({feature_dict['entropy']:.2f}) — possible random generation")

    return triggered
