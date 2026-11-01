from urllib.parse import urlparse
import re


SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "secure",
    "security",
    "update",
    "password",
    "confirm",
    "bank",
    "wallet",
    "payment",
    "credential",
    "authenticate",
    "auth",
]


def extract_features(url):

    parsed = urlparse(url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""

    url_length = len(url)

    domain_length = len(hostname)

    num_dots = url.count(".")

    num_hyphens = url.count("-")

    num_slashes = url.count("/")

    num_digits = sum(
        char.isdigit()
        for char in url
    )

    num_special_chars = len(
        re.findall(
            r"[^a-zA-Z0-9]",
            url
        )
    )

    has_https = (
        parsed.scheme.lower() == "https"
    )

    has_at_symbol = "@" in url

    ip_pattern = (
        r"^(?:\d{1,3}\.){3}\d{1,3}$"
    )

    has_ip_address = bool(
        re.match(
            ip_pattern,
            hostname
        )
    )

    domain_parts = hostname.split(".")

    if len(domain_parts) > 2:
        num_subdomains = len(domain_parts) - 2
    else:
        num_subdomains = 0

    url_lower = url.lower()

    found_keywords = [
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in url_lower
    ]

    suspicious_keyword_count = len(
        found_keywords
    )

    double_slash_redirect = "//" in path

    return {
        "url_length": url_length,
        "domain_length": domain_length,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_slashes": num_slashes,
        "num_digits": num_digits,
        "num_special_chars": num_special_chars,
        "has_https": has_https,
        "has_at_symbol": has_at_symbol,
        "has_ip_address": has_ip_address,
        "num_subdomains": num_subdomains,
        "suspicious_keyword_count": suspicious_keyword_count,
        "found_keywords": found_keywords,
        "double_slash_redirect": double_slash_redirect,
    }