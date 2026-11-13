
from urllib.parse import urlparse, parse_qs
import ipaddress
import re
import tldextract


# Common suspicious words found in phishing URLs
SUSPICIOUS_KEYWORDS = {
    "login", "signin", "verify", "verification",
    "account", "secure", "update", "password",
    "banking", "payment", "confirm", "wallet",
    "recover", "authenticate", "webscr"
}


def is_ip_address(hostname):
    """Check whether hostname is an IPv4 or IPv6 address."""

    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def extract_features(url):
    """
    Extract security-related features from a URL.

    Returns a dictionary containing URL structure,
    domain information, and suspicious indicators.
    """

    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL must be a non-empty string.")

    url = url.strip()

    # Parse URL
    parsed_url = urlparse(url)

    hostname = parsed_url.hostname or ""
    scheme = parsed_url.scheme.lower()

    # Extract registered domain information
    extracted = tldextract.extract(hostname)

    registered_domain = extracted.top_domain_under_public_suffix
    subdomain = extracted.subdomain
    domain = extracted.domain
    suffix = extracted.suffix

    # Check whether hostname is an IP address
    ip_address = is_ip_address(hostname)

    # Extract query parameters
    query_params = parse_qs(parsed_url.query)

    # Count suspicious keywords
    url_lower = url.lower()

    suspicious_keywords_found = [
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in url_lower
    ]

    # Detect encoded characters
    has_percent_encoding = bool(
        re.search(r"%[0-9a-fA-F]{2}", url)
    )

    # Detect punycode
    has_punycode = "xn--" in hostname.lower()

    # Detect non-standard port
    try:
        port = parsed_url.port
    except ValueError:
        port = None

    has_non_standard_port = (
        port is not None and
        port not in (80, 443)
    )

    # Detect username/password in URL
    has_userinfo = (
        parsed_url.username is not None or
        parsed_url.password is not None
    )

    features = {
        # Basic URL features
        "url_length": len(url),
        "domain_length": len(hostname),
        "num_dots": hostname.count("."),
        "num_hyphens": hostname.count("-"),
        "num_slashes": url.count("/"),
        "num_digits": sum(char.isdigit() for char in url),

        "num_special_chars": sum(
            not char.isalnum()
            for char in url
        ),

        # URL structure
        "scheme": scheme,
        "has_https": scheme == "https",
        "has_http": scheme == "http",
        "hostname": hostname,
        "port": port,
        "path": parsed_url.path,
        "query": parsed_url.query,
        "fragment": parsed_url.fragment,

        # Domain features
        "registered_domain": registered_domain,
        "subdomain": subdomain,
        "domain": domain,
        "suffix": suffix,
        "num_subdomains": len(subdomain.split(".")) if subdomain else 0,

        # Security indicators
        "has_ip_address": ip_address,
        "has_at_symbol": "@" in url,
        "has_userinfo": has_userinfo,
        "has_punycode": has_punycode,
        "has_percent_encoding": has_percent_encoding,
        "has_non_standard_port": has_non_standard_port,

        # Query features
        "num_query_parameters": len(query_params),
        "has_query": bool(parsed_url.query),
        "has_fragment": bool(parsed_url.fragment),

        # Suspicious keyword features
        "suspicious_keywords_found": suspicious_keywords_found,
        "num_suspicious_keywords": len(suspicious_keywords_found),
    }

    return features
