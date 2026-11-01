from urllib.parse import urlparse
import ipaddress


def is_ip_address(hostname):
    """
    Check whether hostname is an IP address.
    """

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
    """

    parsed_url = urlparse(url)

    hostname = parsed_url.hostname or ""

    features = {
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

        "has_at_symbol": "@" in url,

        "has_https": parsed_url.scheme == "https",

        "has_ip_address": is_ip_address(hostname),

        "num_subdomains": max(
            len(hostname.split(".")) - 2,
            0
        ),

        "hostname": hostname,
    }

    return features