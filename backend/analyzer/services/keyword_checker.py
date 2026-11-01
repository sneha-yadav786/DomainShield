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
]


def find_suspicious_keywords(url):
    """
    Find suspicious keywords present in the URL.
    """

    url_lower = url.lower()

    found_keywords = []

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword in url_lower:
            found_keywords.append(keyword)

    return found_keywords