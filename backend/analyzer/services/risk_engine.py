
def calculate_risk(features):

    score = 0
    reasons = []
    checks = []

    def add_check(name, status, reason=None):
        check = {
            "name": name,
            "status": status
        }

        if reason:
            check["reason"] = reason

        checks.append(check)

    # 1. IP Address
    if features.get("has_ip_address", False):
        score += 25
        reason = "Website uses an IP address instead of a domain name."
        reasons.append(reason)
        add_check("Domain type", "warning", reason)
    else:
        add_check("Domain type", "safe")

    # 2. HTTPS
    if not features.get("has_https", False):
        score += 15
        reason = "Website does not use HTTPS."
        reasons.append(reason)
        add_check("HTTPS connection", "warning", reason)
    else:
        add_check("HTTPS connection", "safe")

    # 3. URL Length
    if features.get("url_length", 0) > 100:
        score += 10
        reason = "URL is unusually long."
        reasons.append(reason)
        add_check("URL length", "warning", reason)
    else:
        add_check("URL length", "safe")

    # 4. Subdomains
    if features.get("num_subdomains", 0) >= 3:
        score += 15
        reason = "URL contains an unusually high number of subdomains."
        reasons.append(reason)
        add_check("Domain structure", "warning", reason)
    else:
        add_check("Domain structure", "safe")

    # 5. @ Symbol
    if features.get("has_at_symbol", False):
        score += 15
        reason = "URL contains an @ symbol that may disguise its destination."
        reasons.append(reason)
        add_check("URL obfuscation", "warning", reason)
    else:
        add_check("URL obfuscation", "safe")

    # 6. Multiple Hyphens
    if features.get("num_hyphens", 0) >= 3:
        score += 10
        reason = "Domain contains multiple hyphens."
        reasons.append(reason)
        add_check("Domain characters", "warning", reason)
    else:
        add_check("Domain characters", "safe")

    # 7. Suspicious Keywords
    keywords = features.get("suspicious_keywords_found", [])
    keyword_count = len(keywords)

    if keyword_count > 0:
        keyword_score = min(keyword_count * 5, 15)
        score += keyword_score

        reason = (
            "Suspicious keywords detected: "
            + ", ".join(keywords)
            + "."
        )

        reasons.append(reason)
        add_check("Suspicious keywords", "warning", reason)
    else:
        add_check("Suspicious keywords", "safe")

    # 8. Punycode
    if features.get("has_punycode", False):
        score += 15
        reason = "Domain contains Punycode, which can represent internationalized characters."
        reasons.append(reason)
        add_check("Internationalized domain", "warning", reason)
    else:
        add_check("Internationalized domain", "safe")

    # 9. Non-standard Port
    if features.get("has_non_standard_port", False):
        score += 10
        reason = "Website uses a non-standard port."
        reasons.append(reason)
        add_check("Port configuration", "warning", reason)
    else:
        add_check("Port configuration", "safe")

    # 10. URL Encoding
    if features.get("has_percent_encoding", False):
        score += 5
        reason = "URL contains encoded characters that should be inspected."
        reasons.append(reason)
        add_check("URL encoding", "warning", reason)
    else:
        add_check("URL encoding", "safe")

    # 11. Username / Password in URL
    if features.get("has_userinfo", False):
        score += 15
        reason = "URL contains embedded username or password information."
        reasons.append(reason)
        add_check("URL credentials", "warning", reason)
    else:
        add_check("URL credentials", "safe")

    # Final score
    score = min(score, 100)

    # Risk classification
    if score < 30:
        status = "safe"
        status_text = "No major risk indicators detected"
        description = (
            "This URL has relatively few suspicious characteristics. "
            "This does not guarantee that the website is safe."
        )

    elif score < 60:
        status = "suspicious"
        status_text = "Website looks suspicious"
        description = (
            "Some characteristics of this URL may indicate "
            "a potential security risk."
        )

    else:
        status = "high-risk"
        status_text = "High-risk website"
        description = (
            "Multiple suspicious characteristics were detected. "
            "Avoid entering sensitive information."
        )

    return {
        "risk_score": score,
        "status": status,
        "status_text": status_text,
        "description": description,
        "reasons": reasons,
        "checks": checks,
    }
