def calculate_risk(features):

    score = 0

    reasons = []

    checks = []


    # IP address
    if features["has_ip_address"]:

        score += 25

        reasons.append(
            "Website uses an IP address instead of a normal domain."
        )

        checks.append({
            "name": "Domain type",
            "status": "warning"
        })

    else:

        checks.append({
            "name": "Domain type",
            "status": "safe"
        })


    # HTTPS
    if not features["has_https"]:

        score += 15

        reasons.append(
            "Website does not use HTTPS."
        )

        checks.append({
            "name": "HTTPS connection",
            "status": "warning"
        })

    else:

        checks.append({
            "name": "HTTPS connection",
            "status": "safe"
        })


    # Long URL
    if features["url_length"] > 100:

        score += 10

        reasons.append(
            "URL is unusually long."
        )


    # Too many subdomains
    if features["num_subdomains"] >= 3:

        score += 15

        reasons.append(
            "URL contains an unusually high number of subdomains."
        )

    else:

        checks.append({
            "name": "Domain structure",
            "status": "safe"
        })


    # @ symbol
    if features["has_at_symbol"]:

        score += 15

        reasons.append(
            "URL contains an @ symbol."
        )


    # Hyphens
    if features["num_hyphens"] >= 3:

        score += 10

        reasons.append(
            "Domain contains multiple hyphens."
        )


    # Suspicious keywords
    keyword_count = features[
        "suspicious_keyword_count"
    ]

    if keyword_count > 0:

        keyword_score = min(
            keyword_count * 5,
            15
        )

        score += keyword_score

        keywords = ", ".join(
            features["found_keywords"]
        )

        reasons.append(
            f"Suspicious keywords detected: {keywords}."
        )

        checks.append({
            "name": "Suspicious keywords",
            "status": "warning"
        })

    else:

        checks.append({
            "name": "Suspicious keywords",
            "status": "safe"
        })


    # Double slash
    if features["double_slash_redirect"]:

        score += 10

        reasons.append(
            "URL contains an unusual double-slash pattern."
        )


    score = min(score, 100)


    # Status
    if score < 30:

        status = "safe"

        status_text = "Website appears safe"

        description = (
            "No major suspicious characteristics "
            "were detected."
        )

    elif score < 60:

        status = "suspicious"

        status_text = "Website looks suspicious"

        description = (
            "Some characteristics of this URL "
            "may indicate a security risk."
        )

    else:

        status = "high-risk"

        status_text = "High-risk website"

        description = (
            "Multiple suspicious characteristics "
            "were detected."
        )


    return {
        "risk_score": score,
        "status": status,
        "status_text": status_text,
        "description": description,
        "reasons": reasons,
        "checks": checks,
    }