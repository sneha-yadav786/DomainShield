from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status

from urllib.parse import urlparse

from .services.feature_extractor import (
    extract_features
)

from .services.risk_engine import (
    calculate_risk
)


@api_view(["POST"])
def analyze_url(request): 

    url = request.data.get("url", "").strip()


    # Empty URL
    if not url:

        return Response(
            {
                "error": "URL is required."
            },
            status=status.HTTP_400_BAD_REQUEST
        )


    # Validate URL
    parsed = urlparse(url)


    if parsed.scheme not in [
        "http",
        "https"
    ]:

        return Response(
            {
                "error": (
                    "URL must start with "
                    "http:// or https://"
                )
            },
            status=status.HTTP_400_BAD_REQUEST
        )


    if not parsed.netloc:

        return Response(
            {
                "error": "Invalid URL."
            },
            status=status.HTTP_400_BAD_REQUEST
        )


    # Extract features
    features = extract_features(url)


    # Calculate risk
    result = calculate_risk(
        features
    )


    return Response({

        "url": url,

        "risk_score":
            result["risk_score"],

        "status":
            result["status"],

        "status_text":
            result["status_text"],

        "description":
            result["description"],

        "reasons":
            result["reasons"],

        "checks":
            result["checks"],

        "features":
            features
    })