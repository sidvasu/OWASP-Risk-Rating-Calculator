import json

from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_GET, require_POST

from .owasp_risk_rating import (
    calculate_business_impact,
    calculate_likelihood,
    calculate_risk_severity,
    calculate_technical_impact,
    parse_risk_vector,
)

# Maps the HTML <select>/<input> element ids from index.html to the
# short codes used in owasp_risk_rating.py / the OWASP risk vector.
FIELD_ID_TO_CODE = {
    "skill-level": "SL",
    "motive": "M",
    "opportunity": "O",
    "size": "S",
    "ease-of-discovery": "ED",
    "ease-of-exploit": "EE",
    "awareness": "A",
    "intrusion-detection": "ID",
    "loss-of-confidentiality": "LC",
    "loss-of-integrity": "LI",
    "loss-of-availability": "LAV",
    "loss-of-accountability": "LAC",
    "financial-damage": "FD",
    "reputation-damage": "RD",
    "non-compliance": "NC",
    "privacy-violation": "PV",
}

# Order matters: this must match EXPECTED_ORDER in owasp_risk_rating.py
VECTOR_ORDER = [
    "SL", "M", "O", "S", "ED", "EE", "A", "ID",
    "LC", "LI", "LAV", "LAC", "FD", "RD", "NC", "PV",
]


@require_GET
def index(request):
    """Render the risk rating calculator page."""
    return render(request, "risk_calculator/index.html")


def _build_vector_from_fields(data: dict) -> str:
    """Build a risk vector string (e.g. 'SL:3/M:4/...') from a dict of
    field-id -> value pairs, in the order owasp_risk_rating.py expects."""
    segments = []
    for field_id in FIELD_ID_TO_CODE:
        code = FIELD_ID_TO_CODE[field_id]
        if field_id not in data or data[field_id] in (None, ""):
            raise ValueError(f"Missing value for '{field_id}'.")
        segments.append(f"{code}:{data[field_id]}")
    # Re-order to match VECTOR_ORDER (dict above is already in that order,
    # but this keeps the mapping explicit and safe if it's ever reordered).
    ordered = {FIELD_ID_TO_CODE[k]: v for k, v in data.items() if k in FIELD_ID_TO_CODE}
    segments = [f"{code}:{ordered[code]}" for code in VECTOR_ORDER]
    return "/".join(segments)


@require_POST
def calculate(request):
    """
    Accepts a JSON body containing either:
      { "vector": "SL:3/M:4/O:.../PV:9" }
    or
      { "skill-level": "3", "motive": "4", ... } (all 16 field ids)

    Returns JSON with likelihood, technical/business impact, and risk severity.
    """
    try:
        data = json.loads(request.body or "{}")
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON body."}, status=400)

    vector = (data.get("vector") or "").strip()

    if not vector:
        try:
            vector = _build_vector_from_fields(data)
        except ValueError as exc:
            return JsonResponse({"error": str(exc)}, status=400)

    try:
        factors = parse_risk_vector(vector)
    except ValueError as exc:
        return JsonResponse({"error": str(exc)}, status=400)

    likelihood, likelihood_level = calculate_likelihood(
        factors["SL"], factors["M"], factors["O"], factors["S"],
        factors["ED"], factors["EE"], factors["A"], factors["ID"],
    )

    business_impact, business_impact_level = calculate_business_impact(
        factors["FD"], factors["RD"], factors["NC"], factors["PV"],
    )

    technical_impact, technical_impact_level = calculate_technical_impact(
        factors["LC"], factors["LI"], factors["LAV"], factors["LAC"],
    )

    # Per OWASP methodology, business impact takes precedence over technical
    # impact whenever business impact factors are available, which they are
    # here since the vector always includes FD/RD/NC/PV.
    impact, impact_level = business_impact, business_impact_level

    risk_severity = calculate_risk_severity(likelihood_level, impact_level)

    return JsonResponse({
        "vector": vector,
        "likelihood": round(likelihood, 2),
        "likelihood_level": likelihood_level,
        "technical_impact": round(technical_impact, 2),
        "technical_impact_level": technical_impact_level,
        "business_impact": round(business_impact, 2),
        "business_impact_level": business_impact_level,
        "impact": round(impact, 2),
        "impact_level": impact_level,
        "risk_severity": risk_severity,
    })
