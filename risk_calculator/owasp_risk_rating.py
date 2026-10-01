# OWASP Risk Rating Library

# Risk Vector Parsing
def parse_risk_vector(vector: str) -> dict:
    EXPECTED_ORDER = [
        "SL", "M", "O", "S", "ED", "EE", "A", "ID",
        "LC", "LI", "LAV", "LAC", "FD", "RD", "NC", "PV"
    ]

    values = {}

    pairs = vector.strip().split("/")

    cleaned_pairs = []
    for p in pairs:
        if p:
            cleaned_pairs.append(p)
            
    pairs = cleaned_pairs

    if len(pairs) != len(EXPECTED_ORDER):
        raise ValueError(
            f"Expected {len(EXPECTED_ORDER)} factors, got {len(pairs)}."
        )

    for i, pair in enumerate(pairs):
        if ":" not in pair:
            raise ValueError(f"Malformed segment (missing ':'): '{pair}'")

        code, value_str = pair.split(":", 1)
        code = code.strip()
        value_str = value_str.strip()

        expected_code = EXPECTED_ORDER[i]

        if code != expected_code:
            raise ValueError(
                f"Out of order or unexpected factor at position {i + 1}: "
                f"expected '{expected_code}', got '{code}'"
            )

        if not value_str.isdigit():
            raise ValueError(f"Value for '{code}' is not a valid integer: '{value_str}'")

        value = int(value_str)

        if not (0 <= value <= 9):
            raise ValueError(f"Value for '{code}' out of range (0-9): {value}")

        values[code] = value

    return values

# Likelihood Calculation
def calculate_likelihood(SL, M, O, S, ED, EE, A, ID):
    threat_agent_factor = SL + M + O + S
    vulnerability_factor = ED + EE + A + ID 

    likelihood = (threat_agent_factor + vulnerability_factor) / 8

    if 0 <= likelihood < 3:
        likelihood_level = "Low"
    elif 3 <= likelihood < 6:
        likelihood_level = "Medium"
    else:
        likelihood_level = "High"

    return likelihood, likelihood_level

# Impact Calculation
def calculate_business_impact(FD, RD, NC, PV):
    business_impact = (FD + RD + NC + PV) / 4

    if 0 <= business_impact < 3:
        business_impact_level = "Low"
    elif 3 <= business_impact < 6:
        business_impact_level = "Medium"
    else:
        business_impact_level = "High"

    return business_impact, business_impact_level

def calculate_technical_impact(LC, LI, LAV, LAC):
    technical_impact = (LC + LI + LAV + LAC) / 4
    
    if 0 <= technical_impact < 3:
        technical_impact_level = "Low"
    elif 3 <= technical_impact < 6:
        technical_impact_level = "Medium"
    else:
        technical_impact_level = "High"

    return technical_impact, technical_impact_level

# Risk Severity Calculation
def calculate_risk_severity(likelihood_level, impact_level):
    match likelihood_level:
        case "Low":
            likelihood_score = 1
        case "Medium":
            likelihood_score = 2
        case "High":
            likelihood_score = 3

    match impact_level:
        case "Low":
            impact_score = 1
        case "Medium":
            impact_score = 2
        case "High":
            impact_score = 3

    risk_score = likelihood_score + impact_score

    match risk_score:
        case 2:
            return "Note"
        case 3:
            return "Low"
        case 4:
            return "Medium"
        case 5:
            return "High"
        case 6:
            return "Critical"

if __name__ == "__main__":
    business_impact_is_known = True
    risk_vector = "SL:0/M:0/O:0/S:0/ED:0/EE:0/A:0/ID:0/LC:0/LI:0/LAV:0/LAC:0/FD:0/RD:0/NC:0/PV:0"
    risk_factors = parse_risk_vector(risk_vector)

    # Threat Agent Factors
    SL = risk_factors["SL"]
    M = risk_factors["M"]
    O = risk_factors["O"]
    S = risk_factors["S"]

    # Vulnerability Factors
    ED = risk_factors["ED"]
    EE = risk_factors["EE"]
    A = risk_factors["A"]
    ID = risk_factors["ID"]

    # Technical Impact Factors
    LC = risk_factors["LC"]
    LI = risk_factors["LI"]
    LAV = risk_factors["LAV"]
    LAC = risk_factors["LAC"]

    # Business Impact Factors
    FD = risk_factors["FD"]
    RD = risk_factors["RD"]
    NC = risk_factors["NC"]
    PV = risk_factors["PV"]

    likelihood, likelihood_level = calculate_likelihood(SL, M, O, S, ED, EE, A, ID)

    if business_impact_is_known:
        impact, impact_level = calculate_business_impact(FD, RD, NC, PV)
    else:
        impact, impact_level = calculate_technical_impact(LC, LI, LAV, LAC)

    risk_severity = calculate_risk_severity(likelihood_level, impact_level)

    print(f"Likelihood: {likelihood}")
    print(f"Likelihood Level: {likelihood_level}")
    print(f"Impact: {impact}")
    print(f"Impact Level: {impact_level}")
    print(f"Risk Severity: {risk_severity}")