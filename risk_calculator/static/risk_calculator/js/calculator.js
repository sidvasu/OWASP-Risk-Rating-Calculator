// Field ids for all 16 select dropdowns, used when the free-text vector
// input is left empty.
const FIELD_IDS = [
    "skill-level",
    "motive",
    "opportunity",
    "size",
    "ease-of-discovery",
    "ease-of-exploit",
    "awareness",
    "intrusion-detection",
    "loss-of-confidentiality",
    "loss-of-integrity",
    "loss-of-availability",
    "loss-of-accountability",
    "financial-damage",
    "reputation-damage",
    "non-compliance",
    "privacy-violation",
];

function getCsrfToken() {
    const input = document.querySelector('input[name="csrfmiddlewaretoken"]');
    return input ? input.value : "";
}

function buildPayload() {
    const vectorInput = document.getElementById("input").value.trim();
    const useBusinessImpact = document.getElementById("business-impact").checked;

    if (vectorInput) {
        return { vector: vectorInput, useBusinessImpact: useBusinessImpact };
    }

    const payload = {};
    for (const fieldId of FIELD_IDS) {
        payload[fieldId] = document.getElementById(fieldId).value;
    }
    payload.useBusinessImpact = useBusinessImpact;
    return payload;
}

function showError(message) {
    document.getElementById("error-message").textContent = message;
    document.getElementById("likelihood").textContent = "";
    document.getElementById("impact").textContent = "";
    document.getElementById("risk-severity").textContent = "";
}

function showResults(data) {
    document.getElementById("error-message").textContent = "";
    document.getElementById("likelihood").textContent =
        `${data.likelihood} (${data.likelihood_level})`;
    document.getElementById("impact").textContent =
        `${data.impact} (${data.impact_level})`;
    document.getElementById("risk-severity").textContent = data.risk_severity;
}

function calculateImpact() {
    const useBusiness = document.getElementById('business-impact').checked;

    if (useBusiness) {
        // Calculate using business impact fields
        const result = calculateBusinessImpact();
        // ...
    } else {
        // Calculate using technical impact fields
        const result = calculateTechnicalImpact();
        // ...
    }
}

async function calculateRisk() {
    const payload = buildPayload();

    try {
        const response = await fetch("/api/calculate/", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRFToken": getCsrfToken(),
            },
            body: JSON.stringify(payload),
        });

        const data = await response.json();

        if (!response.ok) {
            showError(data.error || "Something went wrong.");
            return;
        }

        showResults(data);
    } catch (err) {
        showError("Could not reach the server. Please try again.");
    }
}

document.getElementById("calculate").addEventListener("click", calculateRisk);
