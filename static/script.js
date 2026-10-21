
const form = document.getElementById("scanForm");
const button = document.getElementById("scanButton");

async function loadStats() {
    try {
        const response = await fetch("/api/stats");
        if (!response.ok) throw new Error("Stats request failed");

        const data = await response.json();

        document.getElementById("model").textContent = data.model;
        document.getElementById("accuracy").textContent =
            `${data.test_accuracy}%`;
        document.getElementById("totalScans").textContent =
            data.total_scans;
        document.getElementById("suspiciousScans").textContent =
            data.suspicious_scans;
    } catch (error) {
        console.error("Stats error:", error);
    }
}

async function loadAlerts() {
    try {
        const response = await fetch("/api/alerts");
        if (!response.ok) throw new Error("Alerts request failed");

        const alerts = await response.json();
        const table = document.getElementById("alertTable");

        table.replaceChildren();

        if (alerts.length === 0) {
            const row = table.insertRow();
            const cell = row.insertCell();
            cell.colSpan = 3;
            cell.textContent = "No scans performed yet.";
            return;
        }

        alerts.forEach(alert => {
            const row = table.insertRow();

            [alert.timestamp, alert.prediction, `${alert.risk_score}%`]
                .forEach(value => {
                    const cell = row.insertCell();
                    cell.textContent = value;
                });
        });
    } catch (error) {
        console.error("Alerts error:", error);
    }
}

form.addEventListener("submit", async event => {
    event.preventDefault();

    button.disabled = true;
    button.textContent = "Analyzing...";

    const payload = {
        arp_rate: Number(document.getElementById("arp_rate").value),
        mac_changes: Number(document.getElementById("mac_changes").value),
        gateway_mismatch:
            Number(document.getElementById("gateway_mismatch").value),
        packet_rate: Number(document.getElementById("packet_rate").value)
    };

    try {
        const response = await fetch("/api/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Analysis failed");
        }

        const result = document.getElementById("result");
        result.className = "result " +
            (data.prediction === "Normal" ? "normal" : "suspicious");
        result.replaceChildren();

        const heading = document.createElement("h3");
        heading.textContent = data.prediction === "Normal"
            ? "Normal Pattern" : "Suspicious Pattern";

        const description = document.createElement("p");
        description.textContent = data.prediction === "Normal"
            ? "The model classified this sample as normal."
            : "The model flagged this sample for further investigation.";

        result.append(heading, description);

        document.getElementById("riskScore").textContent =
            `${data.risk_score}%`;

        document.getElementById("riskBar").style.width =
            `${Math.min(100, Math.max(0, data.risk_score))}%`;

        document.getElementById("riskBar").style.background =
            data.prediction === "Normal" ? "#53e0b3" : "#ff7185";

        await Promise.all([loadStats(), loadAlerts()]);

    } catch (error) {
        alert(error.message);
        console.error("Analysis error:", error);
    } finally {
        button.disabled = false;
        button.textContent = "Analyze Traffic";
    }
});

loadStats();
loadAlerts();
