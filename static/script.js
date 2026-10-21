
"use strict";

// ==================================================
// MITM SHIELD - DASHBOARD SCRIPT
// Manual Random Forest + Live Scapy Monitor
// ==================================================

const form = document.getElementById("scanForm");
const scanButton = document.getElementById("scanButton");

const startMonitorButton = document.getElementById("startMonitor");
const stopMonitorButton = document.getElementById("stopMonitor");

let livePolling = null;


// ==================================================
// COMMON HELPERS
// ==================================================

function setText(id, value) {
    const element = document.getElementById(id);

    if (element) {
        element.textContent = value ?? "--";
    }
}

function addCell(row, value) {
    const cell = row.insertCell();
    cell.textContent = value ?? "--";
    return cell;
}

async function fetchJSON(url, options = {}) {
    const response = await fetch(url, options);

    let data;

    try {
        data = await response.json();
    } catch {
        throw new Error(`Invalid server response (${response.status}).`);
    }

    if (!response.ok) {
        throw new Error(
            data.message || data.error || `Request failed (${response.status}).`
        );
    }

    return data;
}

function showLiveError(message) {
    const element = document.getElementById("liveError");

    if (element) {
        element.textContent = message;
        element.hidden = false;
    }

    console.error("MITM Shield live monitor:", message);
}

function clearLiveError() {
    const element = document.getElementById("liveError");

    if (element) {
        element.textContent = "";
        element.hidden = true;
    }
}


// ==================================================
// 1. MANUAL MODEL STATISTICS
// ==================================================

async function loadStats() {
    try {
        const data = await fetchJSON("/api/stats");

        setText("model", data.model);
        setText("accuracy", `${data.test_accuracy}%`);
        setText("totalScans", data.total_scans);
        setText("suspiciousScans", data.suspicious_scans);
    } catch (error) {
        console.error("Stats error:", error);
    }
}


// ==================================================
// 2. MANUAL SCAN HISTORY
// ==================================================

async function loadAlerts() {
    try {
        const alerts = await fetchJSON("/api/alerts");
        const table = document.getElementById("alertTable");

        // Allow this script to run even if an older HTML page is loaded.
        if (!table) {
            console.warn("Manual scan history table was not found.");
            return;
        }

        table.replaceChildren();

        if (!Array.isArray(alerts) || alerts.length === 0) {
            const row = table.insertRow();
            const cell = row.insertCell();

            cell.colSpan = 3;
            cell.textContent = "No scans performed yet.";
            return;
        }

        alerts.forEach(alert => {
            const row = table.insertRow();

            addCell(row, alert.timestamp);
            addCell(row, alert.prediction);
            addCell(row, `${alert.risk_score}%`);
        });
    } catch (error) {
        console.error("Manual alerts error:", error);
    }
}


// ==================================================
// 3. MANUAL RANDOM FOREST ANALYSIS
// ==================================================

if (form && scanButton) {
    form.addEventListener("submit", async event => {
        event.preventDefault();

        scanButton.disabled = true;
        scanButton.textContent = "Analyzing...";

        const arpInput = document.getElementById("arp_rate");
        const macInput = document.getElementById("mac_changes");
        const gatewayInput = document.getElementById("gateway_mismatch");
        const packetInput = document.getElementById("packet_rate");

        if (!arpInput || !macInput || !gatewayInput || !packetInput) {
            alert("One or more manual-analysis input fields are missing.");
            scanButton.disabled = false;
            scanButton.textContent = "Analyze Traffic";
            return;
        }

        const payload = {
            arp_rate: Number(arpInput.value),
            mac_changes: Number(macInput.value),
            gateway_mismatch: Number(gatewayInput.value),
            packet_rate: Number(packetInput.value)
        };

        try {
            const data = await fetchJSON("/api/analyze", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(payload)
            });

            const result = document.getElementById("result");

            if (result) {
                result.className =
                    "result " +
                    (data.prediction === "Normal" ? "normal" : "suspicious");

                result.replaceChildren();

                const heading = document.createElement("h3");
                heading.textContent =
                    data.prediction === "Normal"
                        ? "Normal Pattern"
                        : "Suspicious Pattern";

                const description = document.createElement("p");
                description.textContent =
                    data.prediction === "Normal"
                        ? "The model classified this sample as normal."
                        : "The model flagged this sample for further investigation.";

                result.append(heading, description);
            }

            setText("riskScore", `${data.risk_score}%`);

            const riskBar = document.getElementById("riskBar");

            if (riskBar) {
                riskBar.style.width =
                    `${Math.min(100, Math.max(0, data.risk_score))}%`;

                riskBar.style.background =
                    data.prediction === "Normal" ? "#53e0b3" : "#ff7185";
            }

            await Promise.all([loadStats(), loadAlerts()]);
        } catch (error) {
            alert(error.message);
            console.error("Analysis error:", error);
        } finally {
            scanButton.disabled = false;
            scanButton.textContent = "Analyze Traffic";
        }
    });
} else {
    console.warn(
        "Manual analyzer form or button is missing. " +
        "Check the IDs scanForm and scanButton in index.html."
    );
}


// ==================================================
// 4. LIVE MONITOR BUTTON STATES
// ==================================================

function setMonitorButtons(running) {
    if (startMonitorButton) {
        startMonitorButton.disabled = running;
    }

    if (stopMonitorButton) {
        stopMonitorButton.disabled = !running;
    }
}


// ==================================================
// 5. START LIVE PACKET MONITOR
// ==================================================

if (startMonitorButton) {
    startMonitorButton.addEventListener("click", async () => {
        startMonitorButton.disabled = true;

        setText("liveMessage", "Starting packet capture...");
        clearLiveError();

        try {
            const result = await fetchJSON("/api/live/start", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({})
            });

            setText("liveMessage", result.message || "Monitor started.");

            await loadLiveStatus();
            beginLivePolling();
        } catch (error) {
            setText("liveMessage", "Unable to start monitoring.");
            showLiveError(error.message);

            startMonitorButton.disabled = false;
        }
    });
} else {
    console.error(
        'Start Monitor button not found. ' +
        'Check that index.html contains id="startMonitor".'
    );
}


// ==================================================
// 6. STOP LIVE PACKET MONITOR
// ==================================================

if (stopMonitorButton) {
    stopMonitorButton.addEventListener("click", async () => {
        stopMonitorButton.disabled = true;

        try {
            const result = await fetchJSON("/api/live/stop", {
                method: "POST"
            });

            setText("liveMessage", result.message || "Monitoring stopped.");

            endLivePolling();
            await loadLiveStatus();
        } catch (error) {
            showLiveError(error.message);
            stopMonitorButton.disabled = false;
        }
    });
} else {
    console.error(
        'Stop Monitor button not found. ' +
        'Check that index.html contains id="stopMonitor".'
    );
}


// ==================================================
// 7. LOAD LIVE MONITOR STATUS AND METRICS
// ==================================================

async function loadLiveStatus() {
    try {
        const data = await fetchJSON("/api/live");

        setText(
            "liveInterface",
            data.interface || "Default interface"
        );

        const running = Boolean(data.running);

        setMonitorButtons(running);

        const badge = document.getElementById("liveBadge");

        if (badge) {
            badge.textContent = running
                ? (data.trained ? "MONITORING" : "CALIBRATING")
                : (data.status || "STOPPED").toUpperCase();

            badge.className =
                "live-badge " + (running ? "active" : "inactive");
        }

        if (data.error) {
            showLiveError(data.error);
        } else {
            clearLiveError();
        }

        const latest = data.latest;

        if (latest) {
            setText("livePps", latest.packets_per_second);

            setText(
                "liveBps",
                `${formatBytes(latest.bytes_per_second)}/s`
            );

            setText("liveIps", latest.unique_source_ips);
            setText("liveMacs", latest.unique_source_macs);
            setText("liveArp", latest.arp_per_second);
            setText("liveMacChanges", latest.mac_changes);

            setText(
                "liveClassification",
                latest.classification || "Waiting"
            );

            setText(
                "liveAnomalyScore",
                latest.anomaly_score == null
                    ? "--"
                    : latest.anomaly_score
            );

            let explanation;

            if (!data.trained) {
                explanation =
                    "Collecting baseline traffic. Classification is not ready yet.";
            } else if (latest.classification === "Anomaly") {
                explanation =
                    "Traffic differs from the learned baseline. Investigate the evidence.";
            } else if (latest.classification === "Normal") {
                explanation =
                    "The latest feature window is within the learned baseline.";
            } else {
                explanation = "Waiting for the next analysis window.";
            }

            setText("liveExplanation", explanation);

            if (running) {
                setText(
                    "liveMessage",
                    data.trained
                        ? "Live packet capture is active."
                        : "Collecting baseline traffic..."
                );
            }
        } else {
            setText("livePps", "--");
            setText("liveBps", "--");
            setText("liveIps", "--");
            setText("liveMacs", "--");
            setText("liveArp", "--");
            setText("liveMacChanges", "--");
            setText("liveClassification", "Waiting for traffic");
            setText("liveAnomalyScore", "--");
            setText(
                "liveExplanation",
                "Start monitoring to collect traffic features."
            );
        }

        // Calibration progress
        const baselineCount = Number(data.baseline_windows || 0);
        const baselineRequired = Number(
            data.required_baseline_windows || 12
        );

        const progress = Math.min(
            100,
            (baselineCount / Math.max(1, baselineRequired)) * 100
        );

        setText(
            "baselineProgress",
            `${baselineCount} / ${baselineRequired} windows`
        );

        const baselineBar = document.getElementById("baselineBar");

        if (baselineBar) {
            baselineBar.style.width = `${progress}%`;
        }

        renderLiveHistory(data.history || []);
        renderLiveEvents(data.events || []);

        if (running) {
            beginLivePolling();
        } else {
            endLivePolling();
        }
    } catch (error) {
        console.error("Live status error:", error);
        setText("liveMessage", "Could not refresh live status.");
    }
}


// ==================================================
// 8. FORMAT BYTE COUNTS
// ==================================================

function formatBytes(value) {
    const bytes = Number(value || 0);

    if (bytes < 1024) {
        return `${bytes.toFixed(0)} B`;
    }

    if (bytes < 1024 * 1024) {
        return `${(bytes / 1024).toFixed(1)} KB`;
    }

    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}


// ==================================================
// 9. RENDER LIVE TRAFFIC HISTORY
// ==================================================

function renderLiveHistory(history) {
    const table = document.getElementById("liveHistory");

    if (!table) {
        return;
    }

    table.replaceChildren();

    if (!Array.isArray(history) || history.length === 0) {
        const row = table.insertRow();
        const cell = row.insertCell();

        cell.colSpan = 5;
        cell.textContent = "No live traffic windows yet.";
        return;
    }

    history.forEach(item => {
        const row = table.insertRow();

        addCell(row, item.time);
        addCell(row, item.packets_per_second);
        addCell(row, item.arp_per_second);
        addCell(row, item.unique_source_ips);

        const classification = addCell(
            row,
            item.classification
        );

        if (item.classification === "Anomaly") {
            classification.className = "text-danger";
        } else if (item.classification === "Normal") {
            classification.className = "text-success";
        }
    });
}


// ==================================================
// 10. RENDER LIVE SECURITY EVENTS
// ==================================================

function renderLiveEvents(events) {
    const table = document.getElementById("liveEvents");

    if (!table) {
        return;
    }

    table.replaceChildren();

    if (!Array.isArray(events) || events.length === 0) {
        const row = table.insertRow();
        const cell = row.insertCell();

        cell.colSpan = 4;
        cell.textContent = "No live events yet.";
        return;
    }

    events.forEach(event => {
        const row = table.insertRow();

        addCell(row, event.time);
        addCell(row, event.type);
        addCell(row, event.message);

        const severity = addCell(row, event.severity);

        if (
            event.severity === "Warning" ||
            event.severity === "Critical"
        ) {
            severity.className = "text-danger";
        }
    });
}


// ==================================================
// 11. AUTOMATIC LIVE REFRESH
// ==================================================

function beginLivePolling() {
    if (livePolling !== null) {
        return;
    }

    livePolling = setInterval(() => {
        loadLiveStatus();
    }, 3000);
}

function endLivePolling() {
    if (livePolling !== null) {
        clearInterval(livePolling);
        livePolling = null;
    }
}


// ==================================================
// 12. INITIALIZE DASHBOARD
// ==================================================

async function initializeDashboard() {
    console.log("MITM Shield dashboard initializing...");

    console.log("HTML elements:", {
        scanForm: Boolean(form),
        scanButton: Boolean(scanButton),
        startMonitor: Boolean(startMonitorButton),
        stopMonitor: Boolean(stopMonitorButton)
    });

    await Promise.all([
        loadStats(),
        loadAlerts(),
        loadLiveStatus()
    ]);

    console.log("MITM Shield dashboard initialized.");
}

initializeDashboard();
