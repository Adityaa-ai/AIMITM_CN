
from datetime import datetime

import numpy as np
import pandas as pd
from flask import Flask, render_template, request, jsonify
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

from monitor import monitor


app = Flask(__name__)


# --------------------------------------------------
# 1. TRAIN RANDOM FOREST MODEL (SYNTHETIC PROTOTYPE)
# --------------------------------------------------

rng = np.random.default_rng(42)
n = 1000

normal = pd.DataFrame({
    "arp_rate": rng.integers(0, 8, n),
    "mac_changes": rng.integers(0, 2, n),
    "gateway_mismatch": rng.integers(0, 2, n),
    "packet_rate": rng.integers(10, 150, n),
})
normal["label"] = 0

suspicious = pd.DataFrame({
    "arp_rate": rng.integers(15, 80, n),
    "mac_changes": rng.integers(1, 6, n),
    "gateway_mismatch": rng.integers(0, 2, n),
    "packet_rate": rng.integers(20, 250, n),
})
suspicious["label"] = 1

dataset = pd.concat(
    [normal, suspicious],
    ignore_index=True
)

FEATURES = [
    "arp_rate",
    "mac_changes",
    "gateway_mismatch",
    "packet_rate",
]

X = dataset[FEATURES]
y = dataset["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y,
)

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
)

model.fit(X_train, y_train)

test_accuracy = accuracy_score(
    y_test,
    model.predict(X_test),
)


# --------------------------------------------------
# 2. APPLICATION DATA
# --------------------------------------------------

alerts = []


# --------------------------------------------------
# 3. DASHBOARD HOME
# --------------------------------------------------

@app.route("/")
def home():
    return render_template("index.html")


# --------------------------------------------------
# 4. DASHBOARD STATISTICS
# --------------------------------------------------

@app.route("/api/stats", methods=["GET"])
def stats():
    return jsonify({
        "model": "Random Forest",
        "test_accuracy": round(test_accuracy * 100, 2),
        "total_scans": len(alerts),
        "suspicious_scans": sum(
            1
            for alert in alerts
            if alert["prediction"] == "Suspicious"
        ),
        "status": "Online",
    })


# --------------------------------------------------
# 5. MANUAL TRAFFIC ANALYSIS
# --------------------------------------------------

@app.route("/api/analyze", methods=["POST"])
def analyze():
    try:
        payload = request.get_json(silent=True)

        if not isinstance(payload, dict):
            return jsonify({
                "error": "Please provide a valid JSON object."
            }), 400

        arp_rate = int(payload["arp_rate"])
        mac_changes = int(payload["mac_changes"])
        gateway_mismatch = int(payload["gateway_mismatch"])
        packet_rate = int(payload["packet_rate"])

        if not (
            0 <= arp_rate <= 100
            and 0 <= mac_changes <= 10
            and gateway_mismatch in (0, 1)
            and 0 <= packet_rate <= 500
        ):
            return jsonify({
                "error": "Input values are outside allowed ranges."
            }), 400

        sample = pd.DataFrame(
            [{
                "arp_rate": arp_rate,
                "mac_changes": mac_changes,
                "gateway_mismatch": gateway_mismatch,
                "packet_rate": packet_rate,
            }],
            columns=FEATURES,
        )

        prediction = int(model.predict(sample)[0])
        probability = float(
            model.predict_proba(sample)[0][1]
        )

        result = {
            "prediction": (
                "Suspicious" if prediction == 1 else "Normal"
            ),
            "risk_score": round(probability * 100, 2),
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "features": sample.iloc[0].to_dict(),
            "model": "Random Forest",
        }

        alerts.insert(0, result)
        del alerts[100:]

        return jsonify(result)

    except (KeyError, ValueError, TypeError, OverflowError):
        return jsonify({
            "error": "Please provide valid numeric inputs."
        }), 400


# --------------------------------------------------
# 6. MANUAL ANALYSIS ALERT HISTORY
# --------------------------------------------------

@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    return jsonify(alerts)


# --------------------------------------------------
# 7. LIVE MONITOR STATUS
# --------------------------------------------------

@app.route("/api/live", methods=["GET"])
def live_status():
    return jsonify(monitor.snapshot())


# --------------------------------------------------
# 8. START LIVE PACKET MONITORING
# --------------------------------------------------

@app.route("/api/live/start", methods=["POST"])
def live_start():
    payload = request.get_json(silent=True) or {}

    if not isinstance(payload, dict):
        return jsonify({
            "ok": False,
            "message": "Please provide a valid JSON object."
        }), 400

    # Default to the USB Wi-Fi interface identified on this PC.
    default_interface = (
        r"\Device\NPF_{F4DFB01D-F970-433D-8471-44427B82E21D}"
    )

    interface = payload.get("interface") or default_interface

    if not isinstance(interface, str) or not interface.strip():
        return jsonify({
            "ok": False,
            "message": "A valid network interface is required."
        }), 400

    result = monitor.start(interface=interface.strip())

    return jsonify(result), (200 if result["ok"] else 400)


# --------------------------------------------------
# 9. STOP LIVE PACKET MONITORING
# --------------------------------------------------

@app.route("/api/live/stop", methods=["POST"])
def live_stop():
    result = monitor.stop()
    return jsonify(result)


# --------------------------------------------------
# 10. START LOCAL DEVELOPMENT SERVER
# --------------------------------------------------

if __name__ == "__main__":
    print("=" * 50)
    print("MITM SHIELD - AI-BASED DETECTION SYSTEM")
    print("=" * 50)
    print(
        "Synthetic Random Forest test accuracy: "
        f"{test_accuracy * 100:.2f}%"
    )
    print("Dashboard: http://127.0.0.1:5000")
    print("Live monitoring API: http://127.0.0.1:5000/api/live")
    print("=" * 50)

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        use_reloader=False,
    )
