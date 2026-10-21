
from flask import Flask, render_template, request, jsonify
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from datetime import datetime

app = Flask(__name__)

# Generate synthetic training data for the prototype
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

dataset = pd.concat([normal, suspicious], ignore_index=True)

FEATURES = [
    "arp_rate",
    "mac_changes",
    "gateway_mismatch",
    "packet_rate",
]

X = dataset[FEATURES]
y = dataset["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

test_accuracy = accuracy_score(y_test, model.predict(X_test))
alerts = []


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/stats")
def stats():
    return jsonify({
        "model": "Random Forest",
        "test_accuracy": round(test_accuracy * 100, 2),
        "total_scans": len(alerts),
        "suspicious_scans": sum(
            1 for alert in alerts if alert["prediction"] == "Suspicious"
        ),
        "status": "Online",
    })


@app.route("/api/analyze", methods=["POST"])
def analyze():
    try:
        payload = request.get_json(force=True)

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
            return jsonify({"error": "Input values are outside allowed ranges."}), 400

        sample = pd.DataFrame([{
            "arp_rate": arp_rate,
            "mac_changes": mac_changes,
            "gateway_mismatch": gateway_mismatch,
            "packet_rate": packet_rate,
        }], columns=FEATURES)

        prediction = int(model.predict(sample)[0])
        probability = float(model.predict_proba(sample)[0][1])

        result = {
            "prediction": "Suspicious" if prediction == 1 else "Normal",
            "risk_score": round(probability * 100, 2),
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "features": sample.iloc[0].to_dict(),
            "model": "Random Forest",
        }

        alerts.insert(0, result)
        del alerts[100:]

        return jsonify(result)

    except (KeyError, ValueError, TypeError):
        return jsonify({"error": "Please provide valid numeric inputs."}), 400


@app.route("/api/alerts")
def get_alerts():
    return jsonify(alerts)


if __name__ == "__main__":
    print("MITM Detection server starting...")
    print(f"Synthetic test-set accuracy: {test_accuracy * 100:.2f}%")
    app.run(debug=False, host="0.0.0.0", port=5000)
