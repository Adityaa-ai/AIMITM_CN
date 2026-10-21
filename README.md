
# AI-Based Man-in-the-Middle (MITM) Detection System

## Project Overview
This Computer Networks mini-project demonstrates a machine-learning
prototype that classifies network traffic feature patterns as normal
or suspicious.

## Objectives
- Understand Man-in-the-Middle attacks.
- Explore ARP-related suspicious traffic indicators.
- Demonstrate Random Forest classification.
- Display predictions through a Flask web dashboard.

## Technology Stack
- Python
- Flask
- Scikit-learn
- Pandas and NumPy
- HTML, CSS and JavaScript

## System Modules
1. Synthetic traffic dataset generation
2. Feature preparation and preprocessing
3. Random Forest model training
4. Flask API for traffic analysis
5. Web dashboard and scan history

## How to Run
1. Activate the Python virtual environment.
2. Install dependencies:
   pip install flask scikit-learn pandas numpy
3. Start the server:
   python app.py
4. Open http://127.0.0.1:5000

## Limitations
The current implementation uses synthetic training data and
manually entered traffic features. It does not capture live network
traffic or establish that an actual MITM attack has occurred.

## Future Scope
- Integrate authorized live packet capture.
- Analyze ARP traffic and gateway MAC changes.
- Evaluate on a realistic, labeled network traffic dataset.
- Improve detection performance and reduce false positives.
