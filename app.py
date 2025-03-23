from flask import Flask, render_template, request, jsonify
from datetime import datetime
import json
import os
import random
import requests
from datetime import datetime, timedelta

app = Flask(__name__)

# Log file path
LOG_FILE = "backend/logs/ids.log"

# Updated Groq API key
GROQ_API_KEY = "your-api-key-here"

# Ensure logs directory exists
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# Attack severity levels and descriptions
ATTACK_TYPES = {
    "xss": {
        "severity": "Low",
        "description": "Cross-site Scripting",
        "details": "Malicious scripts injected into web pages"
    },
    "sql": {
        "severity": "High",
        "description": "Database Attack",
        "details": "Malicious SQL queries attempting to manipulate database"
    },
    "ddos": {
        "severity": "High",
        "description": "Denial of Service",
        "details": "Overwhelming system resources"
    },
    "bruteforce": {
        "severity": "Medium",
        "description": "Password Attack",
        "details": "Repeated login attempts"
    },
    "mitm": {
        "severity": "Medium",
        "description": "Man in the Middle",
        "details": "Intercepting network traffic"
    }
}

# Add these imports
from sklearn.ensemble import RandomForestClassifier
import numpy as np
import pickle
import os

# Path to save model
MODEL_PATH = "backend/models/threat_detection_model.pkl"


# Feature extraction function
def extract_features(log_entry):
    """Extract features from a log entry for ML processing."""
    # This is simplified - in reality, you'd extract more sophisticated features
    features = []

    # Example features (you would expand this)
    # Is the IP internal or external?
    ip_parts = log_entry["ip"].split(".")
    is_internal = 1 if ip_parts[0] == "192" and ip_parts[1] == "168" else 0
    features.append(is_internal)

    # Attack type encoded as number
    attack_types = ["XSS", "SQL", "DDOS", "BRUTEFORCE", "MITM"]
    attack_type_idx = next((i for i, a in enumerate(attack_types) if a == log_entry["type"]), -1)
    features.append(attack_type_idx)

    # Time of day (hour)
    try:
        hour = int(log_entry["timestamp"].split()[1].split(":")[0])
        features.append(hour)
    except:
        features.append(0)

    return features


# Train model with existing data
def train_detection_model():
    """Train a machine learning model to detect attacks based on log data."""
    logs = get_logs()

    if len(logs) < 10:
        return None, "Not enough data to train model"

    # Extract features and labels
    X = []
    y = []

    for log in logs:
        X.append(extract_features(log))
        # For this example, we'll consider 'High' severity as 1, others as 0
        is_high_severity = 1 if log.get("severity") == "High" else 0
        y.append(is_high_severity)

    # Train a Random Forest model
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(np.array(X), np.array(y))

    # Save the model
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)

    return model, "Model trained successfully"


# Predict attack severity using AI
def predict_attack_severity(log_entry):
    """Use trained model to predict if an attack is high severity."""
    # Load model if exists
    if not os.path.exists(MODEL_PATH):
        return None, "No trained model found"

    with open(MODEL_PATH, 'rb') as f:
        model = pickle.load(f)

    # Extract features
    features = extract_features(log_entry)

    # Make prediction
    prediction = model.predict([features])[0]
    prediction_proba = model.predict_proba([features])[0][1]  # Probability of class 1

    return prediction, prediction_proba


# New route to train model
@app.route("/api/train-detection-model", methods=["POST"])
def train_model_endpoint():
    """Train the attack detection model."""
    model, message = train_detection_model()
    if model:
        return jsonify({"message": message, "success": True}), 200
    return jsonify({"message": message, "success": False}), 400


# Update the attack logging to use AI prediction
def log_attack(attack_data):
    """Append attack data to log file with AI-based severity prediction."""
    try:
        # If severity not provided, predict it
        if "severity" not in attack_data:
            prediction, probability = predict_attack_severity(attack_data)
            if prediction is not None:
                attack_data["severity"] = "High" if prediction == 1 else "Low"
                attack_data["ai_severity_score"] = float(probability)
                attack_data["ai_analyzed"] = True

        with open(LOG_FILE, "a") as file:
            file.write(json.dumps(attack_data) + "\n")

        # If high severity, consider blocking the IP
        if attack_data.get("severity") == "High" and attack_data.get("ai_analyzed", False):
            BLOCKED_IPS.add(attack_data["ip"])

    except Exception as e:
        print(f"Error writing to log file: {e}")


from sklearn.ensemble import IsolationForest


def detect_anomalies(logs, contamination=0.1):
    """Detect anomalies in the logs using Isolation Forest."""
    # Extract features
    X = [extract_features(log) for log in logs]

    # Train isolation forest
    model = IsolationForest(contamination=contamination)
    model.fit(X)

    # Predict anomalies (-1 is anomaly, 1 is normal)
    predictions = model.predict(X)

    # Return anomalous logs
    anomalies = [logs[i] for i, pred in enumerate(predictions) if pred == -1]
    return anomalies


# Add these to your Flask application

# Store blocked IPs
BLOCKED_IPS = set()

@app.route("/api/block/<ip>", methods=["POST"])
def block_ip(ip):
    """Block an IP address."""
    BLOCKED_IPS.add(ip)
    return jsonify({"message": f"IP {ip} has been blocked", "blocked_ips": list(BLOCKED_IPS)}), 200

@app.route("/api/unblock/<ip>", methods=["POST"])
def unblock_ip(ip):
    """Unblock an IP address."""
    if ip in BLOCKED_IPS:
        BLOCKED_IPS.remove(ip)
        return jsonify({"message": f"IP {ip} has been unblocked", "blocked_ips": list(BLOCKED_IPS)}), 200
    return jsonify({"error": f"IP {ip} was not blocked"}), 400

@app.route("/api/blocked-ips", methods=["GET"])
def get_blocked_ips():
    """Get all blocked IPs."""
    return jsonify({"blocked_ips": list(BLOCKED_IPS)}), 200

# Middleware to check if IP is blocked
@app.before_request
def check_if_blocked():
    client_ip = request.remote_addr
    if client_ip in BLOCKED_IPS:
        return jsonify({"error": "Access denied. Your IP has been blocked."}), 403


def generate_attack_with_groq(base_attack_type=None):
    """Generate a new attack pattern using Groq LLama model."""
    url = "https://api.groq.com/openai/v1/chat/completions"

    # Craft prompt based on existing attack or request new one
    if base_attack_type and base_attack_type in ATTACK_TYPES:
        prompt = f"Generate a variation of a {base_attack_type} attack with details including: a name, severity (High/Medium/Low), a short description (under 10 words), and detailed explanation (1-2 sentences). Format as JSON with keys: name, severity, description, details."
    else:
        prompt = "Generate a new network security attack with details including: a name, severity (High/Medium/Low), a short description (under 10 words), and detailed explanation (1-2 sentences). Format as JSON with keys: name, severity, description, details."

    payload = {
        "model": "llama-3.3-70b-versatile",
        "messages": [{
            "role": "user",
            "content": prompt
        }]
    }

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {GROQ_API_KEY}"
    }

    try:
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()  # Will raise an exception for 4XX/5XX responses

        result = response.json()
        content = result["choices"][0]["message"]["content"]

        # Parse the JSON from the response
        # The model might return markdown-formatted JSON, so we need to extract it
        import re
        json_match = re.search(r'{[\s\S]*}', content)
        if json_match:
            attack_data = json.loads(json_match.group(0))
            return attack_data
        else:
            print(f"Failed to extract JSON from response: {content}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"API request failed: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"JSON parsing error: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error in Groq API call: {e}")
        return None


@app.route("/api/simulate/ai-attack", methods=["POST"])
def simulate_ai_attack():
    """Generate and simulate an AI-created attack pattern."""
    base_type = request.json.get("base_type") if request.json else None

    # Generate attack using Groq
    ai_attack = generate_attack_with_groq(base_type)

    if not ai_attack:
        return jsonify({"error": "Failed to generate attack with AI. Check server logs for details."}), 500

    try:
        # Create an attack ID (lowercase name with hyphens)
        attack_id = ai_attack["name"].lower().replace(" ", "-")

        # Add to attack types dictionary temporarily
        ATTACK_TYPES[attack_id] = {
            "severity": ai_attack["severity"],
            "description": ai_attack["description"],
            "details": ai_attack["details"]
        }

        # Generate IP
        attacker_ip = f"192.168.1.{random.randint(1, 254)}"

        # Log the attack
        attack_data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": ai_attack["name"].upper(),
            "severity": ai_attack["severity"],
            "description": ai_attack["description"],
            "details": ai_attack["details"],
            "ip": attacker_ip,
            "ai_generated": True
        }

        log_attack(attack_data)

        return jsonify({
            "message": f"AI-generated attack simulated: {ai_attack['name']}",
            "severity": ai_attack["severity"],
            "description": ai_attack["description"],
            "details": attack_data
        }), 200
    except KeyError as e:
        return jsonify({"error": f"Missing required field in AI response: {str(e)}"}), 500


@app.route('/api/generate-ai-attacks', methods=['POST'])
def generate_ai_attacks():
    """Generate multiple AI-created attack patterns."""
    try:
        num_entries = int(request.json.get('count', 3))
        successful_attacks = 0

        for _ in range(num_entries):
            ai_attack = generate_attack_with_groq()

            if ai_attack:
                try:
                    # Create an attack ID
                    attack_id = ai_attack["name"].lower().replace(" ", "-")

                    # Generate timestamp and IP
                    time_delta = timedelta(
                        hours=random.randint(0, 23),
                        minutes=random.randint(0, 59),
                        seconds=random.randint(0, 59)
                    )

                    timestamp = (datetime.now() - time_delta).strftime("%Y-%m-%d %H:%M:%S")
                    attacker_ip = f"192.168.1.{random.randint(1, 254)}"

                    # Log the attack
                    attack_data = {
                        "timestamp": timestamp,
                        "type": ai_attack["name"].upper(),
                        "severity": ai_attack["severity"],
                        "description": ai_attack["description"],
                        "details": ai_attack["details"],
                        "ip": attacker_ip,
                        "ai_generated": True
                    }

                    log_attack(attack_data)
                    successful_attacks += 1
                except KeyError as e:
                    print(f"Missing field in AI response: {str(e)}")
                    continue

        if successful_attacks > 0:
            return jsonify({"message": f"Generated {successful_attacks} AI attacks"}), 200
        else:
            return jsonify({"error": "Failed to generate any AI attacks"}), 500
    except Exception as e:
        return jsonify({"error": f"Error generating AI attacks: {str(e)}"}), 400


# Function to log attacks
def log_attack(attack_data):
    """Append attack data to log file."""
    try:
        with open(LOG_FILE, "a") as file:
            file.write(json.dumps(attack_data) + "\n")
    except Exception as e:
        print(f"Error writing to log file: {e}")


# Function to retrieve logs
def get_logs():
    """Read logs from file and return them as a list."""
    logs = []
    try:
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r") as file:
                logs = [json.loads(line.strip()) for line in file if line.strip()]
        else:
            # If log file doesn't exist, return empty list
            return []
    except Exception as e:
        print(f"Error reading log file: {e}")
        return []
    return logs


@app.route("/")
def index():
    """Render dashboard page."""
    return render_template("index.html")


@app.route("/live-logs")
def live_logs():
    """Render live logs page."""
    return render_template("live-logs.html")


@app.route("/api/simulate/<attack_type>", methods=["POST"])
def simulate_attack(attack_type):
    """Simulate an attack and log it."""
    if attack_type not in ATTACK_TYPES:
        return jsonify({"error": "Invalid attack type"}), 400

    attack_info = ATTACK_TYPES[attack_type]
    attacker_ip = request.remote_addr  # Get attacker's IP

    # Generate random IP if running locally
    if attacker_ip == "127.0.0.1":
        attacker_ip = f"192.168.1.{random.randint(1, 254)}"

    attack_data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": attack_type.upper(),
        "severity": attack_info["severity"],
        "description": attack_info["description"],
        "details": attack_info["details"],
        "ip": attacker_ip
    }

    log_attack(attack_data)

    return jsonify({
        "message": f"{attack_type.upper()} Attack simulated",
        "severity": attack_info["severity"],
        "description": attack_info["description"]
    }), 200


@app.route("/api/events", methods=["GET"])
def get_events():
    """Fetch attack logs."""
    return jsonify(get_logs())


@app.route("/api/logs", methods=["GET"])
def fetch_logs():
    """Fetch all attack logs."""
    return jsonify(get_logs())


@app.route('/api/attack', methods=['POST'])
def attack():
    """Detect and log an attack."""
    data = request.json
    attack_type = data.get("type")
    ip = data.get("ip")

    if not attack_type or not ip:
        return jsonify({"error": "Missing attack type or IP"}), 400

    # Determine severity and description based on attack type
    severity = "Medium"  # Default
    description = ""

    # Try to match with known attack types
    attack_key = attack_type.lower()
    if attack_key in ATTACK_TYPES:
        severity = ATTACK_TYPES[attack_key]["severity"]
        description = ATTACK_TYPES[attack_key]["description"]

    attack_data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": attack_type.upper(),
        "severity": severity,
        "description": description,
        "ip": ip
    }

    log_attack(attack_data)

    return jsonify({"message": "Attack logged", "data": attack_data}), 200


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get attack statistics for dashboard."""
    logs = get_logs()

    # Calculate statistics
    attack_types = {}
    severity_counts = {'High': 0, 'Medium': 0, 'Low': 0}

    for log in logs:
        attack_type = log.get('type', 'UNKNOWN')
        if attack_type in attack_types:
            attack_types[attack_type] += 1
        else:
            attack_types[attack_type] = 1

        severity = log.get('severity')
        if severity in severity_counts:
            severity_counts[severity] += 1

    return jsonify({
        'total_attacks': len(logs),
        'attack_types': attack_types,
        'severity': severity_counts
    })


@app.route('/api/clear-logs', methods=['POST'])
def clear_logs():
    """Clear all attack logs and reset statistics."""
    try:
        if os.path.exists(LOG_FILE):
            open(LOG_FILE, "w").close()  # Effectively clears the file

        return jsonify({
            "message": "All attack logs cleared successfully",
            "total_attacks": 0,
            "attack_types": {},
            "severity": {"High": 0, "Medium": 0, "Low": 0}
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/generate-sample-data', methods=['POST'])
def generate_sample_data():
    """Generate sample attack data for testing."""
    try:
        num_entries = int(request.json.get('count', 10))

        attack_types = list(ATTACK_TYPES.keys())
        ips = [f"192.168.1.{i}" for i in range(1, 255)]

        for _ in range(num_entries):
            attack_type = random.choice(attack_types)
            attack_info = ATTACK_TYPES[attack_type]

            # Generate random timestamp from the last 24 hours
            time_delta = timedelta(
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59),
                seconds=random.randint(0, 59)
            )

            timestamp = (datetime.now() - time_delta).strftime("%Y-%m-%d %H:%M:%S")

            attack_data = {
                "timestamp": timestamp,
                "type": attack_type.upper(),
                "severity": attack_info["severity"],
                "description": attack_info["description"],
                "details": attack_info["details"],
                "ip": random.choice(ips)
            }

            log_attack(attack_data)

        return jsonify({"message": f"Generated {num_entries} sample attacks"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400







if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5001)