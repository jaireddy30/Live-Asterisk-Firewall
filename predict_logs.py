import joblib
import pandas as pd

def predict_ip_threat(model_path, ip_features):
    """
    Loads a trained LightGBM model and predicts threat probability for an IP address.
    """
    try:
        model = joblib.load(model_path)
    except FileNotFoundError:
        print(f"[ERROR] Model file '{model_path}' not found. Please run train_lightgbm.py first.")
        return

    # Create DataFrame from input features
    df = pd.DataFrame([ip_features])
    
    # Feature columns expected by LightGBM
    feature_cols = ["total_events", "failed_auth", "success_auth", "unique_users", "fail_ratio"]
    X = df[feature_cols]

    # Prediction (0 = Normal, 1 = Attack)
    prediction = model.predict(X)[0]
    probability = model.predict_proba(X)[0][1]

    print("\n--- Real-Time LightGBM Threat Detection ---")
    print(f"Target IP Metrics: {ip_features}")
    print(f"Attack Probability: {probability:.2%}")

    if prediction == 1:
        print("[ALERT] THREAT DETECTED! Action: BLOCK IP ADDRESS")
    else:
        print("[INFO] NORMAL TRAFFIC. Action: ALLOW")

if __name__ == "__main__":
    # Example: Suspicious IP with 15 failed logins and high failure ratio
    suspicious_ip_data = {
        "total_events": 18,
        "failed_auth": 15,
        "success_auth": 0,
        "unique_users": 8,
        "fail_ratio": 0.83
    }
    
    predict_ip_threat("lightgbm_log_model.pkl", suspicious_ip_data)
