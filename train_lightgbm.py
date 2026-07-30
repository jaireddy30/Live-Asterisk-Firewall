import os
import sys
import pandas as pd
import numpy as np

# Check dependencies
try:
    import lightgbm as lgb
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report
    import joblib
except ImportError:
    print("[ERROR] Missing required package! Please run:")
    print("   pip install lightgbm pandas scikit-learn joblib")
    exit(1)

# Import native LogParser from Live-Asterisk-Firewall subfolder if available
sys.path.append(os.path.abspath("Live-Asterisk-Firewall-main"))
try:
    from log_parser import LogParser
except ImportError:
    LogParser = None


def parse_asterisk_log_file(file_path):
    """
    Parses a single Asterisk log file.
    """
    print(f"[INFO] Reading log file: {file_path}")
    parser = LogParser() if LogParser else None
    events = []
    
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            if parser:
                parsed_event = parser.parse(line)
                if parsed_event:
                    events.append({
                        "timestamp": parsed_event.get("timestamp", "N/A"),
                        "event_type": parsed_event.get("event", "OTHER"),
                        "source_ip": parsed_event.get("source_ip", "UNKNOWN"),
                        "username": parsed_event.get("account_id", "unknown")
                    })
            else:
                import re
                ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                ip = ip_match.group(1) if ip_match else "UNKNOWN"
                event_type = "FAILED_AUTH" if any(k in line for k in ["Invalid", "Error", "Failed", "FAILURE"]) else "NORMAL"
                events.append({
                    "timestamp": "N/A",
                    "event_type": event_type,
                    "source_ip": ip,
                    "username": "unknown"
                })
    return events


def parse_target_path(target_path):
    """
    Handles both single log file path OR a folder directory containing log files.
    """
    all_events = []
    
    if os.path.isdir(target_path):
        print(f"[INFO] Target is a folder directory: {target_path}")
        log_files = []
        for root, dirs, files in os.walk(target_path):
            for file in files:
                if file.endswith(".log") or file.endswith(".txt") or "asterisk" in file.lower():
                    log_files.append(os.path.join(root, file))
                    
        if not log_files:
            print(f"[ERROR] No .log or log files found inside folder: {target_path}")
            return pd.DataFrame()
            
        print(f"[INFO] Found {len(log_files)} log file(s) in directory:")
        for lf in log_files:
            print(f"   -> {lf}")
            all_events.extend(parse_asterisk_log_file(lf))
    else:
        all_events.extend(parse_asterisk_log_file(target_path))
        
    return pd.DataFrame(all_events)


def extract_features(df):
    """
    Aggregates log events per IP address into numerical features for LightGBM.
    """
    if df.empty:
        return pd.DataFrame()
        
    print("[INFO] Extracting features per IP address...")
    profiles = []
    
    for ip, ip_df in df.groupby("source_ip"):
        if ip in ("UNKNOWN", "127.0.0.1", "0.0.0.0") or not ip:
            continue
            
        total_events = len(ip_df)
        failed_auth = len(ip_df[ip_df["event_type"].isin(["FAILED_AUTH", "INVALID_USER", "TOLL_FRAUD", "AUTH_FAILURE"])])
        success_auth = len(ip_df[ip_df["event_type"].isin(["AUTH_SUCCESS", "SUCCESS"])])
        unique_users = ip_df["username"].nunique()
        fail_ratio = failed_auth / total_events if total_events > 0 else 0
        
        # Labeling rule: 1 = Attack, 0 = Normal
        label = 1 if (failed_auth >= 3 or fail_ratio > 0.5) else 0

        profiles.append({
            "source_ip": ip,
            "total_events": total_events,
            "failed_auth": failed_auth,
            "success_auth": success_auth,
            "unique_users": unique_users,
            "fail_ratio": fail_ratio,
            "is_attack": label
        })
        
    return pd.DataFrame(profiles)


def train_lightgbm(feature_df):
    """
    Trains a LightGBM Classifier model on extracted Asterisk log features.
    """
    print("[INFO] Training LightGBM Model...")
    
    if feature_df.empty:
        print("[ERROR] No valid IP features extracted from logs.")
        return None

    feature_cols = ["total_events", "failed_auth", "success_auth", "unique_users", "fail_ratio"]
    X = feature_df[feature_cols]
    y = feature_df["is_attack"]

    if len(feature_df) < 5:
        print("[WARNING] Small dataset detected. Training directly on available IP profiles.")
        X_train, y_train = X, y
        X_test, y_test = X, y
    else:
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # LightGBM Classifier
    model = lgb.LGBMClassifier(
        n_estimators=100,
        learning_rate=0.05,
        num_leaves=15,
        max_depth=4,
        random_state=42,
        verbose=-1
    )
    
    model.fit(X_train, y_train)

    print("\n--- LightGBM Model Evaluation Report ---")
    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred, zero_division=0))

    # Save model
    model_filename = "lightgbm_log_model.pkl"
    joblib.dump(model, model_filename)
    print(f"[SUCCESS] Model successfully saved to '{model_filename}'!")
    return model


if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_path = sys.argv[1]
    else:
        possible_defaults = [
            "Live-Asterisk-Firewall-main/data/sim_asterisk.log",
            "data/sim_asterisk.log",
            "data/raw/asterisk_security.log"
        ]
        target_path = None
        for p in possible_defaults:
            if os.path.exists(p):
                target_path = p
                break
                
        if not target_path:
            print("[ERROR] No default log file found.")
            print("Usage: python train_lightgbm.py \"C:\\path\\to\\your_log_file.log\"")
            exit(1)

    if not os.path.exists(target_path):
        print(f"[ERROR] Path '{target_path}' not found.")
        exit(1)

    df_logs = parse_target_path(target_path)
    feature_df = extract_features(df_logs)
    
    if not feature_df.empty:
        print("\nExtracted IP Features:")
        print(feature_df)
        print("-" * 50)
        train_lightgbm(feature_df)
    else:
        print("[ERROR] Could not extract features. Check log file format.")