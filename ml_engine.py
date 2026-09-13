import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_recall_fscore_support

MODEL_DIR = 'models'
MODEL_PATH = os.path.join(MODEL_DIR, 'ids_model.joblib')
SCALER_PATH = os.path.join(MODEL_DIR, 'ids_scaler.joblib')
METRICS_PATH = os.path.join(MODEL_DIR, 'model_metrics.json')

FEATURE_COLUMNS = [
    'duration', 'protocol_type', 'service', 'src_bytes', 'dst_bytes', 
    'flag', 'wrong_fragment', 'hot', 'failed_logins', 'count', 
    'srv_count', 'same_srv_rate', 'diff_srv_rate', 'dst_host_srv_count', 
    'dst_host_same_srv_rate'
]

LABEL_NAMES = {
    0: 'Normal Traffic',
    1: 'DoS / DDoS Attack',
    2: 'Port Scan / Probe',
    3: 'Brute Force Attack'
}

LABEL_SEVERITY = {
    0: {'level': 'SAFE', 'color': '#00e676', 'badge': 'badge-success'},
    1: {'level': 'CRITICAL', 'color': '#ff1744', 'badge': 'badge-danger'},
    2: {'level': 'HIGH', 'color': '#ff9100', 'badge': 'badge-warning'},
    3: {'level': 'CRITICAL', 'color': '#d500f9', 'badge': 'badge-purple'}
}

LABEL_MITIGATIONS = {
    0: "Normal system operation. No threat detected.",
    1: "CRITICAL: SYN/UDP DDoS flood detected. Enable Rate Limiting, trigger IP Banning on firewall, and activate Cloudflare / Anti-DDoS scrubbing center.",
    2: "HIGH RISK: Port Scanning / Nmap Reconnaissance detected. Block source IP address, conceal exposed listening ports, and update IDS firewall filter rules.",
    3: "CRITICAL: SSH/FTP Brute Force Authentication attack detected. Enforce multi-factor authentication (MFA), lock target user account, and add source IP to Fail2ban blacklist."
}

PROTOCOL_MAP = {0: 'TCP', 1: 'UDP', 2: 'ICMP'}
SERVICE_MAP = {0: 'HTTP', 1: 'SSH', 2: 'FTP', 3: 'DNS', 4: 'SMTP', 5: 'OTHER'}
FLAG_MAP = {0: 'SF (Normal)', 1: 'S0 (SYN Flood)', 2: 'REJ (Rejected)', 3: 'RSTO (Reset)'}


class IDSEngine:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.metrics = None
        self.is_loaded = False
        
        os.makedirs(MODEL_DIR, exist_ok=True)
        self.load_or_train()

    def train_model(self, data_path='data/network_traffic.csv', n_estimators=100, max_depth=16):
        """Train Random Forest model using dataset and save artifacts."""
        if not os.path.exists(data_path):
            from dataset_generator import generate_network_dataset
            df = generate_network_dataset(num_samples=8000)
            os.makedirs('data', exist_ok=True)
            df.to_csv(data_path, index=False)
        else:
            df = pd.read_csv(data_path)
            
        X = df[FEATURE_COLUMNS]
        y = df['label']

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.20, random_state=42, stratify=y
        )

        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)

        model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=42,
            n_jobs=-1
        )
        model.fit(X_train_scaled, y_train)

        # Predictions & Metrics
        y_pred = model.predict(X_test_scaled)
        acc = float(accuracy_score(y_test, y_pred))

        precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='weighted')
        cm = confusion_matrix(y_test, y_pred).tolist()

        # Feature Importance
        importances = model.feature_importances_
        feature_importance_dict = [
            {'feature': feat, 'importance': round(float(imp) * 100, 2)}
            for feat, imp in zip(FEATURE_COLUMNS, importances)
        ]
        feature_importance_dict = sorted(feature_importance_dict, key=lambda x: x['importance'], reverse=True)

        # Per-class metrics
        class_prec, class_rec, class_f1, class_supp = precision_recall_fscore_support(y_test, y_pred)
        per_class_report = {}
        for cls_id in range(4):
            per_class_report[LABEL_NAMES[cls_id]] = {
                'precision': round(float(class_prec[cls_id]) * 100, 2),
                'recall': round(float(class_rec[cls_id]) * 100, 2),
                'f1_score': round(float(class_f1[cls_id]) * 100, 2),
                'support': int(class_supp[cls_id])
            }

        metrics_data = {
            'accuracy': round(acc * 100, 2),
            'precision': round(float(precision) * 100, 2),
            'recall': round(float(recall) * 100, 2),
            'f1_score': round(float(f1) * 100, 2),
            'confusion_matrix': cm,
            'feature_importances': feature_importance_dict,
            'per_class_metrics': per_class_report,
            'total_test_samples': len(y_test),
            'model_name': 'Random Forest Classifier',
            'n_estimators': n_estimators,
            'max_depth': max_depth
        }

        # Save artifacts
        joblib.dump(model, MODEL_PATH)
        joblib.dump(scaler, SCALER_PATH)
        with open(METRICS_PATH, 'w') as f:
            json.dump(metrics_data, f, indent=4)

        self.model = model
        self.scaler = scaler
        self.metrics = metrics_data
        self.is_loaded = True
        
        print(f"Model successfully trained! Accuracy: {acc*100:.2f}%")
        return metrics_data

    def load_or_train(self):
        """Loads serialized model and scaler or trains if missing."""
        if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH) and os.path.exists(METRICS_PATH):
            try:
                self.model = joblib.load(MODEL_PATH)
                self.scaler = joblib.load(SCALER_PATH)
                with open(METRICS_PATH, 'r') as f:
                    self.metrics = json.load(f)
                self.is_loaded = True
                print(f"Loaded active model with accuracy {self.metrics.get('accuracy')}%")
                return
            except Exception as e:
                print(f"Error loading model artifacts: {e}. Re-training...")
        
        self.train_model()

    def predict_single(self, feature_dict):
        """Runs prediction for a single network packet feature dictionary."""
        if not self.is_loaded:
            self.load_or_train()

        # Vector format
        vector = []
        for col in FEATURE_COLUMNS:
            val = float(feature_dict.get(col, 0.0))
            vector.append(val)

        # Vector format as DataFrame with column names to prevent scaler feature warning
        vector_df = pd.DataFrame([vector], columns=FEATURE_COLUMNS)
        scaled_vector = self.scaler.transform(vector_df)

        probabilities = self.model.predict_proba(scaled_vector)[0]
        pred_label_id = int(np.argmax(probabilities))
        confidence = float(probabilities[pred_label_id]) * 100

        prob_breakdown = {
            LABEL_NAMES[i]: round(float(probabilities[i]) * 100, 2)
            for i in range(len(probabilities))
        }

        severity = LABEL_SEVERITY[pred_label_id]
        mitigation = LABEL_MITIGATIONS[pred_label_id]

        return {
            'prediction': LABEL_NAMES[pred_label_id],
            'label_id': pred_label_id,
            'confidence': round(confidence, 2),
            'severity': severity['level'],
            'color': severity['color'],
            'badge': severity['badge'],
            'mitigation': mitigation,
            'probabilities': prob_breakdown,
            'protocol_str': PROTOCOL_MAP.get(int(feature_dict.get('protocol_type', 0)), 'TCP'),
            'service_str': SERVICE_MAP.get(int(feature_dict.get('service', 0)), 'HTTP'),
            'flag_str': FLAG_MAP.get(int(feature_dict.get('flag', 0)), 'SF')
        }

    def predict_batch(self, df):
        """Runs batch prediction for pandas dataframe."""
        if not self.is_loaded:
            self.load_or_train()

        # Ensure required columns exist
        missing_cols = [c for c in FEATURE_COLUMNS if c not in df.columns]
        if missing_cols:
            raise ValueError(f"Missing required feature columns in CSV: {missing_cols}")

        X = df[FEATURE_COLUMNS].astype(float)
        X_scaled = self.scaler.transform(X)

        probabilities = self.model.predict_proba(X_scaled)
        preds = np.argmax(probabilities, axis=1)
        confidences = np.max(probabilities, axis=1) * 100

        results = []
        counts = {0: 0, 1: 0, 2: 0, 3: 0}

        for i, pred_id in enumerate(preds):
            pred_id = int(pred_id)
            counts[pred_id] += 1
            severity = LABEL_SEVERITY[pred_id]
            results.append({
                'row_index': i + 1,
                'prediction': LABEL_NAMES[pred_id],
                'label_id': pred_id,
                'confidence': round(float(confidences[i]), 2),
                'severity': severity['level'],
                'color': severity['color'],
                'src_bytes': float(df.iloc[i].get('src_bytes', 0)),
                'dst_bytes': float(df.iloc[i].get('dst_bytes', 0)),
                'duration': float(df.iloc[i].get('duration', 0)),
                'count': int(df.iloc[i].get('count', 0))
            })

        total = len(df)
        malicious_count = total - counts[0]

        summary = {
            'total_packets': total,
            'normal_count': counts[0],
            'dos_count': counts[1],
            'probe_count': counts[2],
            'brute_force_count': counts[3],
            'malicious_count': malicious_count,
            'threat_ratio': round((malicious_count / total) * 100, 2) if total > 0 else 0
        }

        return {
            'summary': summary,
            'predictions': results
        }

# Global singleton instance
ids_engine = IDSEngine()

if __name__ == '__main__':
    print("Testing IDSEngine...")
    print("Metrics:", json.dumps(ids_engine.metrics, indent=2))
    
    # Test single prediction
    sample_normal = {
        'duration': 12.5, 'protocol_type': 0, 'service': 0, 'src_bytes': 450,
        'dst_bytes': 2300, 'flag': 0, 'wrong_fragment': 0, 'hot': 0,
        'failed_logins': 0, 'count': 10, 'srv_count': 8, 'same_srv_rate': 0.95,
        'diff_srv_rate': 0.05, 'dst_host_srv_count': 150, 'dst_host_same_srv_rate': 0.90
    }
    res = ids_engine.predict_single(sample_normal)
    print("\nSample Normal Prediction:", res['prediction'], "| Confidence:", res['confidence'], "%")

    sample_ddos = {
        'duration': 0.001, 'protocol_type': 0, 'service': 0, 'src_bytes': 20,
        'dst_bytes': 0, 'flag': 1, 'wrong_fragment': 0, 'hot': 0,
        'failed_logins': 0, 'count': 450, 'srv_count': 420, 'same_srv_rate': 0.98,
        'diff_srv_rate': 0.02, 'dst_host_srv_count': 5, 'dst_host_same_srv_rate': 0.15
    }
    res_ddos = ids_engine.predict_single(sample_ddos)
    print("Sample DDoS Prediction:", res_ddos['prediction'], "| Confidence:", res_ddos['confidence'], "%")
