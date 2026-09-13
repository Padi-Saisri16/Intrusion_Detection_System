import os
import time
import json
import random
from datetime import datetime
from flask import Flask, render_template, request, jsonify, Response
import pandas as pd
from ml_engine import ids_engine, FEATURE_COLUMNS, LABEL_NAMES, LABEL_SEVERITY

app = Flask(__name__, template_folder='templates', static_folder='static')

START_TIME = datetime.now()
SYSTEM_STATS = {
    'total_packets_scanned': 0,
    'threats_detected': 0,
    'normal_packets': 0,
    'active_session_id': 'SOC-IDS-v2.4'
}

ALERT_LOGS = []

def add_alert_log(prediction_res, src_ip=None, dst_ip=None):
    """Appends prediction to runtime in-memory logs."""
    global SYSTEM_STATS, ALERT_LOGS
    SYSTEM_STATS['total_packets_scanned'] += 1
    
    if prediction_res['label_id'] == 0:
        SYSTEM_STATS['normal_packets'] += 1
    else:
        SYSTEM_STATS['threats_detected'] += 1

    if src_ip is None:
        src_ip = f"{random.randint(10, 192)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    if dst_ip is None:
        dst_ip = f"192.168.1.{random.randint(10, 100)}"

    log_entry = {
        'id': f"ALT-{random.randint(10000, 99999)}",
        'timestamp': datetime.now().strftime('%H:%M:%S'),
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'threat': prediction_res['prediction'],
        'severity': prediction_res['severity'],
        'color': prediction_res['color'],
        'confidence': prediction_res['confidence'],
        'protocol': prediction_res.get('protocol_str', 'TCP'),
        'service': prediction_res.get('service_str', 'HTTP'),
        'mitigation': prediction_res['mitigation']
    }
    
    ALERT_LOGS.insert(0, log_entry)
    if len(ALERT_LOGS) > 200:
        ALERT_LOGS = ALERT_LOGS[:200]
        
    return log_entry

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/status', methods=['GET'])
def get_status():
    uptime = str(datetime.now() - START_TIME).split('.')[0]
    metrics = ids_engine.metrics or {}
    return jsonify({
        'status': 'ONLINE',
        'uptime': uptime,
        'model_name': metrics.get('model_name', 'Random Forest Classifier'),
        'model_accuracy': metrics.get('accuracy', 96.5),
        'total_scanned': SYSTEM_STATS['total_packets_scanned'],
        'threats_detected': SYSTEM_STATS['threats_detected'],
        'normal_packets': SYSTEM_STATS['normal_packets'],
        'threat_rate': round((SYSTEM_STATS['threats_detected'] / max(1, SYSTEM_STATS['total_packets_scanned'])) * 100, 1),
        'active_session': SYSTEM_STATS['active_session_id']
    })

@app.route('/api/model/metrics', methods=['GET'])
def get_metrics():
    if not ids_engine.is_loaded:
        ids_engine.load_or_train()
    return jsonify(ids_engine.metrics)

@app.route('/api/predict/single', methods=['POST'])
def predict_single():
    try:
        data = request.json or {}
        res = ids_engine.predict_single(data)
        log_entry = add_alert_log(res)
        res['alert_log'] = log_entry
        return jsonify({'status': 'success', 'data': res})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@app.route('/api/predict/batch', methods=['POST'])
def predict_batch():
    try:
        if 'file' in request.files:
            file = request.files['file']
            if file.filename == '':
                return jsonify({'status': 'error', 'message': 'No file selected'}), 400
            df = pd.read_csv(file)
        elif request.json and 'data' in request.json:
            df = pd.DataFrame(request.json['data'])
        else:
            return jsonify({'status': 'error', 'message': 'No CSV file or data payload provided'}), 400

        result = ids_engine.predict_batch(df)
        
        # Log summary stats
        global SYSTEM_STATS
        SYSTEM_STATS['total_packets_scanned'] += result['summary']['total_packets']
        SYSTEM_STATS['normal_packets'] += result['summary']['normal_count']
        SYSTEM_STATS['threats_detected'] += result['summary']['malicious_count']

        return jsonify({'status': 'success', 'data': result})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@app.route('/api/simulation/stream', methods=['GET'])
def live_stream():
    """Generates server-sent events (SSE) for live network traffic simulation."""
    def generate():
        while True:
            # 70% normal, 30% attack burst
            is_attack = random.random() < 0.35
            if is_attack:
                attack_type = random.choice([1, 2, 3])
                if attack_type == 1: # DoS
                    packet = {
                        'duration': round(random.uniform(0.001, 0.05), 4),
                        'protocol_type': 0, 'service': 0,
                        'src_bytes': random.randint(10, 80), 'dst_bytes': 0,
                        'flag': 1, 'wrong_fragment': 0, 'hot': 0, 'failed_logins': 0,
                        'count': random.randint(300, 500), 'srv_count': random.randint(280, 480),
                        'same_srv_rate': round(random.uniform(0.90, 1.0), 2),
                        'diff_srv_rate': round(random.uniform(0.0, 0.05), 2),
                        'dst_host_srv_count': random.randint(1, 20),
                        'dst_host_same_srv_rate': round(random.uniform(0.05, 0.25), 2)
                    }
                elif attack_type == 2: # Port scan
                    packet = {
                        'duration': round(random.uniform(0.01, 0.2), 4),
                        'protocol_type': 0, 'service': random.randint(0, 5),
                        'src_bytes': random.randint(0, 50), 'dst_bytes': 0,
                        'flag': 2, 'wrong_fragment': 0, 'hot': 0, 'failed_logins': 0,
                        'count': random.randint(150, 350), 'srv_count': random.randint(1, 5),
                        'same_srv_rate': round(random.uniform(0.01, 0.15), 2),
                        'diff_srv_rate': round(random.uniform(0.80, 1.0), 2),
                        'dst_host_srv_count': random.randint(1, 10),
                        'dst_host_same_srv_rate': round(random.uniform(0.01, 0.10), 2)
                    }
                else: # Brute Force
                    packet = {
                        'duration': round(random.uniform(1.0, 5.0), 4),
                        'protocol_type': 0, 'service': 1,
                        'src_bytes': random.randint(200, 500), 'dst_bytes': random.randint(300, 600),
                        'flag': 0, 'wrong_fragment': 0, 'hot': random.randint(2, 5),
                        'failed_logins': random.randint(3, 7),
                        'count': random.randint(50, 120), 'srv_count': random.randint(45, 110),
                        'same_srv_rate': round(random.uniform(0.85, 1.0), 2),
                        'diff_srv_rate': round(random.uniform(0.0, 0.10), 2),
                        'dst_host_srv_count': random.randint(50, 150),
                        'dst_host_same_srv_rate': round(random.uniform(0.70, 0.90), 2)
                    }
            else: # Normal
                packet = {
                    'duration': round(random.uniform(2.0, 25.0), 4),
                    'protocol_type': random.choice([0, 1]),
                    'service': random.choice([0, 3]),
                    'src_bytes': random.randint(200, 2000),
                    'dst_bytes': random.randint(500, 8000),
                    'flag': 0, 'wrong_fragment': 0, 'hot': 0, 'failed_logins': 0,
                    'count': random.randint(2, 20), 'srv_count': random.randint(2, 18),
                    'same_srv_rate': round(random.uniform(0.85, 1.0), 2),
                    'diff_srv_rate': round(random.uniform(0.0, 0.10), 2),
                    'dst_host_srv_count': random.randint(80, 255),
                    'dst_host_same_srv_rate': round(random.uniform(0.80, 1.0), 2)
                }

            res = ids_engine.predict_single(packet)
            log = add_alert_log(res)
            
            event_data = {
                'packet': packet,
                'prediction': res,
                'log': log,
                'stats': {
                    'total': SYSTEM_STATS['total_packets_scanned'],
                    'threats': SYSTEM_STATS['threats_detected'],
                    'normal': SYSTEM_STATS['normal_packets']
                }
            }
            yield f"data: {json.dumps(event_data)}\n\n"
            time.sleep(1.5)

    return Response(generate(), mimetype='text/event-stream')

@app.route('/api/logs', methods=['GET'])
def get_logs():
    severity_filter = request.args.get('severity', None)
    limit = int(request.args.get('limit', 100))
    
    logs = ALERT_LOGS
    if severity_filter:
        logs = [l for l in logs if l['severity'].upper() == severity_filter.upper()]
        
    return jsonify({'status': 'success', 'count': len(logs), 'logs': logs[:limit]})

@app.route('/api/model/retrain', methods=['POST'])
def retrain_model():
    try:
        params = request.json or {}
        n_estimators = int(params.get('n_estimators', 100))
        max_depth = int(params.get('max_depth', 16))
        
        metrics = ids_engine.train_model(n_estimators=n_estimators, max_depth=max_depth)
        return jsonify({'status': 'success', 'message': 'Model successfully re-trained!', 'metrics': metrics})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

if __name__ == '__main__':
    print("Starting Intrusion Detection System (IDS) Flask Server...")
    app.run(host='0.0.0.0', port=5000, debug=True)
