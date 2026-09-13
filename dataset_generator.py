import os
import numpy as np
import pandas as pd

def generate_network_dataset(num_samples=8000, seed=42):
    """
    Generates a realistic synthetic network traffic dataset for Intrusion Detection System (IDS).
    Features match standard network flow telemetry (NSL-KDD / CICIDS benchmark structure).
    
    Classes:
    0: Normal
    1: DoS / DDoS Attack
    2: Port Scan / Probe
    3: Brute Force
    """
    np.random.seed(seed)
    
    samples_per_class = num_samples // 4
    
    # --- Class 0: Normal Traffic ---
    n0 = samples_per_class
    duration_0 = np.random.exponential(scale=12.0, size=n0) + 0.1
    protocol_0 = np.random.choice([0, 1, 2], size=n0, p=[0.70, 0.25, 0.05]) # TCP, UDP, ICMP
    service_0 = np.random.choice([0, 1, 2, 3, 4, 5], size=n0, p=[0.50, 0.10, 0.10, 0.15, 0.10, 0.05])
    src_bytes_0 = np.random.gamma(shape=2.0, scale=400.0, size=n0) + 40
    dst_bytes_0 = np.random.gamma(shape=3.0, scale=1200.0, size=n0) + 100
    flag_0 = np.random.choice([0, 1, 2, 3], size=n0, p=[0.92, 0.04, 0.03, 0.01]) # SF (Normal)
    wrong_frag_0 = np.zeros(n0)
    hot_0 = np.random.choice([0, 1], size=n0, p=[0.98, 0.02])
    failed_logins_0 = np.zeros(n0)
    count_0 = np.random.poisson(lam=12, size=n0) + 1
    srv_count_0 = np.random.poisson(lam=10, size=n0) + 1
    same_srv_rate_0 = np.random.uniform(0.75, 1.0, size=n0)
    diff_srv_rate_0 = np.random.uniform(0.0, 0.15, size=n0)
    dst_host_srv_count_0 = np.random.randint(50, 255, size=n0)
    dst_host_same_srv_rate_0 = np.random.uniform(0.70, 1.0, size=n0)
    label_0 = np.zeros(n0, dtype=int)
    
    # --- Class 1: DoS / DDoS Attack ---
    n1 = samples_per_class
    duration_1 = np.random.uniform(0.001, 0.5, size=n1) # extremely short connection floods
    protocol_1 = np.random.choice([0, 1, 2], size=n1, p=[0.80, 0.15, 0.05])
    service_1 = np.random.choice([0, 3, 5], size=n1, p=[0.70, 0.20, 0.10]) # HTTP/DNS target
    src_bytes_1 = np.random.gamma(shape=1.5, scale=50.0, size=n1)
    dst_bytes_1 = np.random.uniform(0, 10, size=n1) # almost no server response
    flag_1 = np.random.choice([0, 1, 2, 3], size=n1, p=[0.05, 0.70, 0.20, 0.05]) # High S0/REJ (SYN flood)
    wrong_frag_1 = np.random.choice([0, 1, 3], size=n1, p=[0.85, 0.10, 0.05])
    hot_1 = np.zeros(n1)
    failed_logins_1 = np.zeros(n1)
    count_1 = np.random.randint(250, 512, size=n1) # massive burst count
    srv_count_1 = np.random.randint(200, 512, size=n1)
    same_srv_rate_1 = np.random.uniform(0.85, 1.0, size=n1)
    diff_srv_rate_1 = np.random.uniform(0.0, 0.10, size=n1)
    dst_host_srv_count_1 = np.random.randint(1, 50, size=n1)
    dst_host_same_srv_rate_1 = np.random.uniform(0.1, 0.4, size=n1)
    label_1 = np.ones(n1, dtype=int)
    
    # --- Class 2: Port Scan / Probe ---
    n2 = samples_per_class
    duration_2 = np.random.uniform(0.01, 1.2, size=n2)
    protocol_2 = np.random.choice([0, 1, 2], size=n2, p=[0.60, 0.30, 0.10])
    service_2 = np.random.choice([0, 1, 2, 3, 4, 5], size=n2, p=[0.2, 0.2, 0.2, 0.2, 0.1, 0.1])
    src_bytes_2 = np.random.uniform(0, 64, size=n2) # probe pings
    dst_bytes_2 = np.random.uniform(0, 32, size=n2)
    flag_2 = np.random.choice([0, 1, 2, 3], size=n2, p=[0.10, 0.40, 0.45, 0.05]) # High REJ/S0
    wrong_frag_2 = np.zeros(n2)
    hot_2 = np.zeros(n2)
    failed_logins_2 = np.zeros(n2)
    count_2 = np.random.randint(80, 300, size=n2)
    srv_count_2 = np.random.randint(1, 15, size=n2) # low srv_count because target ports change!
    same_srv_rate_2 = np.random.uniform(0.01, 0.25, size=n2)
    diff_srv_rate_2 = np.random.uniform(0.75, 1.0, size=n2) # High diff service rate!
    dst_host_srv_count_2 = np.random.randint(1, 25, size=n2)
    dst_host_same_srv_rate_2 = np.random.uniform(0.01, 0.20, size=n2)
    label_2 = np.full(n2, 2, dtype=int)
    
    # --- Class 3: Brute Force Attack ---
    n3 = samples_per_class
    duration_3 = np.random.exponential(scale=4.0, size=n3) + 0.2
    protocol_3 = np.zeros(n3, dtype=int) # TCP
    service_3 = np.random.choice([1, 2], size=n3, p=[0.75, 0.25]) # SSH (1) / FTP (2)
    src_bytes_3 = np.random.uniform(150, 600, size=n3)
    dst_bytes_3 = np.random.uniform(200, 800, size=n3)
    flag_3 = np.random.choice([0, 1, 2], size=n3, p=[0.70, 0.15, 0.15])
    wrong_frag_3 = np.zeros(n3)
    hot_3 = np.random.randint(1, 6, size=n3) # High sensitive access attempt
    failed_logins_3 = np.random.randint(2, 8, size=n3) # High failed logins!
    count_3 = np.random.randint(30, 150, size=n3)
    srv_count_3 = np.random.randint(25, 140, size=n3)
    same_srv_rate_3 = np.random.uniform(0.80, 1.0, size=n3)
    diff_srv_rate_3 = np.random.uniform(0.0, 0.10, size=n3)
    dst_host_srv_count_3 = np.random.randint(40, 200, size=n3)
    dst_host_same_srv_rate_3 = np.random.uniform(0.60, 0.95, size=n3)
    label_3 = np.full(n3, 3, dtype=int)
    
    # Combine dataset
    data = {
        'duration': np.concatenate([duration_0, duration_1, duration_2, duration_3]),
        'protocol_type': np.concatenate([protocol_0, protocol_1, protocol_2, protocol_3]),
        'service': np.concatenate([service_0, service_1, service_2, service_3]),
        'src_bytes': np.concatenate([src_bytes_0, src_bytes_1, src_bytes_2, src_bytes_3]),
        'dst_bytes': np.concatenate([dst_bytes_0, dst_bytes_1, dst_bytes_2, dst_bytes_3]),
        'flag': np.concatenate([flag_0, flag_1, flag_2, flag_3]),
        'wrong_fragment': np.concatenate([wrong_frag_0, wrong_frag_1, wrong_frag_2, wrong_frag_3]),
        'hot': np.concatenate([hot_0, hot_1, hot_2, hot_3]),
        'failed_logins': np.concatenate([failed_logins_0, failed_logins_1, failed_logins_2, failed_logins_3]),
        'count': np.concatenate([count_0, count_1, count_2, count_3]),
        'srv_count': np.concatenate([srv_count_0, srv_count_1, srv_count_2, srv_count_3]),
        'same_srv_rate': np.concatenate([same_srv_rate_0, same_srv_rate_1, same_srv_rate_2, same_srv_rate_3]),
        'diff_srv_rate': np.concatenate([diff_srv_rate_0, diff_srv_rate_1, diff_srv_rate_2, diff_srv_rate_3]),
        'dst_host_srv_count': np.concatenate([dst_host_srv_count_0, dst_host_srv_count_1, dst_host_srv_count_2, dst_host_srv_count_3]),
        'dst_host_same_srv_rate': np.concatenate([dst_host_same_srv_rate_0, dst_host_same_srv_rate_1, dst_host_same_srv_rate_2, dst_host_same_srv_rate_3]),
        'label': np.concatenate([label_0, label_1, label_2, label_3])
    }
    
    df = pd.DataFrame(data)
    
    # Shuffle dataframe
    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    
    # Round float columns for realistic formatting
    float_cols = ['duration', 'src_bytes', 'dst_bytes', 'same_srv_rate', 'diff_srv_rate', 'dst_host_same_srv_rate']
    df[float_cols] = df[float_cols].round(4)
    
    return df

if __name__ == '__main__':
    os.makedirs('data', exist_ok=True)
    os.makedirs('static/data', exist_ok=True)
    
    print("Generating training dataset (8,000 records)...")
    df_full = generate_network_dataset(num_samples=8000)
    df_full.to_csv('data/network_traffic.csv', index=False)
    print("Saved data/network_traffic.csv")
    
    print("Generating sample evaluation dataset (500 records)...")
    df_sample = generate_network_dataset(num_samples=500, seed=99)
    # Exclude label from sample test batch so user can upload and test prediction
    df_sample_unlabeled = df_sample.drop(columns=['label'])
    df_sample_unlabeled.to_csv('static/data/sample_traffic.csv', index=False)
    print("Saved static/data/sample_traffic.csv")
