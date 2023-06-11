from scapy.all import rdpcap, IP
import pandas as pd
import matplotlib.pyplot as plt

def preprocess_pcap(file_path, packet_limit):
    packets = rdpcap(file_path)
    packets = packets[:packet_limit]

    data = []
    for packet in packets:
        if IP in packet:
            features = {
                'timestamp': packet.time,
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'protocol': packet[IP].proto,
                'length': len(packet)
            }
            data.append(features)
    
    df = pd.DataFrame(data)
    
    return df

def plot_data(df):
    plt.figure(figsize=(10, 6))
    plt.plot(df['timestamp'], df['length'], marker='o', linestyle='-', color='b')
    plt.xlabel('Timestamp')
    plt.ylabel('Packet Length')
    plt.title('Packet Length over Time')
    plt.grid(True)
    plt.show()

def save_to_csv(df, output_path):
    df.to_csv(output_path, index=False)

file_path = './capture2/ethcap_00001_20240418173623.pcap'
packet_limit = 1e3
output_csv_path = 'packet_data.csv'

df = preprocess_pcap(file_path, packet_limit)

plot_data(df)

save_to_csv(df, output_csv_path)

print(df)
