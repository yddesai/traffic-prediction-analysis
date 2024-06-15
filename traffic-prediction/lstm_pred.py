from scapy.all import PcapReader, TCP
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

def read_pcap_file(pcap_file, chunk_size):
    times = []
    packet_count = 0

    with PcapReader(pcap_file) as pcap_reader:
        for packet in pcap_reader:
            if TCP in packet:
                times.append(packet.time)
                packet_count += 1
                if packet_count >= chunk_size:
                    break

    if not times:
        raise ValueError("No TCP packets found in the specified chunk.")
    
    return times

def classify_bursts(packet_timestamps, threshold):
    bursts = []
    current_burst = []

    for i in range(1, len(packet_timestamps)):
        inter_arrival_time = packet_timestamps[i] - packet_timestamps[i-1]
        
        if inter_arrival_time <= threshold:
            current_burst.append(packet_timestamps[i])
        else:
            if len(current_burst) > 0:
                bursts.append(current_burst)
                current_burst = []
            current_burst.append(packet_timestamps[i-1])

    if len(current_burst) > 0:
        bursts.append(current_burst)

    return bursts

def extract_burst_features(packet_times, burst_threshold=0.001):
    bursts = classify_bursts(packet_times, burst_threshold)
    burst_sizes = [len(burst) for burst in bursts]
    
    inter_burst_intervals = [bursts[i+1][0] - bursts[i][-1] for i in range(len(bursts) - 1)]
    inter_burst_intervals.append(0)  
    
    return burst_sizes, inter_burst_intervals

def compute_packets_per_second(packet_times, bin_size=1):
    start_time = packet_times[0]
    end_time = packet_times[-1]
    bins = np.arange(start_time, end_time, bin_size)
    packet_counts, _ = np.histogram(packet_times, bins=bins)
    return packet_counts

def create_dataset(data, time_step=1):
    X, Y = [], []
    for i in range(len(data) - time_step):
        X.append(data[i:(i + time_step)])
        Y.append(data[i + time_step, -1])
    return np.array(X), np.array(Y)

def main():
    pcap_file = './capture2/ethcap_00001_20240418173623.pcap' 
    chunk_size = 1e6 
    bin_size = 0.5  
    time_step = 10  
    burst_threshold = 0.001
    packet_times = read_pcap_file(pcap_file, chunk_size)
    burst_sizes, inter_burst_intervals = extract_burst_features(packet_times, burst_threshold)
    packet_counts = compute_packets_per_second(packet_times, bin_size)

    min_length = min(len(burst_sizes), len(inter_burst_intervals), len(packet_counts))
    burst_sizes = burst_sizes[:min_length]
    inter_burst_intervals = inter_burst_intervals[:min_length]
    packet_counts = packet_counts[:min_length]

    df = pd.DataFrame({
        'burst_size': burst_sizes,
        'inter_burst_interval': inter_burst_intervals,
        'packet_count': packet_counts
    })

    target = df['packet_count'].values.reshape(-1, 1)
    target_scaler = MinMaxScaler(feature_range=(0, 1))
    target_scaled = target_scaler.fit_transform(target)

    df = df.drop(columns=['packet_count'])
    scaler = MinMaxScaler(feature_range=(0, 1))
    df_scaled = scaler.fit_transform(df)

    df_scaled = np.hstack((df_scaled, target_scaled))

    X, Y = create_dataset(df_scaled, time_step)

    X = X.reshape((X.shape[0], X.shape[1], X.shape[2]))

    train_size = int(len(X) * 0.70)
    test_size = len(X) - train_size
    train_X, test_X = X[0:train_size], X[train_size:len(X)]
    train_Y, test_Y = Y[0:train_size], Y[train_size:len(Y)]

    # LSTM Model
    model = Sequential()
    model.add(LSTM(50, return_sequences=True, input_shape=(time_step, X.shape[2])))
    model.add(LSTM(50, return_sequences=False))
    model.add(Dense(1))
    model.compile(optimizer='adam', loss='mean_squared_error')

    model.fit(train_X, train_Y, epochs=20, batch_size=32, verbose=1)

    # Predictions
    train_predict = model.predict(train_X)
    test_predict = model.predict(test_X)

    train_predict = target_scaler.inverse_transform(train_predict)
    train_Y = target_scaler.inverse_transform(train_Y.reshape(-1, 1))
    test_predict = target_scaler.inverse_transform(test_predict)
    test_Y = target_scaler.inverse_transform(test_Y.reshape(-1, 1))

    train_mae = mean_absolute_error(train_Y, train_predict)
    train_mse = mean_squared_error(train_Y, train_predict)
    train_rmse = np.sqrt(train_mse)
    train_r2 = r2_score(train_Y, train_predict)

    test_mae = mean_absolute_error(test_Y, test_predict)
    test_mse = mean_squared_error(test_Y, test_predict)
    test_rmse = np.sqrt(test_mse)
    test_r2 = r2_score(test_Y, test_predict)

    print(f'Train MAE: {train_mae:.4f}')
    print(f'Train MSE: {train_mse:.4f}')
    print(f'Train RMSE: {train_rmse:.4f}')
    print(f'Train R²: {train_r2:.4f}')
    print(f'Test MAE: {test_mae:.4f}')
    print(f'Test MSE: {test_mse:.4f}')
    print(f'Test RMSE: {test_rmse:.4f}')
    print(f'Test R²: {test_r2:.4f}')

    plt.figure(figsize=(12, 6))
    plt.plot(test_Y, label='Actual Data')
    plt.plot(test_predict, label='Predicted Data')
    plt.xlabel('Time')
    plt.ylabel('Packet Count')
    plt.title('Actual vs Predicted Packet Count')
    plt.legend()
    plt.show()

if __name__ == '__main__':
    main()