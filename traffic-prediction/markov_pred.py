import matplotlib.pyplot as plt
import numpy as np

from scapy.all import PcapReader, TCP, rdpcap
from sklearn.model_selection import train_test_split
from collections import defaultdict

states = ['Low', 'Medium', 'High']

def categorize_traffic(packets_per_second, low_threshold, high_threshold):
    if packets_per_second < low_threshold:
        return 'Low'
    elif packets_per_second < high_threshold:
        return 'Medium'
    else:
        return 'High'

def read_and_categorize_traffic(pcap_file, chunk_size, bin_size, low_threshold, high_threshold):
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
        print("No TCP packets found in the specified chunk.")
        return [], []
    start_time = times[0]
    relative_times = [t - start_time for t in times]

    max_time = relative_times[-1]
    bins = np.arange(0, max_time + bin_size, bin_size)

    counts, bin_edges = np.histogram(relative_times, bins=bins)
    packets_per_second = counts / bin_size

    categories = [categorize_traffic(p, low_threshold, high_threshold) for p in packets_per_second]

    return categories, bin_edges[:-1]  

def construct_transition_matrix(categories):
    transitions = defaultdict(int)
    for (current_state, next_state) in zip(categories[:-1], categories[1:]):
        transitions[(current_state, next_state)] += 1

    transition_matrix = np.zeros((len(states), len(states)))

    for i, state_from in enumerate(states):
        total_transitions = sum(transitions[(state_from, state_to)] for state_to in states)
        if total_transitions > 0:
            for j, state_to in enumerate(states):
                transition_matrix[i, j] = transitions[(state_from, state_to)] / total_transitions

    return transition_matrix

def predict_next_state(current_state, transition_matrix):
    
    state_index = states.index(current_state)
    next_state_index = np.argmax(transition_matrix[state_index])
    return states[next_state_index]

def validate_model(test_categories, transition_matrix):
    correct_predictions = 0
    for i in range(len(test_categories) - 1):
        if predict_next_state(test_categories[i], transition_matrix) == test_categories[i + 1]:
            correct_predictions += 1
    return correct_predictions / (len(test_categories) - 1)

def plot_traffic_categories(bin_edges, categories):
    plt.figure(figsize=(10, 6))
    for i, category in enumerate(categories):
        color = {'Low': 'green', 'Medium': 'yellow', 'High': 'red'}[category]
        plt.bar(bin_edges[i], 1, width=bin_size, color=color)

    plt.xlabel('Time (seconds)')
    plt.ylabel('Traffic Category')
    plt.title('TCP Traffic Categorization')
    plt.grid(True)
    plt.show()

def main():
    pcap_file = './capture2/ethcap_00001_20240418173623.pcap' 

    chunk_size = 1e6
    bin_size = 1 
    low_threshold = 100  
    high_threshold = 400  

    categories, bin_edges = read_and_categorize_traffic(pcap_file, chunk_size, bin_size, low_threshold, high_threshold)
    plot_traffic_categories(bin_edges, categories)

    train_categories, test_categories = train_test_split(categories, test_size=0.2, random_state=42, shuffle=False)

    transition_matrix = construct_transition_matrix(train_categories)

    accuracy = validate_model(test_categories, transition_matrix)
    print(f'Accuracy of the Markov Chain model: {accuracy * 100:.2f}%')

if __name__ == '__main__':
    main()

