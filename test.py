import numpy as np
import sys
import pickle
import time
import matplotlib.pyplot as plt
import csv

blocked_packets = []

def icmp_test(attributes):
    model = pickle.load(open("./saved_model/icmp_data.sav", 'rb'))
    result = model.predict([attributes])
    if result[0] == 1:
        print("ICMP Attack Detected")    
        blocked_packets.append(attributes)

def udp_test(attributes):
    model = pickle.load(open("./saved_model/udp_data.sav", 'rb'))
    result = model.predict([attributes])
    if result[0] == 1:
        print("UDP Attack Detected")    
        blocked_packets.append(attributes)

def tcp_syn_test(attributes):
    model = pickle.load(open("./saved_model/tcp_syn_data.sav", 'rb'))
    result = model.predict([attributes])
    if result[0] == 1:
        print("TCP_SYN Attack Detected")    
        blocked_packets.append(attributes)
def preprocess_data(row):
    data = []
    # Remove '\n' and split the values by space
    values = row.strip().split(',')
    for each in values:
        data.append(float(each))
    # # Convert the values to floats
    # attributes = [float(val) for val in values]
    return data
   # return attributes
if __name__ == "__main__":
    icmp_times = []
    udp_times = []
    tcp_syn_times = []
    start_time = time.time()

    # Read the CSV file and perform tests
    f = open("test.csv", "r")
    for row in f:
        x = row.split(",")
        if len(x) == 7:
            start_time = time.time()
            if preprocess_data(row) in blocked_packets:
                print("This packet is blocked!.")
            icmp_test(preprocess_data(row))
            end_time = time.time()
            icmp_times.append(end_time - start_time)
        elif len(x) == 5:
            start_time = time.time()
            if preprocess_data(row) in blocked_packets:
                print("This packet is blocked!.")
            udp_test(preprocess_data(row))
            end_time = time.time()
            udp_times.append(end_time - start_time)
        if len(x) == 5:
            start_time = time.time()
            if preprocess_data(row) in blocked_packets:
                print("This packet is blocked!.")
            tcp_syn_test(preprocess_data(row))
            end_time = time.time()
            tcp_syn_times.append(end_time - start_time)
        # Calculate recovery times
    recovery_times = []
    for i in range(len(blocked_packets)):
        start_time = time.time()
        # Perform recovery actions here
        time.sleep(0.5)
        end_time = time.time()
        recovery_times.append(end_time - start_time)
    print("Recovery Time: ",recovery_times)
    # Plotting the time comparison
    methods = ["ICMP", "UDP", "TCP_SYN", "Recovery"]
    mean_times = [np.mean(icmp_times), np.mean(udp_times), np.mean(tcp_syn_times), np.mean(recovery_times)]
    plt.plot(methods, mean_times)
    plt.xlabel('Methods')
    plt.ylabel('Mean Time (seconds)')
    plt.title('Time Comparison for Packet Detection Methods and Recovery')
    plt.show()
    


