import matplotlib.pyplot as plt

def visualize_traffic():
    # Sample data for visualization (replace with real packet data)
    protocols = ['HTTP', 'DNS', 'TCP', 'UDP']
    counts = [50, 30, 70, 20]
    
    plt.bar(protocols, counts, color='blue')
    plt.title("Network Traffic by Protocol")
    plt.xlabel("Protocol")
    plt.ylabel("Packet Count")
    plt.show()
