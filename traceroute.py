from scapy.all import *
import threading
import ipaddress
import networkx as nx
import matplotlib.pyplot as plt

# Define the destination IP range you want to scan
start_ip = "1.2.3.1"
end_ip = "1.2.4.2"

# Define the maximum number of hops
max_hops = 28
hops = 0

# Create a NetworkX graph to represent the network
G = nx.Graph()

def traceroute_ip(ip):
    global hops
    for ttl in range(1, max_hops + 1):
        pkt = IP(dst=ip, ttl=ttl) / ICMP()
        reply = sr1(pkt, verbose=0, timeout=5)
        hops += 1
        if reply is None:
            # No reply
            break
        elif reply.type == 0:
            # We've reached our destination
            G.add_node(ip, ttl=ttl)
            G.add_edge(ip, reply.src, ttl=ttl)
            print(f"Done! {ip} -> {reply.src} (TTL={ttl})")
            break
        else:
            # We're in the middle somewhere
            G.add_node(ip, ttl=ttl)
            G.add_edge(ip, reply.src, ttl=ttl)
            print(f"We are at {hops} hops away: {ip} -> {reply.src} (TTL={ttl})")

def main():
    # Generate a list of IP addresses to scan within the specified range
    start_ip_int = int(ipaddress.IPv4Address(start_ip))
    end_ip_int = int(ipaddress.IPv4Address(end_ip))
    
    ip_range = [str(ipaddress.IPv4Address(ip)) for ip in range(start_ip_int, end_ip_int + 1)]

    # Create a thread for each IP address in the range
    threads = []
    for ip in ip_range:
        thread = threading.Thread(target=traceroute_ip, args=(ip,))
        threads.append(thread)

    # Start all threads
    for thread in threads:
        thread.start()

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

    # Visualize the network graph
    pos = nx.spring_layout(G)  # You can choose different layout algorithms
    nx.draw(G, pos, with_labels=True)
    labels = nx.get_edge_attributes(G, 'ttl')
    nx.draw_networkx_edge_labels(G, pos, edge_labels=labels)
    plt.show()

if __name__ == "__main__":
    main()
