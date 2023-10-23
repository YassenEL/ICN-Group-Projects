from scapy.all import *
import threading
import ipaddress
import networkx as nx
import matplotlib.pyplot as plt

# Define the destination IP range you want to scan
start_ip = "138.238.254.99"
end_ip = "138.238.254.255"

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
            if ip != reply.src:  # Check for self-loop
                G.add_edge(ip, reply.src, ttl=ttl)
            print(f"Done! {ip} -> {reply.src} (TTL={ttl})")
            hops = 0
            break
        else:
            # We're in the middle somewhere
            G.add_node(ip, ttl=ttl)
            if ip != reply.src:  # Check for self-loop
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
    pos = nx.spring_layout(G, k=0.2)  # Adjust the 'k' value to control node separation
    nx.draw(G, pos, with_labels=False)  # Turn off automatic labeling

    # Customize node labels to have red text font and a smaller font size
    node_labels = {node: node for node in G.nodes()}
    nx.draw_networkx_labels(G, pos, labels=node_labels, font_color='red', font_size=8)  # You can adjust the font size as needed

    labels = nx.get_edge_attributes(G, 'ttl')
    nx.draw_networkx_edge_labels(G, pos, edge_labels=labels)
    plt.show()

if __name__ == "__main__":
    main()
