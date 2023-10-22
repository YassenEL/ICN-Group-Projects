from scapy.all import *
import threading
import ipaddress

# Define the destination IP range you want to scan
start_ip = "1.2.3.1"
end_ip = "1.2.4.2"

# Define the maximum number of hops
max_hops = 28
hops = 0
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
            print(f"Done! {ip} -> {reply.src} (TTL={ttl})")
            break
        else:
            # We're in the middle somewhere
            print(f"We are at {hops} hops: {ip} -> {reply.src} (TTL={ttl})")

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

if __name__ == "__main__":
    main()
