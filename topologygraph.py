import networkx as nx
import os
import re

# Create an empty graph
G = nx.Graph()

# Create a set to keep track of encountered nodes
encountered_nodes = set()

# Directory where this script is located
script_directory = os.path.dirname(os.path.realpath(__file__ if '__file__' in locals() else __file__))

# Regular expression pattern to match IP addresses
ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'

# Iterate through the files in the same directory as this script
for filename in os.listdir(script_directory):
    if filename.endswith('.txt'):
        file_path = os.path.join(script_directory, filename)

        # Read data from each text file and extract IP addresses
        with open(file_path, 'r') as file:
            for line in file:
                ip_addresses = re.findall(ip_pattern, line)
                if len(ip_addresses) == 2:
                    source_ip, destination_ip = ip_addresses

                    # Add nodes only if they haven't been encountered before
                    if source_ip not in encountered_nodes:
                        G.add_node(source_ip)
                        encountered_nodes.add(source_ip)
                    if destination_ip not in encountered_nodes:
                        G.add_node(destination_ip)
                        encountered_nodes.add(destination_ip)

                    G.add_edge(source_ip, destination_ip)

# Set the position of nodes to create even more space between them
pos = nx.spring_layout(G, scale=5000)

# Visualize the combined graph with customized colors
import matplotlib.pyplot as plt

# Define node and edge colors
node_color = 'lightblue'  # Change this to your desired color
edge_color = 'gray'       # Change this to your desired color

# Draw the graph with custom colors
nx.draw(G, pos, with_labels=True, node_size=100, font_size=8, node_color=node_color, edge_color=edge_color)

plt.show()
