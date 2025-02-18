import networkx as nx
import matplotlib.pyplot as plt

# Define the number of levels in the BCube topology
levels = 6

# Define the number of nodes per level
nodes_per_level = 3

# Define the total number of nodes in the BCube topology
num_nodes = nodes_per_level ** (levels + 1)

# Create a new graph object
G = nx.Graph()

# Add all the nodes to the graph
for i in range(num_nodes):
    if i < nodes_per_level:
        G.add_node(i, type='server')
    else:
        G.add_node(i, type='switch')

# Add all the edges to the graph
for l in range(levels):
    for i in range(nodes_per_level ** l):
        for j in range(nodes_per_level):
            for k in range(nodes_per_level ** (l + 1)):
                src = i + j * nodes_per_level ** l
                dst = nodes_per_level * i + j + k * nodes_per_level ** (l + 1)
                G.add_edge(src, dst)

# Draw the graph
pos = nx.spring_layout(G)
node_colors = [{'server': 'r', 'switch': 'b'}.get(G.nodes[n].get('type'), 'gray') for n in G.nodes()]
nx.draw(G, pos, node_color=node_colors, with_labels=True)

# Save the image
plt.savefig('bcube_topology.png')

# Show the graph
plt.show()