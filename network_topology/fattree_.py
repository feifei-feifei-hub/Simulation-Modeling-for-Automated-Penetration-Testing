import networkx as nx
import random
import matplotlib.pyplot as plt

def generate_fat_tree(k):
    G = nx.Graph()
    num_core_switches = (k // 2) ** 2
    num_agg_switches = k * (k // 2)
    num_edge_switches = k * (k // 2)
    num_servers = num_edge_switches * (k // 2)
    num_nodes = num_core_switches + num_agg_switches + num_edge_switches + num_servers

    # Add core switches
    for i in range(num_core_switches):
        G.add_node('c{}'.format(i), type='switch')

    # Add aggregation switches
    for i in range(num_core_switches, num_core_switches + num_agg_switches):
        G.add_node('a{}'.format(i - num_core_switches), type='switch')

    # Add edge switches and servers
    for i in range(num_core_switches + num_agg_switches, num_nodes):
        if i < num_core_switches + num_agg_switches + num_edge_switches:
            G.add_node('e{}'.format(i - num_core_switches - num_agg_switches), type='switch')
        else:
            G.add_node('s{}'.format(i - num_core_switches - num_agg_switches - num_edge_switches), type='server')

    # Connect core switches to aggregation switches
    for i in range(num_core_switches):
        for j in range(num_agg_switches):
            if j // (k // 2) == i // (k // 2):
                G.add_edge('c{}'.format(i), 'a{}'.format(j))

    # Connect aggregation switches to edge switches
    for i in range(num_agg_switches):
        for j in range(num_edge_switches):
            if j // (k // 2) == i % (k // 2):
                G.add_edge('a{}'.format(i - num_core_switches), 'e{}'.format(j))

    # Connect edge switches to servers
    for i in range(num_edge_switches):
        for j in range(k // 2):
            G.add_edge('e{}'.format(i - num_core_switches - num_agg_switches), 's{}'.format((i - num_core_switches - num_agg_switches) * (k // 2) + j))

    return G

# Generate FatTree topology with k=10 and 1000 nodes
G = generate_fat_tree(3)

# Set node attributes
for node in G.nodes():
    if node.startswith('s'):
        G.nodes[node]['type'] = 'server'
    else:
        G.nodes[node]['type'] = 'switch'

# Draw network
pos = nx.spring_layout(G)
node_colors = {'switch': 'blue', 'server': 'red'}
#node_shapes = {'switch': 'o', 'server': 's'}
node_labels = {node: node.split('s')[1] if node.startswith('s') else '' for node in G.nodes()}
node_types = nx.get_node_attributes(G, 'type')
node_color = [node_colors[node_types[node]] for node in G.nodes()]
#node_shape = [node_shapes[node_types[node]] for node in G.nodes()]
nx.draw_networkx(G, pos=pos, node_color=node_color, labels=node_labels)

# Save figure
plt.savefig('fat_tree_topology.png')