import networkx as nx
import random
import matplotlib.pyplot as plt
import os
import copy
import pickle
from number_util import set_node_attribute,commen_change,host_work_off,host_error_off,host_work_on,host_error_on

def generate_fat_tree(k,defense_type):
    G = nx.Graph()
    num_core_switches = (k // 2) ** 2#Number of core switches
    num_agg_switches = k * (k // 2)#Number of aggregation switches
    num_edge_switches = k * (k // 2)#Number of edge switches
    num_servers = num_edge_switches * (k // 2)#Number of servers
    num_nodes = num_core_switches + num_agg_switches + num_edge_switches + num_servers#Total number of nodes

    # Add core switches
    for i in range(num_core_switches):
        G.add_node('c{}'.format(i), type='switch')

    # Add aggregation switches
    # for i in range(num_core_switches, num_core_switches + num_agg_switches):
    #     G.add_node('a{}'.format(i - num_core_switches), type='switch')
    for i in range(num_agg_switches):
        G.add_node(f'a{i}', type='switch')

    # Add edge switches (e0, e1, ..., e_{num_edge-1})
    for i in range(num_edge_switches):
        G.add_node(f'e{i}', type='switch')

    # Add servers (s0, s1, ..., s_{num_servers-1})
    for i in range(num_servers):
        G.add_node(f's{i}', type='server')
    
    # Connect core switches to aggregation switches
    for core_id in range(num_core_switches):
        pod_group = core_id // (k // 2)  # Each core switch corresponds to a Pod group
        for agg_id in range(pod_group * (k//2), (pod_group + 1) * (k//2)):
            G.add_edge(f'c{core_id}', f'a{agg_id}')
    # for i in range(num_core_switches):
    #     for j in range(num_agg_switches):
    #         if j // (k // 2) == i // (k // 2):
    #             G.add_edge('c{}'.format(i), 'a{}'.format(j))

    # Connect aggregation switches to edge switches
    for agg_id in range(num_agg_switches):
        pod = agg_id // (k//2)  # Each aggregation switch belongs to a Pod
        edge_start = pod * (k//2)
        for edge_id in range(edge_start, edge_start + (k//2)):
            G.add_edge(f'a{agg_id}', f'e{edge_id}')
    # for i in range(num_agg_switches):
    #     for j in range(num_edge_switches):
    #         if j // (k // 2) == i % (k // 2):
    #             G.add_edge('a{}'.format(i - num_core_switches), 'e{}'.format(j))

    # Connect edge switches to servers
    for edge_id in range(num_edge_switches):
        server_start = edge_id * (k//2)
        for server_offset in range(k//2):
            server_id = server_start + server_offset
            G.add_edge(f'e{edge_id}', f's{server_id}')
    # for i in range(num_edge_switches):
    #     for j in range(k // 2):
    #         G.add_edge('e{}'.format(i - num_core_switches - num_agg_switches), 's{}'.format((i - num_core_switches - num_agg_switches) * (k // 2) + j))
    all_switches = {n for n in G.nodes() if G.nodes[n]['type'] == 'switch'}
    all_servers = {n for n in G.nodes() if G.nodes[n]['type'] == 'server'}
    sorted_nodes = sorted(G.nodes())
    node_mapping = {node: idx  for idx, node in enumerate(sorted_nodes)}
    G2 = nx.Graph()
    G2.add_nodes_from(node_mapping.values())
    all_nodes = set(G2.nodes())
    all_switches = set([node_mapping[node] for node in all_switches])
    all_servers = all_nodes - all_switches
    Host_work = random.sample(list(all_servers),int(0.3*len(all_servers)))
    for u, v in G.edges():
        G2.add_edge(node_mapping[u], node_mapping[v])
    # Set node attributes
    G_number = set_node_attribute(G2, defense_type)
    # for node in G.nodes():
    #     if node.startswith('s'):
    #         G.nodes[node]['type'] = 'server'
    #     else:
    #         G.nodes[node]['type'] = 'switch'
    return G_number#生成了网络图

def Dy_generate_fat_tree(k,defense_type,T):
    Dy_G = []
    t_errors = []
    G = nx.Graph()
    num_core_switches = (k // 2) ** 2#Number of core switches
    num_agg_switches = k * (k // 2)#Number of aggregation switches
    num_edge_switches = k * (k // 2)#Number of edge switches
    num_servers = num_edge_switches * (k // 2)#Number of servers
    num_nodes = num_core_switches + num_agg_switches + num_edge_switches + num_servers#Total number of nodes

    # Add core switches
    for i in range(num_core_switches):
        G.add_node('c{}'.format(i), type='switch')

    # Add aggregation switches
    # for i in range(num_core_switches, num_core_switches + num_agg_switches):
    #     G.add_node('a{}'.format(i - num_core_switches), type='switch')
    for i in range(num_agg_switches):
        G.add_node(f'a{i}', type='switch')

    # Add edge switches (e0, e1, ..., e_{num_edge-1})
    for i in range(num_edge_switches):
        G.add_node(f'e{i}', type='switch')

    # Add servers (s0, s1, ..., s_{num_servers-1})
    for i in range(num_servers):
        G.add_node(f's{i}', type='server')
    
    # Connect core switches to aggregation switches
    for core_id in range(num_core_switches):
        pod_group = core_id // (k // 2)  # Each core switch corresponds to a Pod group
        for agg_id in range(pod_group * (k//2), (pod_group + 1) * (k//2)):
            G.add_edge(f'c{core_id}', f'a{agg_id}')
    
    # Connect aggregation switches to edge switches
    for agg_id in range(num_agg_switches):
        pod = agg_id // (k//2)  # Each aggregation switch belongs to a Pod
        edge_start = pod * (k//2)
        for edge_id in range(edge_start, edge_start + (k//2)):
            G.add_edge(f'a{agg_id}', f'e{edge_id}')
    

    # Connect edge switches to servers
    for edge_id in range(num_edge_switches):
        server_start = edge_id * (k//2)
        for server_offset in range(k//2):
            server_id = server_start + server_offset
            G.add_edge(f'e{edge_id}', f's{server_id}')
    
    all_switches = {n for n in G.nodes() if G.nodes[n]['type'] == 'switch'}
    all_servers = {n for n in G.nodes() if G.nodes[n]['type'] == 'server'}
    sorted_nodes = sorted(G.nodes())
    node_mapping = {node: idx  for idx, node in enumerate(sorted_nodes)}
    G2 = nx.Graph()
    G2.add_nodes_from(node_mapping.values())
    all_nodes = set(G2.nodes())
    all_switches = set([node_mapping[node] for node in all_switches])
    all_servers = all_nodes - all_switches
    Host_work = random.sample(list(all_servers),int(0.3*len(all_servers)))
    for u, v in G.edges():
        G2.add_edge(node_mapping[u], node_mapping[v])
    # Set node attributes
    G_number = set_node_attribute(G2, defense_type)
    Dy_G.append(G_number)#Save the network at time 0.
    # G_0 = G_number.copy()
    G_0 = copy.deepcopy(G_number)
    for t in range(1, T):
        # G_ = Dy_G[t-1].copy()
        G_ = copy.deepcopy(Dy_G[t-1])
        # Regular changes, randomly select 0.02 of the nodes to enhance or weaken defense capabilities
        all_nodes_ = set(G_.nodes())
        all_servers_ = all_nodes_ - all_switches
        G_0,G_ = commen_change(G_0,G_, all_nodes_, all_switches, all_servers_)

        # Host working status change
        if t % 12 == 0 and (t // 12) % 2 == 1:# Off-duty time, change every 12 time points
            G_ = host_work_off(G_, Host_work)
        elif t % 12 == 0 and (t // 12) % 2 == 0:# On-duty time, change every 12 time points
            G_ = host_work_on(G_0, G_, Host_work)

        # Host failure status change
        real_error = []
        for h in Host_work:
            # If the generated random number is less than 0.001, it indicates that this host has failed
            if random.random() < 0.001:
                G_ = host_error_off(G_, [h])
                real_error.append(h)
        if len(real_error) != 0:# Failures occurred at this moment
            t_errors.append([t,real_error])#    
        for m in t_errors:
            if m[0] + 72 == t:
                G_ = host_error_on(G_0, G_, m[1])
        Dy_G.append(G_)
    return Dy_G
    

# Draw network
# pos = nx.spring_layout(G)
# node_colors = {'switch': 'blue', 'server': 'red'}
# #node_shapes = {'switch': 'o', 'server': 's'}
# node_labels = {node: node.split('s')[1] if node.startswith('s') else '' for node in G.nodes()}
# node_types = nx.get_node_attributes(G, 'type')
# node_color = [node_colors[node_types[node]] for node in G.nodes()]
# #node_shape = [node_shapes[node_types[node]] for node in G.nodes()]
# nx.draw_networkx(G, pos=pos, node_color=node_color, labels=node_labels)

# # Save figure
# plt.savefig('fat_tree_topology.png')



if __name__ == '__main__':
    # Set the type of numerical simulation network to generate, defense_type = 1,2,3
    defense_type = 1
    # defense_type = 2
    # defense_type = 3

    # Generate and save static/dynamic networks
    # static = 0
    static = 1

    # Set the scale of nodes to 10
    # K = 4
    # Set the scale of nodes to 100
    # K = 6
    # Set the scale of nodes to 1000
    K = 14
    # Generate the network
    for c in range(1):
        if static == 1:#static network
            graph = generate_fat_tree(K,defense_type)
            z = (f"./number_net/fattree/static/{len(graph.nodes())}_defensetype_{defense_type}_fattree{c}.gpickle")
            # z = (f"./number_net/test/static/{len(graph.nodes())}_defensetype_{defense_type}_fattree{c}.gpickle")
            os.makedirs(os.path.dirname(z), exist_ok=True)
            with open(z, 'wb') as f:
                pickle.dump(graph, f, pickle.HIGHEST_PROTOCOL)
        else:#dynamic network
            t_end = 100
            Gy_graphs = Dy_generate_fat_tree(K,defense_type, T = t_end)
            for i in range(len(Gy_graphs)):
                z = (f"./number_net/fattree/dynamic/{len(Gy_graphs[0].nodes())}_defensetype_{defense_type}_fattree{c}/t{i}.gpickle")
                # z = (f"./number_net/test/dynamic/{len(Gy_graphs[0].nodes())}_defensetype_{defense_type}_fattree{c}/t{i}.gpickle")
                os.makedirs(os.path.dirname(z), exist_ok=True)
                with open(z, 'wb') as f:
                    pickle.dump(Gy_graphs[i], f, pickle.HIGHEST_PROTOCOL)

