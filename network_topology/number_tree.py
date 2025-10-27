import matplotlib.pyplot as plt
import networkx as nx
import random
import math
import json
import sys,os
import copy
import numpy as np
from networkx.readwrite import json_graph
import pickle
from number_util import set_node_attribute,commen_change,host_work_off,host_error_off,host_work_on,host_error_on

sys.path.append(os.getcwd())
# from data_cve.CVE_detail import Read_data   
#core_switch_num,aggregation_switch_num,edge_switch_num,host_num
#Number of aggregation switches connected to each core switch. core_aggregation={0:6},Number of access switches connected to each aggregation switch.aggregation_edge={0:2,1:2,2:2,3:2,4:2,5:2}
def tree(core_switch_num,core_aggregation, aggregation_switch_num,aggregation_edge,edge_switch_num,host_num,pro,defense_type):
    lan_ID = 0
    start = 0
    end = 0
    each_lan_node_id = []
    # cve = Read_data()#  
    G = nx.Graph()
    G_core = nx.Graph()
    G_aggregation = nx.Graph()
    G_edge = nx.Graph()
    count = 0
    host_per_edge = int(host_num/(int(edge_switch_num)))
    for i in range(core_switch_num):
        G.add_node(i)  # Add core switch
        G_core.add_node(i)
        count += 1
        for j in range(core_aggregation[i]):
            j_count = count
            G_aggregation.add_node(j_count)
            G.add_node(j_count)  # Add aggregation switch
            G.add_edge(i,j_count)
            count += 1
            for k in range(aggregation_edge[j]):
                k_count = count
                G_edge.add_node(k_count)
                G.add_node(k_count)
                G.add_edge(j_count,k_count)
                count += 1
    
    for i in G_edge.nodes():  # For each access switch
        # Create a fully connected subgraph within the subnet
        all_node_now = len(G.nodes())
        G_H = nx.Graph()
        G_H.add_node(i)
        count += 1
        for j in range(host_per_edge):
            G_H.add_node(all_node_now)
            all_node_now += 1
        count += 1
        for j in G_H.nodes():
            for s in G_H.nodes():
                if j != s:
                    G_H.add_edge(j,s)
        
        G = nx.compose(G,G_H)
        # nx.draw(G, with_labels=True, alpha=0.8, node_size=500)
        # plt.savefig("/root/feifei/8_network_generator/data_cve/graph.png")  
    G_number = set_node_attribute(G, defense_type)

    return G_number

def Dy_tree(core_switch_num,core_aggregation, aggregation_switch_num,aggregation_edge,edge_switch_num,host_num,pro,defense_type, T = 1000):
    Dy_G = []
    t_errors = []
    lan_ID = 0
    start = 0
    end = 0
    each_lan_node_id = []
    # cve = Read_data()#  
    G = nx.Graph()
    G_core = nx.Graph()
    G_aggregation = nx.Graph()
    G_edge = nx.Graph()
    count = 0
    host_per_edge = int(host_num/(int(edge_switch_num)))
    for i in range(core_switch_num):
        G.add_node(i)
        G_core.add_node(i)
        count += 1
        for j in range(core_aggregation[i]):
            j_count = count
            G_aggregation.add_node(j_count)
            G.add_node(j_count)
            G.add_edge(i,j_count)
            count += 1
            for k in range(aggregation_edge[j]):
                k_count = count
                G_edge.add_node(k_count)
                G.add_node(k_count)
                G.add_edge(j_count,k_count)
                count += 1
    
    all_switches = set(G.nodes())
    for i in G_edge.nodes():
        all_node_now = len(G.nodes())
        G_H = nx.Graph()
        G_H.add_node(i)
        count += 1
        for j in range(host_per_edge):
            G_H.add_node(all_node_now)
            all_node_now += 1
        count += 1
        for j in G_H.nodes():
            for s in G_H.nodes():
                if j != s:
                    G_H.add_edge(j,s)
        G = nx.compose(G,G_H)

    G_number = set_node_attribute(G, defense_type)
    Dy_G.append(G_number)
    all_nodes = set(G_number.nodes())
    all_servers = all_nodes - all_switches
    Host_work = random.sample(list(all_servers),int(0.3*len(all_servers)))
    # Host_error = random.sample(all_servers,int(0.3*len(all_servers)))
    G_0 = copy.deepcopy(G_number)
    for t in range(1, T):
        G_ = copy.deepcopy(Dy_G[t-1])
        all_nodes_ = set(G_.nodes())
        all_severs_ = all_nodes_ - all_switches
        G_0,G_ = commen_change(G_0,G_, all_nodes_, all_switches, all_severs_)
        
        if t % 12 == 0 and (t // 12) % 2 == 1:
            G_ = host_work_off(G_, Host_work)
        elif t % 12 == 0 and (t // 12) % 2 == 0:
            G_ = host_work_on(G_0, G_, Host_work)
        real_error = []
        for h in Host_work:
            if random.random() < 0.001:
                G_ = host_error_off(G_, [h])
                real_error.append(h)
        if len(real_error) != 0:
            t_errors.append([t,real_error])
        for m in t_errors:
            if m[0] + 72 == t:
                G_ = host_error_on(G_0, G_, m[1])
        Dy_G.append(G_)
    return Dy_G


def save(G, fname):
    json.dump(dict(nodes=[[n, G.node[n]] for n in G.nodes()],
                   edges=[[u, v, G.edge[u][v]] for u,v in G.edges()]),
              open(fname, 'w'), indent=2)
    
def load(fname):
    G = nx.DiGraph()
    d = json.load(open(fname))
    G.add_nodes_from(d['nodes'])
    G.add_edges_from(d['edges'])
    return G


if __name__ == '__main__':
    #node scale of 10
    # core_switch_num =1
    # core_aggregation={0:2}
    # aggregation_switch_num = sum(core_aggregation.values())
    # aggregation_edge={0:2,1:2}
    # edge_switch_num = sum(aggregation_edge.values())
    # host_num = 8

    # #node scale of 100
    # core_switch_num =1
    # core_aggregation={0:3}
    # aggregation_switch_num = sum(core_aggregation.values())
    # aggregation_edge={0:3,1:3,2:3}
    # edge_switch_num = sum(aggregation_edge.values())
    # host_num = 90

    #node scale of 1000
    core_switch_num =1#Number of core switches
    core_aggregation={0:7}#Number of aggregation switches connected to each core switch.
    aggregation_switch_num = sum(core_aggregation.values())#Number of aggregation switches.
    aggregation_edge={0:7,1:3,2:7,3:7,4:6,5:6,6:7}
    edge_switch_num = sum(aggregation_edge.values())
    host_num = 950



    pro = 0.65
    # np.random.seed(2077)
    # Set the type of numerical simulation network to generate. defense_type = 1,2,3
    # defense_type = 1
    defense_type = 2
    # defense_type = 3

    # static = 1
    static = 0
    for c in range(1):
        if static == 1:#static network
            graph = tree(core_switch_num,core_aggregation, aggregation_switch_num,aggregation_edge,edge_switch_num,host_num,pro,defense_type)
            
    # nx.draw(graph, with_labels=True, alpha=0.8, node_size=500)
    # plt.savefig("123.png")
            # z = (f"./number_net/tree/static/{len(graph.nodes())}_defensetype_{defense_type}_tree{c}.gpickle")
            z = (f"./number_net/test/static/{len(graph.nodes())}_defensetype_{defense_type}_tree{c}.gpickle")
            os.makedirs(os.path.dirname(z), exist_ok=True)
            with open(z, 'wb') as f:
                pickle.dump(graph, f, pickle.HIGHEST_PROTOCOL)
        else:#dynamic network
            t_start = 0
            t_end = 1000
            Gy_graphs = Dy_tree(core_switch_num,core_aggregation, aggregation_switch_num,aggregation_edge,edge_switch_num,host_num,pro,defense_type, T = t_end)
            for i in range(len(Gy_graphs)):
                # z = (f"./number_net/tree/dynamic/{len(Gy_graphs[0].nodes())}_defensetype_{defense_type}_tree{c}/t{i}.gpickle")
                z = (f"./number_net/test/dynamic/{len(Gy_graphs[0].nodes())}_defensetype_{defense_type}_tree{c}/t{i}.gpickle")
                os.makedirs(os.path.dirname(z), exist_ok=True)
                with open(z, 'wb') as f:
                    pickle.dump(Gy_graphs[i], f, pickle.HIGHEST_PROTOCOL)


    
