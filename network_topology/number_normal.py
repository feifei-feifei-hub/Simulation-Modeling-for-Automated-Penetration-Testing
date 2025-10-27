
import matplotlib.pyplot as plt
import networkx as nx
import random
import copy
import math
import json
import sys,os
import numpy as np
from networkx.readwrite import json_graph
import pickle
from number_util import set_node_attribute,commen_change,host_work_off,host_error_off,host_work_on,host_error_on

 

def partitioned_layered_garph_generatin(layers,total,layers_percent,Lan_num,switchs_percent,pro,defense_type):
    layers_num = [int(total*i) for i in layers_percent]#Number of hosts per layer
    #print(layers_num)
    graph_list = {}
    each_Lan_node_num = []#Total number of nodes in each LAN
    lan_switchs_num = []#Number of switches in each LAN
    lan_switch_ID= []#ID of each switch
    start = 0
    end = 0
    lan_ID = 0# LAN ID
    each_lan_node_id = []
    for i in range(layers):
        each_Lan = layers_num[i]/Lan_num[i]#A single layer network contains multiple LANs, and the number of nodes within each LAN is the same.
        count = 0
        while count < Lan_num[i]:
            each_Lan_node_num.append(int(each_Lan))#Total number of nodes in each LAN
            lan_switchs_num.append(math.ceil(switchs_percent[i]*each_Lan))#Number of switches in each LAN
            lan_switch_ID_ = set()#ID of switches within the LAN
            flag = True
            start = end
            end = end + int(each_Lan)
            each_lan_node_id_ = [i for i in range(start,end)]
            each_lan_node_id.append(each_lan_node_id_)
            while flag == True:
                lan_switch_ID_.add(random.choice(each_lan_node_id[lan_ID]))
                if len(lan_switch_ID_) == lan_switchs_num[lan_ID]:
                    flag = False
                    lan_ID += 1 
                    lan_switch_ID_ = list(lan_switch_ID_)
                    lan_switch_ID.append(lan_switch_ID_)      
            count += 1
  
    G_lans = {}
    for i in range(len(each_Lan_node_num)):
        G_lans[i] = nx.complete_graph(each_lan_node_id[i]) 
        for j in G_lans[i]:
            G_lans[i].nodes[j]["type"] = "server"
    #Generate connections between switches. Switches in the same layer are not connected; a switch only connects to the switches in the immediately adjacent upper layer.
    G_switchs = nx.Graph()
    count1 = 0
    while count1 < len(lan_switchs_num)-1:
        # for i in lan_switch_ID[count1]:
        #     for j in lan_switch_ID[count1+1]:
        #         G_switchs.add_edge(i,j)
            #随机选择部分上层交换机连接到下层交换机
        for i in lan_switch_ID[count1]:
            num_connections = random.randint(1, len(lan_switch_ID[count1+1]))
            connected_switches = random.sample(lan_switch_ID[count1+1], num_connections)
            for j in connected_switches:
                G_switchs.add_edge(i, j)
        count1 += 1
    switch_cve = []
    for i in G_switchs:
        G_switchs.nodes[i]["type"] = "switch"

    all_graph = []
    for i in G_lans.values():
        all_graph.append(i)
    all_graph.append(G_switchs)
    G = nx.compose_all(all_graph) 
    for i in lan_switch_ID:
        if len(i) > 1:
            #print(i)
            for j in i:
                for h in i:
                    if j != h:
                        G.add_edge(j,h)
                        G.remove_edge(j,h)
    for i in G.nodes():
        if G.nodes[i]["type"] == "server":
            # neineighbors = list(G.neighbors(i))
            switch_neighbors = [j for j in G.neighbors(i) if G.nodes[j]["type"] == "switch"]
            if not switch_neighbors:
                continue
            to_remove = []
            for j in switch_neighbors:
                if random.random() < 0.4:
                    to_remove.append(j)
            if len(to_remove) == len(switch_neighbors):
                saved = random.choice(to_remove)
                to_remove.remove(saved)
            for j in to_remove:
                G.remove_edge(i, j)
            # for j in neineighbors:
            #     if G.nodes[j]["type"] == "switch":
            #         if random.random() < 0.4 and len(list(G.neighbors(i))) > 1:
            #             G.remove_edge(i,j)


    # nx.draw(G, with_labels=True, alpha=0.8, node_size=500)
    # plt.savefig("graph.png")  
    # plt.show()  
    all_switches = {n for n in G.nodes() if G.nodes[n]['type'] == 'switch'}
    all_servers = {n for n in G.nodes() if G.nodes[n]['type'] == 'server'}
    Host_work = random.sample(list(all_servers),int(0.3*len(all_servers)))
    sorted_nodes = sorted(G.nodes())
    # node_mapping = {node: idx  for idx, node in enumerate(sorted_nodes)}
    G2 = nx.Graph()
    G2.add_nodes_from(G2.nodes())
    all_nodes = set(G2.nodes())
    # all_switches = set([node_mapping[node] for node in all_switches])
    # all_servers = all_nodes - all_switches
    Host_work = random.sample(list(all_servers),int(0.3*len(all_servers)))
    for u, v in G.edges():
        G2.add_edge(u,v)
    # Set node attributes
    G_number = set_node_attribute(G2, defense_type)
    return G_number


def Dy_partitioned_layered_garph_generatin(layers,total,layers_percent,Lan_num,switchs_percent,pro,defense_type,T):
    layers_num = [int(total*i) for i in layers_percent]
    #print(layers_num)
    graph_list = {}
    each_Lan_node_num = []
    lan_switchs_num = []
    lan_switch_ID= []
    start = 0
    end = 0
    lan_ID = 0
    each_lan_node_id = []
    for i in range(layers):
        each_Lan = layers_num[i]/Lan_num[i]
        count = 0
        
        while count < Lan_num[i]:
            each_Lan_node_num.append(int(each_Lan))
            lan_switchs_num.append(math.ceil(switchs_percent[i]*each_Lan))
            lan_switch_ID_ = set()
            flag = True
            start = end
            end = end + int(each_Lan)
            each_lan_node_id_ = [i for i in range(start,end)]
            each_lan_node_id.append(each_lan_node_id_)
            while flag == True:
                lan_switch_ID_.add(random.choice(each_lan_node_id[lan_ID]))
                if len(lan_switch_ID_) == lan_switchs_num[lan_ID]:
                    flag = False
                    lan_ID += 1 
                    lan_switch_ID_ = list(lan_switch_ID_)
                    lan_switch_ID.append(lan_switch_ID_)      
            count += 1
  
    G_lans = {}
    for i in range(len(each_Lan_node_num)):
        G_lans[i] = nx.complete_graph(each_lan_node_id[i]) 
        for j in G_lans[i]:
            G_lans[i].nodes[j]["type"] = "server"
    
    G_switchs = nx.Graph()
    count1 = 0
    while count1 < len(lan_switchs_num)-1:
        # for i in lan_switch_ID[count1]:
        #     for j in lan_switch_ID[count1+1]:
        #         G_switchs.add_edge(i,j)
        for i in lan_switch_ID[count1]:
            num_connections = random.randint(1, len(lan_switch_ID[count1+1]))
            connected_switches = random.sample(lan_switch_ID[count1+1], num_connections)
            for j in connected_switches:
                G_switchs.add_edge(i, j)
        count1 += 1
    switch_cve = []
    for i in G_switchs:
        G_switchs.nodes[i]["type"] = "switch"

    
    all_graph = []
    for i in G_lans.values():
        all_graph.append(i)
    all_graph.append(G_switchs)
    G = nx.compose_all(all_graph) 
    for i in lan_switch_ID:
        if len(i) > 1:
            #print(i)
            for j in i:
                for h in i:
                    if j != h:
                        G.add_edge(j,h)
                        G.remove_edge(j,h)
    for i in G.nodes():
        if G.nodes[i]["type"] == "server":
            # if G.nodes[i]["type"] == "server":
            # neineighbors = list(G.neighbors(i))
            switch_neighbors = [j for j in G.neighbors(i) if G.nodes[j]["type"] == "switch"]
            if not switch_neighbors:
                continue
            to_remove = []
            for j in switch_neighbors:
                if random.random() < 0.4:
                    to_remove.append(j)
            if len(to_remove) == len(switch_neighbors):
                saved = random.choice(to_remove)
                to_remove.remove(saved)
            for j in to_remove:
                G.remove_edge(i, j)
            # for j in neineighbors:
            #     if G.nodes[j]["type"] == "switch":
            #         if random.random() < 0.4 and len(list(G.neighbors(i))) > 1:
            #             G.remove_edge(i,j)


    # nx.draw(G, with_labels=True, alpha=0.8, node_size=500)
    # plt.savefig("graph.png")  
    # plt.show()  # 
    all_switches = {n for n in G.nodes() if G.nodes[n]['type'] == 'switch'}
    all_servers = {n for n in G.nodes() if G.nodes[n]['type'] == 'server'}
    Host_work = random.sample(list(all_servers),int(0.3*len(all_servers)))
    all_nodes = set(G.nodes())
    # sorted_nodes = sorted(G.nodes())
    # node_mapping = {node: idx  for idx, node in enumerate(sorted_nodes)}
    # G2 = nx.Graph()
    # G2.add_nodes_from(G2.nodes())
    # all_nodes = set(G2.nodes())
    # all_switches = set([node_mapping[node] for node in all_switches])
    # all_servers = all_nodes - all_switches
    # Host_work = random.sample(list(all_servers),int(0.3*len(all_servers)))
    # for u, v in G.edges():
    #     G2.add_edge(u,v)
    # Set node attributes
    G_number = set_node_attribute(G, defense_type)
    Dy_G = []
    t_errors = []
    Dy_G.append(G_number)#Save the network at time 0.
    # G_0 = G_number.copy()
    G_0 = copy.deepcopy(G_number)
    for t in range(1, T):
        # G_ = Dy_G[t-1].copy()
        G_ = copy.deepcopy(Dy_G[t-1])
        # Routine change: randomly select 0.02 of the nodes to enhance or weaken their defensive capabilities.
        all_nodes_ = set(G_.nodes())
        all_servers_ = all_nodes_ - all_switches
        G_0,G_ = commen_change(G_0,G_, all_nodes_, all_switches, all_servers_)

        #Changes in host operational status.
        if t % 12 == 0 and (t // 12) % 2 == 1:#After work hours, change every 12 time points
            G_ = host_work_off(G_, Host_work)
        elif t % 12 == 0 and (t // 12) % 2 == 0:#During work hours, change every 12 time points
            G_ = host_work_on(G_0, G_, Host_work)

        #Changes in host failure status
        real_error = []
        for h in Host_work:
            #If the generated random number is less than 0.001, it indicates that this host has failed
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
    # save(graph, "./graph.json")
    #Set the type of numerical simulation network to generate，defense_type = 1,2,3
    defense_type = 1
    # defense_type = 2
    # defense_type = 3

    # Generate and save static/dynamic networks
    static = 0
    # static = 1

    # Set the node scale to 10
    layers = 3
    total = 20
    layers_percent = [0.6,0.3,0.1]
    Lan_num = [2,1,1]
    switchs_percent=[0.2,0.2,0.2]
    # Node scale of 100
    # layers = 4
    # total = 100
    # layers_percent = [0.5,0.3,0.1,0.1]
    # Lan_num = [5,2,2,1]
    # switchs_percent=[0.2,0.2,0.2,0.2]
    # Set the node scale to 1000
    # layers = 4
    # total = 1000
    # layers_percent = [0.5,0.3,0.1,0.1]
    # Lan_num = [5,2,2,1]
    # switchs_percent=[0.2,0.2,0.2,0.2]
    # Generate the network
    for c in range(1):
        pro = 0.65  # The probability that nodes within the same LAN share the same CVE
        # np.random.seed(2077)
        if static == 1:  # Static network
            graph = partitioned_layered_garph_generatin(layers, total, layers_percent, Lan_num, switchs_percent, pro, defense_type)
            z = (f"./number_net/partitioned_layered/static/{len(graph.nodes())}_defensetype_{defense_type}_net{c}.gpickle")
            # z = (f"./number_net/test/static/{len(graph.nodes())}_defensetype_{defense_type}_net{c}.gpickle")
            os.makedirs(os.path.dirname(z), exist_ok=True)
            with open(z, 'wb') as f:
                pickle.dump(graph, f, pickle.HIGHEST_PROTOCOL)
        #print(graph.nodes(data = True))
        #nx.write_gpickle(graph, "test_1000_2.gpickle")
        else:  # Dynamic network
            t_end = 100
            Gy_graphs = Dy_partitioned_layered_garph_generatin(layers,total,layers_percent,Lan_num,switchs_percent,pro,defense_type, T = t_end)
            for i in range(len(Gy_graphs)):
                z = (f"./number_net/partitioned_layered/dynamic/{len(Gy_graphs[0].nodes())}_defensetype_{defense_type}_net{c}/t{i}.gpickle")
                # z = (f"./number_net/test/dynamic/{len(Gy_graphs[0].nodes())}_defensetype_{defense_type}_net{c}/t{i}.gpickle")
                os.makedirs(os.path.dirname(z), exist_ok=True)
                with open(z, 'wb') as f:
                    pickle.dump(Gy_graphs[i], f, pickle.HIGHEST_PROTOCOL)
        
