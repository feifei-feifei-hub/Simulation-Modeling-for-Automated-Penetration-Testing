import numpy as np
import random
from networkx.readwrite import json_graph
def commen_change(G_0,G, all_nodes, all_switches, all_servers):
    #Represents routine changes in a numerical-type network graph.
    change_node = random.sample(list(all_nodes), max(int(0.02*len(all_nodes)),1))
    for i in change_node:
        #Increase defense attributes
        if G.nodes[i]["detection"] < 10:
            G.nodes[i]["detection"] += 1
            G_0.nodes[i]["detection"] += 1
        if any(value < 10 for value in G.nodes[i]["defense"]):
            min_defense = min(G.nodes[i]["defense"])
            min_index = G.nodes[i]["defense"].index(min_defense)
            G.nodes[i]["defense"][min_index] += 1
            G_0.nodes[i]["defense"][min_index] += 1
    return G_0,G

def host_work_off(G, Host_work):
    #Delete all Host_work nodes
    for i in Host_work:
        if i in G.nodes():
            G.remove_node(i)
    return G
def host_error_off(G, Host_error):
    #Delete all Host_error nodes
    for i in Host_error:
        if i in G.nodes():
            G.remove_node(i)
    return G
def host_work_on(G_0,G, Host_work):
    #Add all Host_work nodes to graph G and increase corresponding edges based on G_0
    for i in Host_work:
        if i not in G.nodes():
            node_0_attrs = G_0.nodes[i]
            G.add_node(i, **node_0_attrs)
        for j in G_0.neighbors(i):
            if j in G.nodes():
                G.add_edge(i,j)
    return G
    
def host_error_on(G_0,G, Host_error):
    #Add all Host_error nodes to graph G and increase corresponding edges based on G_0
    for i in Host_error:
        if i not in G.nodes():
            node_0_attrs = G_0.nodes[i]
            G.add_node(i, **node_0_attrs)
        for j in G_0.neighbors(i):
            if j in G.nodes():
                G.add_edge(i,j)
    return G


def set_node_attribute(G, defense_type):
    #Increase node attribute values (numerical type), set high defense low detection (1), low detection low defense (2), high detection high defense (3)
    if defense_type == 1:
        #The minimum value for the first 4 attributes is 5, the last attribute's maximum value is 3
        #Attribute values are a list
        for i in G.nodes():
            G.nodes[i]["defense"] =[random.randint(5, 10) for _ in range(4)]
            G.nodes[i]["detection"] = random.randint(0, 3)
    elif defense_type == 2:#Low detection low defense
        for i in G.nodes():
            G.nodes[i]["defense"] = [random.randint(0, 5) for _ in range(4)]
            G.nodes[i]["detection"] = random.randint(0, 3)
    elif defense_type == 3:#High detection high defense
        for i in G.nodes():
            G.nodes[i]["defense"] = [random.randint(5, 10) for _ in range(4)]
            G.nodes[i]["detection"] = random.randint(5, 10)
    return G