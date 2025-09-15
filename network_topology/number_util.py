import numpy as np
import random
from networkx.readwrite import json_graph
def commen_change(G_0,G, all_nodes, all_switches, all_servers):
    #代表数值类型的网络图中的常规变化
    change_node = random.sample(list(all_nodes), max(int(0.02*len(all_nodes)),1))
    for i in change_node:
        #增加防御属性
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
    #删除所有的Host_work节点
    for i in Host_work:
        if i in G.nodes():
            G.remove_node(i)
    return G
def host_error_off(G, Host_error):
    #删除所有的Host_error节点
    for i in Host_error:
        if i in G.nodes():
            G.remove_node(i)
    return G
def host_work_on(G_0,G, Host_work):
    #在节点G中添加所有的Host_work节点，并根据G_0,增加相应的边
    for i in Host_work:
        if i not in G.nodes():
            node_0_attrs = G_0.nodes[i]
            G.add_node(i, **node_0_attrs)
        for j in G_0.neighbors(i):
            if j in G.nodes():
                G.add_edge(i,j)
    return G
    
def host_error_on(G_0,G, Host_error):
    #在节点G中添加所有的Host_error节点，并根据G_0,增加相应的边
    for i in Host_error:
        if i not in G.nodes():
            node_0_attrs = G_0.nodes[i]
            G.add_node(i, **node_0_attrs)
        for j in G_0.neighbors(i):
            if j in G.nodes():
                G.add_edge(i,j)
    return G


def set_node_attribute(G, defense_type):
    #增加节点属性值（数值类型），设置高防御低检测（1），低检测低防御（2），高检测高防御（3）
    if defense_type == 1:
        #前4个属性最小值为5，后一个属性最大值为3
        #属性值为一个列表
        for i in G.nodes():
            G.nodes[i]["defense"] =[random.randint(5, 10) for _ in range(4)]
            G.nodes[i]["detection"] = random.randint(0, 3)
    elif defense_type == 2:#低检测低防御
        for i in G.nodes():
            G.nodes[i]["defense"] = [random.randint(0, 5) for _ in range(4)]
            G.nodes[i]["detection"] = random.randint(0, 3)
    elif defense_type == 3:#高检测高防御
        for i in G.nodes():
            G.nodes[i]["defense"] = [random.randint(5, 10) for _ in range(4)]
            G.nodes[i]["detection"] = random.randint(5, 10)
    return G