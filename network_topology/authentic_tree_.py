import matplotlib.pyplot as plt
import networkx as nx
import random
import math
import json
import sys,os
import numpy as np
from networkx.readwrite import json_graph
import pickle

sys.path.append(os.getcwd())
from data_cve.CVE_detail import Read_data   
#核心交换机数量core_switch_num,汇聚交换机数量aggregation_switch_num,接入交换机数量edge_switch_num,主机数量host_num
#每个核心交换机连接的汇聚交换机数量core_aggregation={0:6},每个汇聚交换机连接的接入交换机数量aggregation_edge={0:2,1:2,2:2,3:2,4:2,5:2}

def authentic_tree(core_switch_num,core_aggregation, aggregation_switch_num,aggregation_edge,edge_switch_num,host_num,pro):
    lan_ID = 0#用于计算当前是在生成哪一个局域网的ID
    start = 0
    end = 0
    each_lan_node_id = []
    all_cve,all_type,all_type_list = Read_data().data()#  
    G = nx.Graph()
    G_core = nx.Graph()
    G_aggregation = nx.Graph()
    G_edge = nx.Graph()
    count = 0
    host_per_edge = int(host_num/(int(edge_switch_num)))
    #读取账号和密码.txt文件
    user = []
    with open('user.txt', 'r', encoding='utf-8') as file:
        for line in file:
            user.append(line.strip()) 
    password = []
    with open('pass.txt', 'r', encoding='utf-8') as file:
        for line in file:
            password.append(line.strip())
    
    for i in range(core_switch_num):
        G.add_node(i)#添加核心交换机
        G_core.add_node(i)
        count += 1
        for j in range(core_aggregation[i]):
            j_count = count
            G_aggregation.add_node(j_count)
            G.add_node(j_count)#添加汇聚交换机
            G.add_edge(i,j_count)
            count += 1
            for k in range(aggregation_edge[j]):
                k_count = count
                G_edge.add_node(k_count)
                G.add_node(k_count)
                G.add_edge(j_count,k_count)
                count += 1
    #这里已经添加了所有的交换机，给交换机增加属性
    for i in G.nodes():
        G.nodes[i]["type"] = "switch"
        G.nodes[i]["lan_id"] = "other"
        G.nodes[i]["port_server_version"] = []
        G.nodes[i]["system"] = random.choice(["os_windows","os_linux","os_ios","os_mac","os_unix"])#all_cve,all_type,all_type_list
        # 生成交换机的候选漏洞列表
        candidate_cve = all_type_list[G.nodes[i]["system"]].values()+all_type_list["switch"].values()+all_type_list["router"].values()
        # 随机选择1-2个漏洞
        h = random.sample(candidate_cve,random.choice([1,2]))
        G.nodes[i]["cve"] = h
        G.nodes[i]["software_version"] = []
        for m in h:
            #G.append(m)
            if len(all_cve[m]["affectedversion"]) != 0:
                version = random.choice(all_cve[m]["affectedversion"])
            G.nodes[i]["software_version"].append(version)
        account = random.randint(1,4)
        G.nodes[i]["account"] = []
        for j in range(account):
            
    #增加边缘交换机连接的主机，然后给每一个主机增加属性
    use_cve = list(cve.cve_database.keys())+list(cve.cve_os.keys())+list(cve.cve_server.keys())
    count = 0
    for i in G_edge.nodes():
        #创建一个子网内部全连接图
        all_node_now = len(G.nodes())
        G_H = nx.Graph()
        G_H.add_node(i)
        normal_cve = random.choice(use_cve)
        for j in range(host_per_edge):
            G_H.add_node(all_node_now)
            G_H.nodes[all_node_now]["type"] = "server"
            G_H.nodes[all_node_now]["lan_id"] = str(count)
            G_H.nodes[all_node_now]["system"] = random.choice(["windows","linux"])
            G_H.nodes[all_node_now]["software_ver"] = []
            h = random.sample(use_cve,random.choice([2,3]))
            if random.random() < pro:
                h.append(normal_cve)
                h = list(set(h))
            G_H.nodes[all_node_now]["cve"] = h
            for m in h:
                #host_cve.append(m)
                if len(cve.all_cve[m]["affectedversion"]) != 0:
                    version = random.choice(cve.all_cve[m]["affectedversion"])
                else:
                    version = "PAD"
                software = random.choice(cve.all_cve[m]["targetname"])
                G_H.nodes[all_node_now]["software_ver"].append((software,version))
            all_node_now += 1
        count += 1
        for j in G_H.nodes():
            for s in G_H.nodes():
                if j != s:
                    G_H.add_edge(j,s)
        #将子网中的节点添加到总网络中
        G = nx.compose(G,G_H)
    return G

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
    core_switch_num =1
    core_aggregation={0:7}
    aggregation_switch_num = 7
    aggregation_edge={0:7,1:3,2:7,3:7,4:6,5:6,6:7}
    edge_switch_num = 43
    host_num = 870
    pro = 0.65
    np.random.seed(2077)
    graph = realworld(core_switch_num,core_aggregation, aggregation_switch_num,aggregation_edge,edge_switch_num,host_num,pro)
    nx.draw(graph, with_labels=True, alpha=0.8, node_size=500)
    plt.savefig("123.png")
    c = 15
    z = (f"./datadrive/dataset/pre_data/test1000_{c}.gpickle")
    with open(z, 'wb') as f:
        pickle.dump(graph, f, pickle.HIGHEST_PROTOCOL)
