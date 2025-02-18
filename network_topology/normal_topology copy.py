# 输入层数 layers ;
# 总的节点数 total;
# 每一层的节点数目占总数目的比例，列表 layers_percent = []
# 每一层内部的子网数量 Lan_num 
# 每一层交换机占该层总数据的比例，列表 switchs_percent = [],除最后一层外，交换机数量最少为1
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
 
# 先定义局域网、在定义局域网内的交换机，交换机和上一层的交换机相连接，上一层交换机再和上一层相连接
def garph_generatin(layers,total,layers_percent,Lan_num,switchs_percent,pro):
    layers_num = [int(total*i) for i in layers_percent]#每一层拥有的主机数量
    #print(layers_num)
    graph_list = {}
    each_Lan_node_num = []#每一个局域网具有的节点的总数量
    lan_switchs_num = []#每一个局域网具有的交换机的数量
    lan_switch_ID= []#每一个交换机的ID
    start = 0
    end = 0
    lan_ID = 0#用于计算当前是在生成哪一个局域网的ID
    each_lan_node_id = []
    cve = Read_data()#
    for i in range(layers):
        each_Lan = layers_num[i]/Lan_num[i]#一层网络有多个局域网，各个局域网内部节点的数目是相同的
        count = 0
        #start和end是方便生成交换机ID定义的起点和终点
        
        while count < Lan_num[i]:
            each_Lan_node_num.append(int(each_Lan))#每一个局域网具有的节点的总数量
            lan_switchs_num.append(math.ceil(switchs_percent[i]*each_Lan))#每一个局域网拥有的交换机的数量
            lan_switch_ID_ = set()#局域网内交换机的ID
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
    # print("each_Lan_node_num",each_Lan_node_num)
    # print("lan_switchs_num",lan_switchs_num)
    # print("lan_switch_ID",lan_switch_ID)
    # print("each_lan_node_id",each_lan_node_id)

    # 上面生成了每一个局域网拥有的总的节点数量each_Lan_node_num、每一个局域网的所有交换机的编号lan_switch_ID
    #每一个局域网内部的所有节点的标号each_lan_node_id
    #接下来，每一个局域网内部需要全连通，每一个交换机与上一层的交换机相连接
    #首先生成全连接的局域网,并且对局域网中的每一个节点增加1-2个漏洞
    #前面几层增加的漏洞是软件类型cve.cve_server,最后一层是数据库类型的cve.cve_database
    G_lans = {}
    

    for i in range(len(each_Lan_node_num)):
        G_lans[i] = nx.complete_graph(each_lan_node_id[i]) 
        a = random.choice(["windows","linux"])
        #print(i,a)
        lan_cve = []
        if i == len(each_Lan_node_num)-1:
            k = random.choice(list(cve.cve_database.keys()))
        else:
            use_cve = list(cve.cve_database.keys())+list(cve.cve_os.keys())+list(cve.cve_server.keys())
            k = random.choice(use_cve)
        for j in G_lans[i]:
            G_lans[i].nodes[j]["type"] = "server"
            G_lans[i].nodes[j]["lan_id"] = str(i)
            G_lans[i].nodes[j]["system"] = a
            G_lans[i].nodes[j]["software_ver"] = []
            if i == len(each_Lan_node_num)-1:#代表现在是最后一层,最后一层从数据库挑选cve
                h = list(random.sample(cve.cve_database.keys(),random.choice([1,2])))
                if random.random() < pro:
                    h.append(k)
                    h = list(set(h))               
                G_lans[i].nodes[j]["cve"] = h
                for m in h:
                    lan_cve.append(m)
                    if len(cve.all_cve[m]["affectedversion"]) != 0:
                        version = random.choice(cve.all_cve[m]["affectedversion"])
                    else:
                         version = "PAD"
                    software = random.choice(cve.all_cve[m]["targetname"])
                    G_lans[i].nodes[j]["software_ver"].append((software,version))
                    #print(G_lans[i].nodes[j]["software_ver"])
            else:#不是最后一层,从软件中产生cve
                use_cve = list(cve.cve_database.keys())+list(cve.cve_os.keys())+list(cve.cve_server.keys())
                h = random.sample(use_cve,random.choice([2,3]))
                if random.random() < pro:
                    h.append(k)
                    h = list(set(h))#这一部分是把局域网内部这个共同的cve添加到局域网的65%的节点中
                G_lans[i].nodes[j]["cve"] = h
                for m in h:
                    lan_cve.append(m)
                    if len(cve.all_cve[m]["affectedversion"]) != 0:
                        version = random.choice(cve.all_cve[m]["affectedversion"])
                    else:
                         version = "PAD"
                    software = random.choice(cve.all_cve[m]["targetname"])
                    G_lans[i].nodes[j]["software_ver"].append((software,version))
                    # print(G_lans[i].nodes[j]["software_ver"])
        # print("lan_cve",lan_cve)

    #生成交换机之间的连接，同层交换机不连接，交换机只与紧挨着的上一层交换机连接
    #交换机漏洞智能从cve.cve_server类型中选择
    G_switchs = nx.Graph()
    count1 = 0
    while count1 < len(lan_switchs_num)-1:
        for i in lan_switch_ID[count1]:
            for j in lan_switch_ID[count1+1]:
                G_switchs.add_edge(i,j)
        count1 += 1
    switch_cve = []
    for i in G_switchs:
        G_switchs.nodes[i]["type"] = "switch"#从交换机相关漏洞中产生cve
        h = random.sample(cve.cve_switch.keys(),random.choice([1,2]))
        G_switchs.nodes[i]["cve"] = h
        G_switchs.nodes[i]["software_ver"] = []
        for m in h:
            switch_cve.append(m)
            if len(cve.all_cve[m]["affectedversion"]) != 0:
                version = random.choice(cve.all_cve[m]["affectedversion"])
            else:
                    version = "PAD"
            software = random.choice(cve.all_cve[m]["targetname"])
            G_switchs.nodes[i]["software_ver"].append((software,version))
        #print(G_switchs.nodes[i])
    # nx.draw(G_switchs, with_labels=True, alpha=0.8, node_size=500)
    # plt.show()
    # print(G_switchs.edges())
    # print(G_switchs.nodes())

    #将上面生成的交换机与局域网连接起来
    all_graph = []
    for i in G_lans.values():
        all_graph.append(i)
    all_graph.append(G_switchs)
    G = nx.compose_all(all_graph) 
    #设定的是同一个局域网中的交换机是不能连接的，所以要把这些边删去
    for i in lan_switch_ID:
        if len(i) > 1:
            #print(i)
            for j in i:
                for h in i:
                    if j != h:
                        G.add_edge(j,h)
                        G.remove_edge(j,h)
    nx.draw(G, with_labels=True, alpha=0.8, node_size=500)
    #plt.savefig("123.png")
    #给图增加属性，同一个局域网内的主机用同一种系统，安装有至少同一个软件，版本可以不同，每个主机安装有3种软件
    #交换机只设置交换机类型的漏洞  
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





# G_switchs.nodes[i]["type"] = "switch"
# h = random.sample(cve.cve_switch.keys(),random.choice([1,2]))
# G_switchs.nodes[i]["cve"] = h
# G_switchs.nodes[i]["software_ver"] = []
def map_list():
    pass

if __name__ == '__main__':
    # save(graph, "./graph.json")
    for c in range(17):
        layers = 4
        total = 1000
        layers_percent = [0.5,0.3,0.1,0.1]
        Lan_num = [5,2,2,1]
        switchs_percent=[0.2,0.2,0.2,0.2]
        pro = 0.65#同一个局域网内部的节点哟多大的可能性拥有同一个cve
        np.random.seed(2077)
        graph = garph_generatin(layers,total,layers_percent,Lan_num,switchs_percent,pro)
        #print(graph.nodes(data = True))
        #nx.write_gpickle(graph, "test_1000_2.gpickle")
        if c < 10:
            z = (f"./datadrive/dataset/pre_data/pre1000_{c}.gpickle")
            with open(z, 'wb') as f:
                pickle.dump(graph, f, pickle.HIGHEST_PROTOCOL)
        elif c >= 10 and c < 15:
            z = (f"./datadrive/dataset/pre_data/train1000_{c}.gpickle")
            with open(z, 'wb') as f:
                pickle.dump(graph, f, pickle.HIGHEST_PROTOCOL)
        elif c == 15:
            z = (f"./datadrive/dataset/pre_data/test1000_{c}.gpickle")
            with open(z, 'wb') as f:
                pickle.dump(graph, f, pickle.HIGHEST_PROTOCOL)
        else:
            z = (f"./datadrive/dataset/pre_data/Rl1000_{c}.gpickle")#用于强化学习的网络拓扑
            with open(z, 'wb') as f:
                pickle.dump(graph, f, pickle.HIGHEST_PROTOCOL)

        # z = (f"./datadrive/dataset/pre_data/pre1000_{c}.gpickle")
        # with open(z, 'wb') as f:
        #     pickle.dump(graph, f, pickle.HIGHEST_PROTOCOL)
        
        # with open('test.gpickle', 'rb') as f:
        #     G = pickle.load(f)

