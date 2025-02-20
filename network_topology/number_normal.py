# 输入层数 layers ;
# 总的节点数 total;
# 每一层的节点数目占总数目的比例，列表 layers_percent = []
# 每一层内部的子网数量 Lan_num 
# 每一层交换机占该层总数据的比例，列表 switchs_percent = [],除最后一层外，交换机数量最少为1
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

 
# 先定义局域网、在定义局域网内的交换机，交换机和上一层的交换机相连接，上一层交换机再和上一层相连接
def partitioned_layered_garph_generatin(layers,total,layers_percent,Lan_num,switchs_percent,pro,defense_type):
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
  
    G_lans = {}
    for i in range(len(each_Lan_node_num)):
        G_lans[i] = nx.complete_graph(each_lan_node_id[i]) 
        for j in G_lans[i]:
            G_lans[i].nodes[j]["type"] = "server"
    #生成交换机之间的连接，同层交换机不连接，交换机只与紧挨着的上一层交换机连接
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
        G_switchs.nodes[i]["type"] = "switch"#从交换机相关漏洞中产生cve

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
    # 随机删除主机与交换机连接的一些边
    for i in G.nodes():
        if G.nodes[i]["type"] == "server":
            neineighbors = list(G.neighbors(i))
            for j in neineighbors:
                if G.nodes[j]["type"] == "switch":
                    if random.random() < 0.4:
                        G.remove_edge(i,j)


    # nx.draw(G, with_labels=True, alpha=0.8, node_size=500)
    # plt.savefig("graph.png")  # 保存为 PNG 文件
    # plt.show()  # 显示图像（可选）
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
    return G_number#生成了网络图


def Dy_partitioned_layered_garph_generatin(layers,total,layers_percent,Lan_num,switchs_percent,pro,defense_type,T):
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
  
    G_lans = {}
    for i in range(len(each_Lan_node_num)):
        G_lans[i] = nx.complete_graph(each_lan_node_id[i]) 
        for j in G_lans[i]:
            G_lans[i].nodes[j]["type"] = "server"
    #生成交换机之间的连接，同层交换机不连接，交换机只与紧挨着的上一层交换机连接
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
        G_switchs.nodes[i]["type"] = "switch"#从交换机相关漏洞中产生cve

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
    # 随机删除主机与交换机连接的一些边
    for i in G.nodes():
        if G.nodes[i]["type"] == "server":
            neineighbors = list(G.neighbors(i))
            for j in neineighbors:
                if G.nodes[j]["type"] == "switch":
                    if random.random() < 0.4:
                        G.remove_edge(i,j)


    # nx.draw(G, with_labels=True, alpha=0.8, node_size=500)
    # plt.savefig("graph.png")  # 保存为 PNG 文件
    # plt.show()  # 显示图像（可选）
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
    Dy_G.append(G_number)#保存0时刻的网络
    # G_0 = G_number.copy()
    G_0 = copy.deepcopy(G_number)
    for t in range(1, T):
        # G_ = Dy_G[t-1].copy()
        G_ = copy.deepcopy(Dy_G[t-1])
        # 常规变化，随机选择0.02的节点增强或减弱防御能力,常规变化的内容也要反馈到后面的修改中
        all_nodes_ = set(G_.nodes())
        #为了维持稳定，交换机是不变化的，但是主机是可以变化的
        all_servers_ = all_nodes_ - all_switches
        G_0,G_ = commen_change(G_0,G_, all_nodes_, all_switches, all_servers_)

        #主机的工作状态变化
        if t % 12 == 0 and (t // 12) % 2 == 1:#下班时间，每隔12个时间点，更换一次
            G_ = host_work_off(G_, Host_work)
        elif t % 12 == 0 and (t // 12) % 2 == 0:#上班时间，每隔12个时间点，更换一次
            G_ = host_work_on(G_0, G_, Host_work)

        #主机的故障状态变化
        real_error = []
        for h in Host_work:
            #如果生成的随机数小于0.001，表示这个主机出现故障
            if random.random() < 0.001:
                G_ = host_error_off(G_, [h])
                real_error.append(h)
        if len(real_error) != 0:#这个时刻产生了故障
            t_errors.append([t,real_error])#记录故障时刻
        for m in t_errors:
            if m[0] + 72 == t:
                G_ = host_error_on(G_0, G_, m[1])
        Dy_G.append(G_)
    return Dy_G#生成了网络图
    




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
    #设置生成数值模拟网络类型，defense_type = 1,2,3
    defense_type = 1
    # defense_type = 2
    # defense_type = 3

    # 静态\动态网络的生成及保存
    static = 0

    #节点规模为10
    layers = 3
    total = 20
    layers_percent = [0.6,0.3,0.1]
    Lan_num = [2,1,1]
    switchs_percent=[0.2,0.2,0.2]
    #节点规模为100
    # layers = 4
    # total = 100
    # layers_percent = [0.5,0.3,0.1,0.1]
    # Lan_num = [5,2,2,1]
    # switchs_percent=[0.2,0.2,0.2,0.2]
    #节点规模为1000
    # layers = 4
    # total = 1000
    # layers_percent = [0.5,0.3,0.1,0.1]
    # Lan_num = [5,2,2,1]
    # switchs_percent=[0.2,0.2,0.2,0.2]
    #生成网络
    for c in range(1):
        pro = 0.65#同一个局域网内部的节点哟多大的可能性拥有同一个cve
        # np.random.seed(2077)
        if static == 1:#静态网络
            graph = partitioned_layered_garph_generatin(layers,total,layers_percent,Lan_num,switchs_percent,pro,defense_type)
            z = (f"./number_net/partitioned_layered/static/{len(graph.nodes())}_defensetype_{defense_type}_net{c}.gpickle")
            with open(z, 'wb') as f:
                pickle.dump(graph, f, pickle.HIGHEST_PROTOCOL)
        #print(graph.nodes(data = True))
        #nx.write_gpickle(graph, "test_1000_2.gpickle")
        else:#动态网络
            t_end = 100
            Gy_graphs = Dy_partitioned_layered_garph_generatin(layers,total,layers_percent,Lan_num,switchs_percent,pro,defense_type, T = t_end)
            for i in range(len(Gy_graphs)):
                z = (f"./number_net/partitioned_layered/dynamic/{len(Gy_graphs[0].nodes())}_defensetype_{defense_type}_net{c}/t{i}.gpickle")
                os.makedirs(os.path.dirname(z), exist_ok=True)
                with open(z, 'wb') as f:
                    pickle.dump(Gy_graphs[i], f, pickle.HIGHEST_PROTOCOL)
        
