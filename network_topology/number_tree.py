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
#核心交换机数量core_switch_num,汇聚交换机数量aggregation_switch_num,接入交换机数量edge_switch_num,主机数量host_num
#每个核心交换机连接的汇聚交换机数量core_aggregation={0:6},每个汇聚交换机连接的接入交换机数量aggregation_edge={0:2,1:2,2:2,3:2,4:2,5:2}
def tree(core_switch_num,core_aggregation, aggregation_switch_num,aggregation_edge,edge_switch_num,host_num,pro,defense_type):
    lan_ID = 0#用于计算当前是在生成哪一个局域网的ID
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
    #这里已经添加了所有的交换机
    for i in G_edge.nodes():#对于每一个接入交换机
        #创建一个子网内部全连接图
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
        #将子网中的节点添加到总网络中
        G = nx.compose(G,G_H)
        # nx.draw(G, with_labels=True, alpha=0.8, node_size=500)
        # plt.savefig("/root/feifei/8_network_generator/data_cve/graph.png")  # 保存为 PNG 文件
    G_number = set_node_attribute(G, defense_type)
    #画图

    return G_number

def Dy_tree(core_switch_num,core_aggregation, aggregation_switch_num,aggregation_edge,edge_switch_num,host_num,pro,defense_type, T = 1000):
    Dy_G = []#用于保存动态网络
    # 动态网络的变化特点：设置一个两个概率，一个是Host_work的概率，固定这一部分节点，每隔24个时间点，更换一次。另一个是Host_error的概率，从除了交换机以外的所有节点中随机选择机型关闭，并在72个时间点之后重新开启。
    #先生成0时刻的网络图，保存0时刻的交换机、主机节点集合，然后基于0时刻的网络图进行动态变化

    #故障时刻表
    t_errors = []
    lan_ID = 0#用于计算当前是在生成哪一个局域网的ID
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
    #这里已经添加了所有的交换机
    all_switches = set(G.nodes())
    for i in G_edge.nodes():#对于每一个接入交换机
        #创建一个子网内部全连接图
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
        #将子网中的节点添加到总网络中
        G = nx.compose(G,G_H)

    G_number = set_node_attribute(G, defense_type)
    #动态网络的变化
    Dy_G.append(G_number)#保存0时刻的网络
    #获取主机类型的节点
    all_nodes = set(G_number.nodes())
    all_servers = all_nodes - all_switches
    Host_work = random.sample(list(all_servers),int(0.3*len(all_servers)))
    # Host_error = random.sample(all_servers,int(0.3*len(all_servers)))
    G_0 = copy.deepcopy(G_number)
    #从G_number.nodes()中选择一部分节点作为Host_work
    for t in range(1, T):
        G_ = copy.deepcopy(Dy_G[t-1])
        # 常规变化，随机选择0.02的节点增强或减弱防御能力
        all_nodes_ = set(G_.nodes())
        #为了维持稳定，交换机是不变化的，但是主机是可以变化的
        all_severs_ = all_nodes_ - all_switches
        G_0,G_ = commen_change(G_0,G_, all_nodes_, all_switches, all_severs_)
        #主机的工作状态变化
        if t % 12 == 0 and (t // 12) % 2 == 1:#下班时间，每隔12个时间点，更换一次
            G_ = host_work_off(G_, Host_work)
        elif t % 12 == 0 and (t // 12) % 2 == 0:#上班时间，每隔12个时间点，更换一次
            G_ = host_work_on(G_0, G_, Host_work)
        real_error = []
        #主机的故障状态变化
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
    return Dy_G

# def commen_change(G, all_nodes, all_switches, all_servers):
#     #代表数值类型的网络图中的常规变化
#     change_node = random.sample(all_nodes, max(int(0.02*len(all_nodes)),1))
#     for i in change_node:
#         #增加防御属性
#         if G.nodes[i]["detection"] < 10:
#             G.nodes[i]["detection"] += 1
#         if any(value < 10 for value in G.nodes[i]["defense"]):
#             min_defense = min(G.nodes[i]["defense"])
#             min_index = G.nodes[i]["defense"].index(min_defense)
#             G.nodes[i]["defense"][min_index] += 1
#     return G

# def host_work_off(G, Host_work):
#     #删除所有的Host_work节点
#     for i in Host_work:
#         if i in G.nodes():
#             G.remove_node(i)
#     return G
# def host_error_off(G, Host_error):
#     #删除所有的Host_error节点
#     for i in Host_error:
#         if i in G.nodes():
#             G.remove_node(i)
#     return G
# def host_work_on(G_0,G, Host_work):
#     #在节点G中添加所有的Host_work节点，并根据G_0,增加相应的边
#     for i in Host_work:
#         if i not in G.nodes():
#             node_0_attrs = G_0.nodes[i]
#             G.add_node(i, **node_0_attrs)
#         for j in G_0.neighbors(i):
#             if j in G.nodes():
#                 G.add_edge(i,j)
#     return G
    
# def host_error_on(G_0,G, Host_error):
#     #在节点G中添加所有的Host_error节点，并根据G_0,增加相应的边
#     for i in Host_error:
#         if i not in G.nodes():
#             node_0_attrs = G_0.nodes[i]
#             G.add_node(i, **node_0_attrs)
#         for j in G_0.neighbors(i):
#             if j in G.nodes():
#                 G.add_edge(i,j)
#     return G


# def set_node_attribute(G, defense_type):
#     #增加节点属性值（数值类型），设置高防御低检测（1），低检测低防御（2），高检测高防御（3）
#     if defense_type == 1:
#         #前4个属性最小值为5，后一个属性最大值为3
#         #属性值为一个列表
#         for i in G.nodes():
#             G.nodes[i]["defense"] =[random.randint(5, 10) for _ in range(4)]
#             G.nodes[i]["detection"] = random.randint(0, 3)
#     elif defense_type == 2:#低检测低防御
#         for i in G.nodes():
#             G.nodes[i]["defense"] = [random.randint(0, 5) for _ in range(4)]
#             G.nodes[i]["detection"] = random.randint(0, 3)
#     elif defense_type == 3:#高检测高防御
#         for i in G.nodes():
#             G.nodes[i]["defense"] = [random.randint(5, 10) for _ in range(4)]
#             G.nodes[i]["detection"] = random.randint(5, 10)
#     return G
            

# 定义一个函数，用于将图G保存到文件fname中
def save(G, fname):
    # 将图G中的节点和边保存为字典，节点以列表形式保存，边以列表形式保存
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
    #节点规模为10
    # core_switch_num =1
    # core_aggregation={0:2}
    # aggregation_switch_num = sum(core_aggregation.values())
    # aggregation_edge={0:2,1:2}
    # edge_switch_num = sum(aggregation_edge.values())
    # host_num = 8

    # #节点规模为100
    # core_switch_num =1
    # core_aggregation={0:3}
    # aggregation_switch_num = sum(core_aggregation.values())
    # aggregation_edge={0:3,1:3,2:3}
    # edge_switch_num = sum(aggregation_edge.values())
    # host_num = 90

    #节点规模为1000
    core_switch_num =1#核心交换机数量,树的根节点
    core_aggregation={0:7}#每个核心交换机连接的汇聚交换机数量
    aggregation_switch_num = sum(core_aggregation.values())#汇聚交换机数量
    aggregation_edge={0:7,1:3,2:7,3:7,4:6,5:6,6:7}#每个汇聚交换机连接的接入交换机数量
    ##接入交换机数量是aggregation_edge的所有键值的和
    edge_switch_num = sum(aggregation_edge.values())#接入交换机数量
    host_num = 950



    pro = 0.65#存在多大的概率在同一个局域网内有同一个漏洞
    # np.random.seed(2077)
    #设置生成数值模拟网络类型，defense_type = 1,2,3
    # defense_type = 1
    defense_type = 2
    # defense_type = 3
    #设置网络是静态的还是动态的，static = 0，1  0表示动态，1表示静态

    # 静态\动态网络的生成及保存
    # static = 1
    static = 0
    for c in range(1):
        if static == 1:#静态网络
            graph = tree(core_switch_num,core_aggregation, aggregation_switch_num,aggregation_edge,edge_switch_num,host_num,pro,defense_type)
            
    # nx.draw(graph, with_labels=True, alpha=0.8, node_size=500)
    # plt.savefig("123.png")
            # z = (f"./number_net/tree/static/{len(graph.nodes())}_defensetype_{defense_type}_tree{c}.gpickle")
            z = (f"./number_net/test/static/{len(graph.nodes())}_defensetype_{defense_type}_tree{c}.gpickle")
            os.makedirs(os.path.dirname(z), exist_ok=True)
            with open(z, 'wb') as f:
                pickle.dump(graph, f, pickle.HIGHEST_PROTOCOL)
        else:#动态网络
            t_start = 0
            t_end = 1000
            Gy_graphs = Dy_tree(core_switch_num,core_aggregation, aggregation_switch_num,aggregation_edge,edge_switch_num,host_num,pro,defense_type, T = t_end)
            for i in range(len(Gy_graphs)):
                # z = (f"./number_net/tree/dynamic/{len(Gy_graphs[0].nodes())}_defensetype_{defense_type}_tree{c}/t{i}.gpickle")
                z = (f"./number_net/test/dynamic/{len(Gy_graphs[0].nodes())}_defensetype_{defense_type}_tree{c}/t{i}.gpickle")
                os.makedirs(os.path.dirname(z), exist_ok=True)
                with open(z, 'wb') as f:
                    pickle.dump(Gy_graphs[i], f, pickle.HIGHEST_PROTOCOL)


    
