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
from authentic_utils import domain_switch_cve,domain_host_cve,firewall_cve,common_host_cve,common_switch_cve,common_database_cve,commen_change,host_work_off,host_error_off,host_work_on,host_error_on,set_node_attribute
import copy
import pandas as pd

 
# 先定义局域网、在定义局域网内的交换机，交换机和上一层的交换机相连接，上一层交换机再和上一层相连接
def partitioned_layered_garph_generatin(layers,total,layers_percent,Lan_num,switchs_percent,pro,defense_type):
    user = []
    with open('/root/feifei/8_network_generator/data_cve/user.txt', 'r', encoding='utf-8') as file:
        for line in file:
            user.append(line.strip()) 
    password = []
    with open('/root/feifei/8_network_generator/data_cve/pass.txt', 'r', encoding='utf-8') as file:
        for line in file:
            password.append(line.strip())
    #读取all_cve,all_type,all_type_list
    with open('/root/feifei/8_network_generator/data_cve/eng_all_type_list.json', 'r', encoding='utf-8') as file:
        all_type_list = json.load(file)
    #读取excel文件
    all_cve = {}
    
    df = pd.read_excel("/root/feifei/8_network_generator/data_cve/all_cve_cvss_epss.xlsx")
    for index, row in df.iterrows():
        cve_id = row['CVE_ID']  # 获取 CVE_ID 作为键
        values = row.drop('CVE_ID').to_dict()  # 其他内容作为值

        # 处理可能为列表的字段
        for key, value in values.items():
            if isinstance(value, str) and value.startswith('[') and value.endswith(']'):
                # 将字符串形式的列表转换为实际的列表
                values[key] = eval(value)

        # 将 CVE_ID 和其他内容存入字典
        all_cve[cve_id] = values
    ports_ = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443, 8888, 9000, 10000, 27017, 27018,
    161, 162, 389, 636, 1433, 1434, 1521, 2049, 2222, 3306, 3389, 5432,
    5900, 5984, 6379, 7001, 8000, 8008, 8081, 8088, 8090, 8443, 8888, 9090,
    9200, 9300, 11211, 27017, 27018, 28017, 50000, 50030, 50060, 50070,
    50075, 50090, 60010, 60030]
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
        a = random.choice(["os_windows","os_linux","os_ios","os_mac","os_unix"])
        lan_cve = []
        if i == len(each_Lan_node_num)-1:
            k = random.choice(list(all_type_list["database"]))
        else:
            k = random.choice(all_type_list["soft"])
        #这个局域网的通用CVE
        for j in G_lans[i]:
            G_lans[i].nodes[j]["type"] = "server"
            G_lans[i].nodes[j]["lan_id"] = str(i)
            G_lans[i].nodes[j]["system"] = a
            G_lans[i].nodes[j]["port_server_version"] = []
            G_lans[i].nodes[j]["software_version"] = []
            G_lans[i].nodes[j]["cve"] = []
            if i == len(each_Lan_node_num)-1:#最后一层是数据库
                common_database_cve_,common_database_port_cve_ = common_database_cve(G_lans[i].nodes[j]["system"])
                G_lans[i].nodes[j]["cve"] = list(common_database_cve_+common_database_port_cve_)
                for m in common_database_cve_:
                    if len(all_cve[m]["affectedversion"]) != 0:
                        version = random.choice(all_cve[m]["affectedversion"])
                    G_lans[i].nodes[j]["software_version"].append(version)
                ports = copy.deepcopy(ports_)
                for g in common_database_port_cve_:
                    if len(all_cve[g]["affectedversion"]) != 0:
                        version = random.choice(all_cve[g]["affectedversion"])
                        port = random.choice(ports)
                        ports.remove(port)
                        port_server_version = (str(port),version[0],version[1])
                    G_lans[i].nodes[j]["port_server_version"].append(port_server_version)
                account = set()
                for d in range(random.randint(1,2)):
                    account.add((random.choice(user),random.choice(password),random.choice(["root","admin","user"])))
                G_lans[i].nodes[j]["account"] = list(account)
            else:
                G_lans[i].nodes[j]["cve"].append(k)




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
    domain_server = []
    for i in G_switchs:
        G_switchs.nodes[i]["type"] = "switch"#从交换机相关漏洞中产生cve
        G_switchs.nodes[i]["lan_id"] = "other"
        G_switchs.nodes[i]["port_server_version"] = []
        G_switchs.nodes[i]["system"] = random.choice(["os_windows","os_linux","os_ios","os_mac","os_unix"])
        if random.random() < 0.2:
            domain_server.append(i)
            #是域交换机
            G_switchs.nodes[i]["system"] = "os_windows"
            domain_cve = random.choice(all_type_list["domain"])
            G_switchs.nodes[i]["cve"] = domain_switch_cve(domain_cve)
            G_switchs.nodes[i]["software_version"] = []
            for m in G_switchs.nodes[i]["cve"]:
                #G.append(m)
                if len(all_cve[m]["affectedversion"]) != 0:
                    version = random.choice(all_cve[m]["affectedversion"])
                G_switchs.nodes[i]["software_version"].append(version)
            account = random.randint(1,3)
            #设置域交换机的账户
            G_switchs.nodes[i]["account"] = []
            domain_account = (random.choice(user),random.choice(password),"domain")
            account = random.randint(1,2)
            for j in range(account):
                G_switchs.nodes[i]["account"].append((random.choice(user),random.choice(password),random.choice(["root","admin","user"])))
        else:#非域控交换机，普通交换机
            G_switchs.nodes[i]["cve"] = common_switch_cve(G_switchs.nodes[i]["system"])
            G_switchs.nodes[i]["software_version"] = []
            for m in G_switchs.nodes[i]["cve"]:
                #G.append(m)
                if len(all_cve[m]["affectedversion"]) != 0:
                    version = random.choice(all_cve[m]["affectedversion"])
                G_switchs.nodes[i]["software_version"].append(version)
            #设置普通交换机的账户
            account = random.randint(1,2)
            G_switchs.nodes[i]["account"] = []
            for j in range(account):
                G_switchs.nodes[i]["account"].append((random.choice(user),random.choice(password),random.choice(["root","admin","user"])))
    # Host_work = random.sample(list(all_servers),int(0.3*len(all_servers)))


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
    #为G增加属性，交换机和最后一层数据库的节点已经设置完了，现在设置其他节点的属性
    pro_type = random.random()
    for i in all_servers:
        is_domain = False
        G.nodes[i]["type"] = "server"
        #首先判断这个节点是不是已经被设置过属性了
        Lan_id_cve = {}
        if "account" not in G.nodes[i].keys():
            #说明这个节点没有设置过属性
            G.nodes[i]["account"] = []
            if len(set(G.neighbors(i)) & set(domain_server)) != 0:
                is_domain = True
                doamin_switch = list(set(G.neighbors(i)) & set(domain_server))[0]
                for h in G.nodes[doamin_switch]["account"]:
                    if h[2] == "domain":
                        domain_account = h
                        break
                for m in G.nodes[doamin_switch]["cve"]:
                    if m in all_type_list["domain"]:
                        domain_cve = m
                        break
            if is_domain:
                G.nodes[i]["system"] = "os_windows"
                G.nodes[i]["software_version"] = []
                G.nodes[i]["port_server_version"] = []
                domain_host_cve_,domain_host_port_cve_ = domain_host_cve(domain_cve)
                G.nodes[i]["cve"] = list(domain_host_cve_+domain_host_port_cve_)#域主机的漏洞全部重新设置
                for m in domain_host_cve_:
                    if len(all_cve[m]["affectedversion"]) != 0:
                        version = random.choice(all_cve[m]["affectedversion"])
                    G.nodes[i]["software_version"].append(version)
                ports = copy.deepcopy(ports_)
                for g in domain_host_port_cve_:
                    if len(all_cve[g]["affectedversion"]) != 0:
                        version = random.choice(all_cve[g]["affectedversion"])
                        port = random.choice(ports)
                        ports.remove(port)
                        port_server_version = (str(port),version[0],version[1])
                    G.nodes[i]["port_server_version"].append(port_server_version)
                account = set()
                account.add(domain_account)
                for d in range(random.randint(1,2)):
                    account.add((random.choice(user),random.choice(password),random.choice(["root","admin","user"])))
                G.nodes[i]["account"] = list(account)
            elif pro_type < 0.7 and is_domain == False:
                #是普通主机
                common_host_cve_,common_host_port_cve_ = common_host_cve(G.nodes[i]["system"])
                if random.random() > pro:#删除已经存在的漏洞
                    G.nodes[i]["cve"] = list(common_host_cve_+common_host_port_cve_)
                else:#在原来漏洞的基础上加上新的漏洞
                    G.nodes[i]["cve"] = list(set(G.nodes[i]["cve"]+common_host_cve_+common_host_port_cve_))
                G.nodes[i]["software_version"] = []
                for m in list(set(G.nodes[i]["cve"]+common_host_cve_)):
                    if len(all_cve[m]["affectedversion"]) != 0:
                        version = random.choice(all_cve[m]["affectedversion"])
                    G.nodes[i]["software_version"].append(version)
                ports = copy.deepcopy(ports_)
                for g in common_host_port_cve_:
                    if len(all_cve[g]["affectedversion"]) != 0:
                        version = random.choice(all_cve[g]["affectedversion"])
                        port = random.choice(ports)
                        ports.remove(port)
                        port_server_version = (str(port),version[0],version[1])
                    G.nodes[i]["port_server_version"].append(port_server_version)
                account = set()
                for d in range(random.randint(1,2)):
                    account.add((random.choice(user),random.choice(password),random.choice(["root","admin","user"])))
                G.nodes[i]["account"] = list(account)
            elif pro_type>0.7 and pro_type<0.8 and is_domain == False:
                #是防火墙
                firewall_cve_,firewall_port_cve_ = firewall_cve(G.nodes[i]["system"])
                if random.random() > pro:#删除已经存在的漏洞
                    G.nodes[i]["cve"] = list(firewall_cve_+firewall_port_cve_)
                else:#在原来漏洞的基础上加上新的漏洞
                    G.nodes[i]["cve"] = list(set(G.nodes[i]["cve"]+firewall_cve_+firewall_port_cve_))
                G.nodes[i]["software_version"] = []
                for m in list(set(G.nodes[i]["cve"]+firewall_cve_)):
                    if len(all_cve[m]["affectedversion"]) != 0:
                        version = random.choice(all_cve[m]["affectedversion"])
                    G.nodes[i]["software_version"].append(version)
                ports = copy.deepcopy(ports_)
                for g in firewall_port_cve_:
                    if len(all_cve[g]["affectedversion"]) != 0:
                        version = random.choice(all_cve[g]["affectedversion"])
                        port = random.choice(ports)
                        ports.remove(port)
                        port_server_version = (str(port),version[0],version[1])
                    G.nodes[i]["port_server_version"].append(port_server_version)
                account = set()
                for d in range(random.randint(1,2)):
                    account.add((random.choice(user),random.choice(password),random.choice(["root","admin","user"])))
                G.nodes[i]["account"] = list(account)
            else:
                #是数据库
                common_database_cve_,common_database_port_cve_ = common_database_cve(G.nodes[i]["system"])
                if random.random() > pro:#删除已经存在的漏洞
                    G.nodes[i]["cve"] = list(common_database_cve_+common_database_port_cve_)
                else:#在原来漏洞的基础上加上新的漏洞
                    G.nodes[i]["cve"] = list(set(G.nodes[i]["cve"]+common_database_cve_+common_database_port_cve_))
                G.nodes[i]["software_version"] = []
                for m in list(set(G.nodes[i]["cve"]+common_database_cve_)):
                    if len(all_cve[m]["affectedversion"]) != 0:
                        version = random.choice(all_cve[m]["affectedversion"])
                    G.nodes[i]["software_version"].append(version)
                ports = copy.deepcopy(ports_)
                for g in common_database_port_cve_:
                    if len(all_cve[g]["affectedversion"]) != 0:
                        version = random.choice(all_cve[g]["affectedversion"])
                        port = random.choice(ports)
                        ports.remove(port)
                        port_server_version = (str(port),version[0],version[1])
                    G.nodes[i]["port_server_version"].append(port_server_version)
                account = set()
                for d in range(random.randint(1,2)):
                    account.add((random.choice(user),random.choice(password),random.choice(["root","admin","user"])))
                G.nodes[i]["account"] = list(account)
    return G#生成了网络图


def Dy_partitioned_layered_garph_generatin(layers,total,layers_percent,Lan_num,switchs_percent,pro,defense_type,T):
    user = []
    with open('/root/feifei/8_network_generator/data_cve/user.txt', 'r', encoding='utf-8') as file:
        for line in file:
            user.append(line.strip()) 
    password = []
    with open('/root/feifei/8_network_generator/data_cve/pass.txt', 'r', encoding='utf-8') as file:
        for line in file:
            password.append(line.strip())
    #读取all_cve,all_type,all_type_list
    with open('/root/feifei/8_network_generator/data_cve/eng_all_type_list.json', 'r', encoding='utf-8') as file:
        all_type_list = json.load(file)
    #读取excel文件
    all_cve = {}
    
    df = pd.read_excel("/root/feifei/8_network_generator/data_cve/all_cve_cvss_epss.xlsx")
    for index, row in df.iterrows():
        cve_id = row['CVE_ID']  # 获取 CVE_ID 作为键
        values = row.drop('CVE_ID').to_dict()  # 其他内容作为值

        # 处理可能为列表的字段
        for key, value in values.items():
            if isinstance(value, str) and value.startswith('[') and value.endswith(']'):
                # 将字符串形式的列表转换为实际的列表
                values[key] = eval(value)

        # 将 CVE_ID 和其他内容存入字典
        all_cve[cve_id] = values
    ports_ = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443, 8888, 9000, 10000, 27017, 27018,
    161, 162, 389, 636, 1433, 1434, 1521, 2049, 2222, 3306, 3389, 5432,
    5900, 5984, 6379, 7001, 8000, 8008, 8081, 8088, 8090, 8443, 8888, 9090,
    9200, 9300, 11211, 27017, 27018, 28017, 50000, 50030, 50060, 50070,
    50075, 50090, 60010, 60030]
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
        a = random.choice(["os_windows","os_linux","os_ios","os_mac","os_unix"])
        lan_cve = []
        if i == len(each_Lan_node_num)-1:
            k = random.choice(list(all_type_list["database"]))
        else:
            k = random.choice(all_type_list["soft"])
        for j in G_lans[i]:
            G_lans[i].nodes[j]["type"] = "server"
            G_lans[i].nodes[j]["lan_id"] = str(i)
            G_lans[i].nodes[j]["system"] = a
            G_lans[i].nodes[j]["port_server_version"] = []
            G_lans[i].nodes[j]["software_version"] = []
            G_lans[i].nodes[j]["cve"] = []
            if i == len(each_Lan_node_num)-1:#最后一层是数据库
                common_database_cve_,common_database_port_cve_ = common_database_cve(G_lans[i].nodes[j]["system"])
                G_lans[i].nodes[j]["cve"] = list(common_database_cve_+common_database_port_cve_)
                for m in common_database_cve_:
                    if len(all_cve[m]["affectedversion"]) != 0:
                        version = random.choice(all_cve[m]["affectedversion"])
                    G_lans[i].nodes[j]["software_version"].append(version)
                ports = copy.deepcopy(ports_)
                for g in common_database_port_cve_:
                    if len(all_cve[g]["affectedversion"]) != 0:
                        version = random.choice(all_cve[g]["affectedversion"])
                        port = random.choice(ports)
                        ports.remove(port)
                        port_server_version = (str(port),version[0],version[1])
                    G_lans[i].nodes[j]["port_server_version"].append(port_server_version)
                account = set()
                for d in range(random.randint(1,2)):
                    account.add((random.choice(user),random.choice(password),random.choice(["root","admin","user"])))
                G_lans[i].nodes[j]["account"] = list(account)
            else:
                G_lans[i].nodes[j]["cve"].append(k)

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
    domain_server = []
    for i in G_switchs:
        G_switchs.nodes[i]["type"] = "switch"#从交换机相关漏洞中产生cve
        G_switchs.nodes[i]["lan_id"] = "other"
        G_switchs.nodes[i]["port_server_version"] = []
        G_switchs.nodes[i]["system"] = random.choice(["os_windows","os_linux","os_ios","os_mac","os_unix"])
        if random.random() < 0.2:
            domain_server.append(i)
            #是域交换机
            G_switchs.nodes[i]["system"] = "os_windows"
            domain_cve = random.choice(all_type_list["domain"])
            G_switchs.nodes[i]["cve"] = domain_switch_cve(domain_cve)
            G_switchs.nodes[i]["software_version"] = []
            for m in G_switchs.nodes[i]["cve"]:
                #G.append(m)
                if len(all_cve[m]["affectedversion"]) != 0:
                    version = random.choice(all_cve[m]["affectedversion"])
                G_switchs.nodes[i]["software_version"].append(version)
            account = random.randint(1,3)
            #设置域交换机的账户
            G_switchs.nodes[i]["account"] = []
            domain_account = (random.choice(user),random.choice(password),"domain")
            account = random.randint(1,2)
            for j in range(account):
                G_switchs.nodes[i]["account"].append((random.choice(user),random.choice(password),random.choice(["root","admin","user"])))
        else:#非域控交换机，普通交换机
            G_switchs.nodes[i]["cve"] = common_switch_cve(G_switchs.nodes[i]["system"])
            G_switchs.nodes[i]["software_version"] = []
            for m in G_switchs.nodes[i]["cve"]:
                #G.append(m)
                if len(all_cve[m]["affectedversion"]) != 0:
                    version = random.choice(all_cve[m]["affectedversion"])
                G_switchs.nodes[i]["software_version"].append(version)
            #设置普通交换机的账户
            account = random.randint(1,2)
            G_switchs.nodes[i]["account"] = []
            for j in range(account):
                G_switchs.nodes[i]["account"].append((random.choice(user),random.choice(password),random.choice(["root","admin","user"])))
    # Host_work = random.sample(list(all_servers),int(0.3*len(all_servers)))

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
    sorted_nodes = sorted(G.nodes())
    pro_type = random.random()
    for i in all_servers:
        is_domain = False
        G.nodes[i]["type"] = "server"
        #首先判断这个节点是不是已经被设置过属性了
        Lan_id_cve = {}
        if "account" not in G.nodes[i].keys():
            #说明这个节点没有设置过属性
            G.nodes[i]["account"] = []
            if len(set(G.neighbors(i)) & set(domain_server)) != 0:
                is_domain = True
                doamin_switch = list(set(G.neighbors(i)) & set(domain_server))[0]
                for h in G.nodes[doamin_switch]["account"]:
                    if h[2] == "domain":
                        domain_account = h
                        break
                for m in G.nodes[doamin_switch]["cve"]:
                    if m in all_type_list["domain"]:
                        domain_cve = m
                        break
            if is_domain:
                G.nodes[i]["system"] = "os_windows"
                G.nodes[i]["software_version"] = []
                G.nodes[i]["port_server_version"] = []
                domain_host_cve_,domain_host_port_cve_ = domain_host_cve(domain_cve)
                G.nodes[i]["cve"] = list(domain_host_cve_+domain_host_port_cve_)#域主机的漏洞全部重新设置
                for m in domain_host_cve_:
                    if len(all_cve[m]["affectedversion"]) != 0:
                        version = random.choice(all_cve[m]["affectedversion"])
                    G.nodes[i]["software_version"].append(version)
                ports = copy.deepcopy(ports_)
                for g in domain_host_port_cve_:
                    if len(all_cve[g]["affectedversion"]) != 0:
                        version = random.choice(all_cve[g]["affectedversion"])
                        port = random.choice(ports)
                        ports.remove(port)
                        port_server_version = (str(port),version[0],version[1])
                    G.nodes[i]["port_server_version"].append(port_server_version)
                account = set()
                account.add(domain_account)
                for d in range(random.randint(1,2)):
                    account.add((random.choice(user),random.choice(password),random.choice(["root","admin","user"])))
                G.nodes[i]["account"] = list(account)
            elif pro_type < 0.7 and is_domain == False:
                #是普通主机
                common_host_cve_,common_host_port_cve_ = common_host_cve(G.nodes[i]["system"])
                if random.random() > pro:#删除已经存在的漏洞
                    G.nodes[i]["cve"] = list(common_host_cve_+common_host_port_cve_)
                else:#在原来漏洞的基础上加上新的漏洞
                    G.nodes[i]["cve"] = list(set(G.nodes[i]["cve"]+common_host_cve_+common_host_port_cve_))
                G.nodes[i]["software_version"] = []
                for m in list(set(G.nodes[i]["cve"]+common_host_cve_)):
                    if len(all_cve[m]["affectedversion"]) != 0:
                        version = random.choice(all_cve[m]["affectedversion"])
                    G.nodes[i]["software_version"].append(version)
                ports = copy.deepcopy(ports_)
                for g in common_host_port_cve_:
                    if len(all_cve[g]["affectedversion"]) != 0:
                        version = random.choice(all_cve[g]["affectedversion"])
                        port = random.choice(ports)
                        ports.remove(port)
                        port_server_version = (str(port),version[0],version[1])
                    G.nodes[i]["port_server_version"].append(port_server_version)
                account = set()
                for d in range(random.randint(1,2)):
                    account.add((random.choice(user),random.choice(password),random.choice(["root","admin","user"])))
                G.nodes[i]["account"] = list(account)
            elif pro_type>0.7 and pro_type<0.8 and is_domain == False:
                #是防火墙
                firewall_cve_,firewall_port_cve_ = firewall_cve(G.nodes[i]["system"])
                if random.random() > pro:#删除已经存在的漏洞
                    G.nodes[i]["cve"] = list(firewall_cve_+firewall_port_cve_)
                else:#在原来漏洞的基础上加上新的漏洞
                    G.nodes[i]["cve"] = list(set(G.nodes[i]["cve"]+firewall_cve_+firewall_port_cve_))
                G.nodes[i]["software_version"] = []
                for m in list(set(G.nodes[i]["cve"]+firewall_cve_)):
                    if len(all_cve[m]["affectedversion"]) != 0:
                        version = random.choice(all_cve[m]["affectedversion"])
                    G.nodes[i]["software_version"].append(version)
                ports = copy.deepcopy(ports_)
                for g in firewall_port_cve_:
                    if len(all_cve[g]["affectedversion"]) != 0:
                        version = random.choice(all_cve[g]["affectedversion"])
                        port = random.choice(ports)
                        ports.remove(port)
                        port_server_version = (str(port),version[0],version[1])
                    G.nodes[i]["port_server_version"].append(port_server_version)
                account = set()
                for d in range(random.randint(1,2)):
                    account.add((random.choice(user),random.choice(password),random.choice(["root","admin","user"])))
                G.nodes[i]["account"] = list(account)
            else:
                #是数据库
                common_database_cve_,common_database_port_cve_ = common_database_cve(G.nodes[i]["system"])
                if random.random() > pro:#删除已经存在的漏洞
                    G.nodes[i]["cve"] = list(common_database_cve_+common_database_port_cve_)
                else:#在原来漏洞的基础上加上新的漏洞
                    G.nodes[i]["cve"] = list(set(G.nodes[i]["cve"]+common_database_cve_+common_database_port_cve_))
                G.nodes[i]["software_version"] = []
                for m in list(set(G.nodes[i]["cve"]+common_database_cve_)):
                    if len(all_cve[m]["affectedversion"]) != 0:
                        version = random.choice(all_cve[m]["affectedversion"])
                    G.nodes[i]["software_version"].append(version)
                ports = copy.deepcopy(ports_)
                for g in common_database_port_cve_:
                    if len(all_cve[g]["affectedversion"]) != 0:
                        version = random.choice(all_cve[g]["affectedversion"])
                        port = random.choice(ports)
                        ports.remove(port)
                        port_server_version = (str(port),version[0],version[1])
                    G.nodes[i]["port_server_version"].append(port_server_version)
                account = set()
                for d in range(random.randint(1,2)):
                    account.add((random.choice(user),random.choice(password),random.choice(["root","admin","user"])))
                G.nodes[i]["account"] = list(account)
    
    # G_number = set_node_attribute(G, defense_type)
    G_number = copy.deepcopy(G)
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
    # defense_type = 1
    defense_type = 2
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
    for c in range(10):
        pro = 0.65#同一个局域网内部的节点哟多大的可能性拥有同一个cve
        # np.random.seed(2077)
        if static == 1:#静态网络
            graph = partitioned_layered_garph_generatin(layers,total,layers_percent,Lan_num,switchs_percent,pro,defense_type)
            z = (f"./authentic_net/partitioned_layered/static/{len(graph.nodes())}_defensetype_{defense_type}_net{c}.gpickle")
            with open(z, 'wb') as f:
                pickle.dump(graph, f, pickle.HIGHEST_PROTOCOL)
        #print(graph.nodes(data = True))
        #nx.write_gpickle(graph, "test_1000_2.gpickle")
        else:#动态网络
            t_end = 1000
            Gy_graphs = Dy_partitioned_layered_garph_generatin(layers,total,layers_percent,Lan_num,switchs_percent,pro,defense_type, T = t_end)
            for i in range(len(Gy_graphs)):
                z = (f"./authentic_net/partitioned_layered/dynamic/{len(Gy_graphs[0].nodes())}_defensetype_{defense_type}_net{c}/t{i}.gpickle")
                os.makedirs(os.path.dirname(z), exist_ok=True)
                with open(z, 'wb') as f:
                    pickle.dump(Gy_graphs[i], f, pickle.HIGHEST_PROTOCOL)
        
