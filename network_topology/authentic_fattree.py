import networkx as nx
import random
import matplotlib.pyplot as plt
import os
import copy
import pickle
import pandas as pd
import json
from authentic_utils import domain_switch_cve,domain_host_cve,firewall_cve,common_host_cve,common_switch_cve,common_database_cve,commen_change,host_work_off,host_error_off,host_work_on,host_error_on,set_node_attribute

def generate_fat_tree(k,defense_type,pro):
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
    G = nx.Graph()
    num_core_switches = (k // 2) ** 2#核心交换机数量
    num_agg_switches = k * (k // 2)#汇聚交换机数量
    num_edge_switches = k * (k // 2)#接入交换机数量
    num_servers = num_edge_switches * (k // 2)#主机数量
    num_nodes = num_core_switches + num_agg_switches + num_edge_switches + num_servers#总节点数量

    # Add core switches
    for i in range(num_core_switches):
        G.add_node('c{}'.format(i), type='switch')
    for i in range(num_agg_switches):
        G.add_node(f'a{i}', type='switch')
    # 添加边缘交换机（e0, e1, ..., e_{num_edge-1}）
    for i in range(num_edge_switches):
        G.add_node(f'e{i}', type='switch')
    #交换机全部设置完成

     # 添加服务器（s0, s1, ..., s_{num_servers-1}）
    for i in range(num_servers):
        G.add_node(f's{i}', type='server')
    
    # Connect core switches to aggregation switches 将核心交换机连接到汇聚交换机
    for core_id in range(num_core_switches):
        pod_group = core_id // (k // 2)  # 每个核心交换机对应一个 Pod 组
        for agg_id in range(pod_group * (k//2), (pod_group + 1) * (k//2)):
            G.add_edge(f'c{core_id}', f'a{agg_id}')
    # for i in range(num_core_switches):
    #     for j in range(num_agg_switches):
    #         if j // (k // 2) == i // (k // 2):
    #             G.add_edge('c{}'.format(i), 'a{}'.format(j))

    # Connect aggregation switches to edge switches将汇聚交换机连接到接入交换机
    for agg_id in range(num_agg_switches):
        pod = agg_id // (k//2)  # 汇聚交换机所属的 Pod
        edge_start = pod * (k//2)
        for edge_id in range(edge_start, edge_start + (k//2)):
            G.add_edge(f'a{agg_id}', f'e{edge_id}')
    # for i in range(num_agg_switches):
    #     for j in range(num_edge_switches):
    #         if j // (k // 2) == i % (k // 2):
    #             G.add_edge('a{}'.format(i - num_core_switches), 'e{}'.format(j))

    # Connect edge switches to servers将接入交换机连接到主机
    for edge_id in range(num_edge_switches):
        server_start = edge_id * (k//2)
        for server_offset in range(k//2):
            server_id = server_start + server_offset
            G.add_edge(f'e{edge_id}', f's{server_id}')
    # for i in range(num_edge_switches):
    #     for j in range(k // 2):
    #         G.add_edge('e{}'.format(i - num_core_switches - num_agg_switches), 's{}'.format((i - num_core_switches - num_agg_switches) * (k // 2) + j))
    # #将网络图进行统一类型映射
    all_switches = {n for n in G.nodes() if G.nodes[n]['type'] == 'switch'}
    all_servers = {n for n in G.nodes() if G.nodes[n]['type'] == 'server'}
    sorted_nodes = sorted(G.nodes())
    node_mapping = {node: idx  for idx, node in enumerate(sorted_nodes)}
    G2 = nx.Graph()
    G2.add_nodes_from(node_mapping.values())
    all_nodes = set(G2.nodes())
    all_switches = set([node_mapping[node] for node in all_switches])
    all_servers = all_nodes - all_switches
    #对所有的交换机节点进行属性设置
    domain_server = []
    for i in all_switches:
        G2.nodes[i]["type"] = "switch"
        G2.nodes[i]["lan_id"] = "other"
        G2.nodes[i]["port_server_version"] = []
        G2.nodes[i]["system"] = random.choice(["os_windows","os_linux","os_ios","os_mac","os_unix"])#all_cve,all_type,all_type_list
        #判断当前交换机是否为域交换机
        if random.random() < 0.2:
            domain_server.append(i)
            #是域交换机
            G2.nodes[i]["system"] = "os_windows"
            domain_cve = random.choice(all_type_list["domain"])
            G2.nodes[i]["cve"] = domain_switch_cve(domain_cve)
            G2.nodes[i]["software_version"] = []
            for m in G2.nodes[i]["cve"]:
                #G.append(m)
                if len(all_cve[m]["affectedversion"]) != 0:
                    version = random.choice(all_cve[m]["affectedversion"])
                G2.nodes[i]["software_version"].append(version)
            account = random.randint(1,3)
            #设置域交换机的账户
            G2.nodes[i]["account"] = []
            domain_account = (random.choice(user),random.choice(password),"domain")
            account = random.randint(1,2)
            for j in range(account):
                G2.nodes[i]["account"].append((random.choice(user),random.choice(password),random.choice(["root","admin","user"])))
        else:#非域控交换机，普通交换机
            G2.nodes[i]["cve"] = common_switch_cve(G2.nodes[i]["system"])
            G2.nodes[i]["software_version"] = []
            for m in G2.nodes[i]["cve"]:
                #G.append(m)
                if len(all_cve[m]["affectedversion"]) != 0:
                    version = random.choice(all_cve[m]["affectedversion"])
                G2.nodes[i]["software_version"].append(version)
            #设置普通交换机的账户
            account = random.randint(1,2)
            G2.nodes[i]["account"] = []
            for j in range(account):
                G2.nodes[i]["account"].append((random.choice(user),random.choice(password),random.choice(["root","admin","user"])))
    Host_work = random.sample(list(all_servers),int(0.3*len(all_servers)))
    for u, v in G.edges():
        G2.add_edge(node_mapping[u], node_mapping[v])
    # 为主机设置属性，如果一个节点没有设置属性，那么他就是主机节点
    Lan_id = []
    Lan_id_cve = {}


    for i in all_servers:
        is_domain = False
        G2.nodes[i]["type"] = "server"
        G2.nodes[i]["account"] = []
        G2.nodes[i]["port_server_version"] = []
        #lan_id与该节点所属的交换机的序号相同
        #获取与该节点相连接的交换机节点
        for j in G2.neighbors(i):
            if j in all_switches:
                G2.nodes[i]["lan_id"] = str(j)
                if str(j) not in Lan_id:
                    Lan_id.append(str(j))
                    Lan_id_cve[str(j)] = random.choice(all_type_list["soft"])
                break
        G2.nodes[i]["system"] = random.choice(["os_windows","os_linux","os_ios","os_mac","os_unix"])
        pro_type = random.random()
        #如果这个节点的邻居节点中存在一个域控交换机，那么这个主机就是域主机
        if len(set(G2.neighbors(i)) & set(domain_server)) != 0:#并集存在重合
            #是域主机
            is_domain = True
            doamin_switch = list(set(G2.neighbors(i)) & set(domain_server))[0]
            for h in G2.nodes[doamin_switch]["account"]:
                if h[2] == "domain":
                    domain_account = h
                    break
            for m in G2.nodes[doamin_switch]["cve"]:
                if m in all_type_list["domain"]:
                    domain_cve = m
                    break
        if is_domain:
            #是域主机
            G2.nodes[i]["system"] = "os_windows"
            G2.nodes[i]["software_version"] = []
            G2.nodes[i]["port_server_version"] = []
            domain_host_cve_,domain_host_port_cve_ = domain_host_cve(domain_cve)
            G2.nodes[i]["cve"] = list(domain_host_cve_+domain_host_port_cve_)
            for m in domain_host_cve_:
                if len(all_cve[m]["affectedversion"]) != 0:
                    version = random.choice(all_cve[m]["affectedversion"])
                G2.nodes[i]["software_version"].append(version)
            ports = copy.deepcopy(ports_)
            for m in domain_host_port_cve_:
                if len(all_cve[m]["affectedversion"]) != 0:
                    version = random.choice(all_cve[m]["affectedversion"])
                    port = random.choice(ports)
                    ports.remove(port)
                    port_server_version = (str(port),version[0],version[1])
                G2.nodes[i]["port_server_version"].append(port_server_version)
            account = set()
            account.add(domain_account)
            for d in range(random.randint(1,2)):
                account.add((random.choice(user),random.choice(password),random.choice(["root","admin","user"])))
            G2.nodes[i]["account"] = list(account)
        elif pro_type < 0.7 and is_domain == False:
            #是普通主机
            common_host_cve_,common_host_port_cve_ = common_host_cve(G2.nodes[i]["system"])
            if random.random() < pro:#有一个公共漏洞
                common_host_cve_.append(Lan_id_cve[G2.nodes[i]["lan_id"]])
            G2.nodes[i]["cve"] = list(common_host_cve_+common_host_port_cve_)
            G2.nodes[i]["software_version"] = []
            for m in common_host_cve_:
                if len(all_cve[m]["affectedversion"]) != 0:
                    version = random.choice(all_cve[m]["affectedversion"])
                G2.nodes[i]["software_version"].append(version)
            ports = copy.deepcopy(ports_)
            for g in common_host_port_cve_:
                if len(all_cve[g]["affectedversion"]) != 0:
                    version = random.choice(all_cve[g]["affectedversion"])
                    port = random.choice(ports)
                    ports.remove(port)
                    port_server_version = (str(port),version[0],version[1])
                G2.nodes[i]["port_server_version"].append(port_server_version)
            account = set()
            for d in range(random.randint(1,2)):
                account.add((random.choice(user),random.choice(password),random.choice(["root","admin","user"])))
            G2.nodes[i]["account"] = list(account)
        elif pro_type>0.7 and pro_type<0.8 and is_domain == False:
            firewall_cve_,firewall_port_cve_ = firewall_cve(G2.nodes[i]["system"])
            G2.nodes[i]["cve"] = list(firewall_cve_+firewall_port_cve_)
            G2.nodes[i]["software_version"] = []
            for m in firewall_cve_:
                if len(all_cve[m]["affectedversion"]) != 0:
                    version = random.choice(all_cve[m]["affectedversion"])
                G2.nodes[i]["software_version"].append(version)
            ports = copy.deepcopy(ports_)
            for g in firewall_port_cve_:
                if len(all_cve[g]["affectedversion"]) != 0:
                    version = random.choice(all_cve[g]["affectedversion"])
                    port = random.choice(ports)
                    ports.remove(port)
                    port_server_version = (str(port),version[0],version[1])
                G2.nodes[i]["port_server_version"].append(port_server_version)
            account = set()
            for d in range(random.randint(1,2)):
                account.add((random.choice(user),random.choice(password),random.choice(["root","admin","user"])))
            G2.nodes[i]["account"] = list(account)
        else:
            #是数据库或服务器
            common_database_cve_,common_database_port_cve_ = common_database_cve(G2.nodes[i]["system"])
            G2.nodes[i]["cve"] = list(common_database_cve_+common_database_port_cve_)
            G2.nodes[i]["software_version"] = []
            for m in common_database_cve_:
                if len(all_cve[m]["affectedversion"]) != 0:
                    version = random.choice(all_cve[m]["affectedversion"])
                G2.nodes[i]["software_version"].append(version)
            ports = copy.deepcopy(ports_)
            for g in common_database_port_cve_:
                if len(all_cve[g]["affectedversion"]) != 0:
                    version = random.choice(all_cve[g]["affectedversion"])
                    port = random.choice(ports)
                    ports.remove(port)
                    port_server_version = (str(port),version[0],version[1])
                G2.nodes[i]["port_server_version"].append(port_server_version)
            account = set()
            for d in range(random.randint(1,2)):
                account.add((random.choice(user),random.choice(password),random.choice(["root","admin","user"])))
            G2.nodes[i]["account"] = list(account)
    return G2#生成了网络图

def Dy_generate_fat_tree(k,defense_type,pro,T):
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
    Dy_G = []
    t_errors = []
    G = nx.Graph()
    num_core_switches = (k // 2) ** 2#核心交换机数量
    num_agg_switches = k * (k // 2)#汇聚交换机数量
    num_edge_switches = k * (k // 2)#接入交换机数量
    num_servers = num_edge_switches * (k // 2)#主机数量
    num_nodes = num_core_switches + num_agg_switches + num_edge_switches + num_servers#总节点数量

    # Add core switches
    for i in range(num_core_switches):
        G.add_node('c{}'.format(i), type='switch')

    # Add aggregation switches
    # for i in range(num_core_switches, num_core_switches + num_agg_switches):
    #     G.add_node('a{}'.format(i - num_core_switches), type='switch')
    for i in range(num_agg_switches):
        G.add_node(f'a{i}', type='switch')

    # 添加边缘交换机（e0, e1, ..., e_{num_edge-1}）
    for i in range(num_edge_switches):
        G.add_node(f'e{i}', type='switch')

     # 添加服务器（s0, s1, ..., s_{num_servers-1}）
    for i in range(num_servers):
        G.add_node(f's{i}', type='server')
    
    # Connect core switches to aggregation switches 将核心交换机连接到汇聚交换机
    for core_id in range(num_core_switches):
        pod_group = core_id // (k // 2)  # 每个核心交换机对应一个 Pod 组
        for agg_id in range(pod_group * (k//2), (pod_group + 1) * (k//2)):
            G.add_edge(f'c{core_id}', f'a{agg_id}')
    
    # Connect aggregation switches to edge switches将汇聚交换机连接到接入交换机
    for agg_id in range(num_agg_switches):
        pod = agg_id // (k//2)  # 汇聚交换机所属的 Pod
        edge_start = pod * (k//2)
        for edge_id in range(edge_start, edge_start + (k//2)):
            G.add_edge(f'a{agg_id}', f'e{edge_id}')
    

    # Connect edge switches to servers将接入交换机连接到主机
    for edge_id in range(num_edge_switches):
        server_start = edge_id * (k//2)
        for server_offset in range(k//2):
            server_id = server_start + server_offset
            G.add_edge(f'e{edge_id}', f's{server_id}')
    
    # #将网络图进行统一类型映射
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
    # G_number = set_node_attribute(G2, defense_type)
    #对所有的交换机节点进行属性设置
    domain_server = []
    for i in all_switches:
        G2.nodes[i]["type"] = "switch"
        G2.nodes[i]["lan_id"] = "other"
        G2.nodes[i]["port_server_version"] = []
        G2.nodes[i]["system"] = random.choice(["os_windows","os_linux","os_ios","os_mac","os_unix"])#all_cve,all_type,all_type_list
        #判断当前交换机是否为域交换机
        if random.random() < 0.2:
            domain_server.append(i)
            #是域交换机
            G2.nodes[i]["system"] = "os_windows"
            domain_cve = random.choice(all_type_list["domain"])
            G2.nodes[i]["cve"] = domain_switch_cve(domain_cve)
            G2.nodes[i]["software_version"] = []
            for m in G2.nodes[i]["cve"]:
                #G.append(m)
                if len(all_cve[m]["affectedversion"]) != 0:
                    version = random.choice(all_cve[m]["affectedversion"])
                G2.nodes[i]["software_version"].append(version)
            account = random.randint(1,3)
            #设置域交换机的账户
            G2.nodes[i]["account"] = []
            domain_account = (random.choice(user),random.choice(password),"domain")
            account = random.randint(1,2)
            for j in range(account):
                G2.nodes[i]["account"].append((random.choice(user),random.choice(password),random.choice(["root","admin","user"])))
        else:#非域控交换机，普通交换机
            G2.nodes[i]["cve"] = common_switch_cve(G2.nodes[i]["system"])
            G2.nodes[i]["software_version"] = []
            for m in G2.nodes[i]["cve"]:
                #G.append(m)
                if len(all_cve[m]["affectedversion"]) != 0:
                    version = random.choice(all_cve[m]["affectedversion"])
                G2.nodes[i]["software_version"].append(version)
            #设置普通交换机的账户
            account = random.randint(1,2)
            G2.nodes[i]["account"] = []
            for j in range(account):
                G2.nodes[i]["account"].append((random.choice(user),random.choice(password),random.choice(["root","admin","user"])))
    Host_work = random.sample(list(all_servers),int(0.3*len(all_servers)))
    for u, v in G.edges():
        G2.add_edge(node_mapping[u], node_mapping[v])
    # 为主机设置属性，如果一个节点没有设置属性，那么他就是主机节点
    Lan_id = []
    Lan_id_cve = {}


    for i in all_servers:
        is_domain = False
        G2.nodes[i]["type"] = "server"
        G2.nodes[i]["account"] = []
        G2.nodes[i]["port_server_version"] = []
        #lan_id与该节点所属的交换机的序号相同
        #获取与该节点相连接的交换机节点
        for j in G2.neighbors(i):
            if j in all_switches:
                G2.nodes[i]["lan_id"] = str(j)
                if str(j) not in Lan_id:
                    Lan_id.append(str(j))
                    Lan_id_cve[str(j)] = random.choice(all_type_list["soft"])
                break
        G2.nodes[i]["system"] = random.choice(["os_windows","os_linux","os_ios","os_mac","os_unix"])
        pro_type = random.random()
        #如果这个节点的邻居节点中存在一个域控交换机，那么这个主机就是域主机
        if len(set(G2.neighbors(i)) & set(domain_server)) != 0:#并集存在重合
            #是域主机
            is_domain = True
            doamin_switch = list(set(G2.neighbors(i)) & set(domain_server))[0]
            for h in G2.nodes[doamin_switch]["account"]:
                if h[2] == "domain":
                    domain_account = h
                    break
            for m in G2.nodes[doamin_switch]["cve"]:
                if m in all_type_list["domain"]:
                    domain_cve = m
                    break
        if is_domain:
            #是域主机
            G2.nodes[i]["system"] = "os_windows"
            G2.nodes[i]["software_version"] = []
            G2.nodes[i]["port_server_version"] = []
            domain_host_cve_,domain_host_port_cve_ = domain_host_cve(domain_cve)
            G2.nodes[i]["cve"] = list(domain_host_cve_+domain_host_port_cve_)
            for m in domain_host_cve_:
                if len(all_cve[m]["affectedversion"]) != 0:
                    version = random.choice(all_cve[m]["affectedversion"])
                G2.nodes[i]["software_version"].append(version)
            ports = copy.deepcopy(ports_)
            for m in domain_host_port_cve_:
                if len(all_cve[m]["affectedversion"]) != 0:
                    version = random.choice(all_cve[m]["affectedversion"])
                    port = random.choice(ports)
                    ports.remove(port)
                    port_server_version = (str(port),version[0],version[1])
                G2.nodes[i]["port_server_version"].append(port_server_version)
            account = set()
            account.add(domain_account)
            for d in range(random.randint(1,2)):
                account.add((random.choice(user),random.choice(password),random.choice(["root","admin","user"])))
            G2.nodes[i]["account"] = list(account)
        elif pro_type < 0.7 and is_domain == False:
            #是普通主机
            common_host_cve_,common_host_port_cve_ = common_host_cve(G2.nodes[i]["system"])
            if random.random() < pro:#有一个公共漏洞
                common_host_cve_.append(Lan_id_cve[G2.nodes[i]["lan_id"]])
            G2.nodes[i]["cve"] = list(common_host_cve_+common_host_port_cve_)
            G2.nodes[i]["software_version"] = []
            for m in common_host_cve_:
                if len(all_cve[m]["affectedversion"]) != 0:
                    version = random.choice(all_cve[m]["affectedversion"])
                G2.nodes[i]["software_version"].append(version)
            ports = copy.deepcopy(ports_)
            for g in common_host_port_cve_:
                if len(all_cve[g]["affectedversion"]) != 0:
                    version = random.choice(all_cve[g]["affectedversion"])
                    port = random.choice(ports)
                    ports.remove(port)
                    port_server_version = (str(port),version[0],version[1])
                G2.nodes[i]["port_server_version"].append(port_server_version)
            account = set()
            for d in range(random.randint(1,2)):
                account.add((random.choice(user),random.choice(password),random.choice(["root","admin","user"])))
            G2.nodes[i]["account"] = list(account)
        elif pro_type>0.7 and pro_type<0.8 and is_domain == False:
            firewall_cve_,firewall_port_cve_ = firewall_cve(G2.nodes[i]["system"])
            G2.nodes[i]["cve"] = list(firewall_cve_+firewall_port_cve_)
            G2.nodes[i]["software_version"] = []
            for m in firewall_cve_:
                if len(all_cve[m]["affectedversion"]) != 0:
                    version = random.choice(all_cve[m]["affectedversion"])
                G2.nodes[i]["software_version"].append(version)
            ports = copy.deepcopy(ports_)
            for g in firewall_port_cve_:
                if len(all_cve[g]["affectedversion"]) != 0:
                    version = random.choice(all_cve[g]["affectedversion"])
                    port = random.choice(ports)
                    ports.remove(port)
                    port_server_version = (str(port),version[0],version[1])
                G2.nodes[i]["port_server_version"].append(port_server_version)
            account = set()
            for d in range(random.randint(1,2)):
                account.add((random.choice(user),random.choice(password),random.choice(["root","admin","user"])))
            G2.nodes[i]["account"] = list(account)
        else:
            #是数据库或服务器
            common_database_cve_,common_database_port_cve_ = common_database_cve(G2.nodes[i]["system"])
            G2.nodes[i]["cve"] = list(common_database_cve_+common_database_port_cve_)
            G2.nodes[i]["software_version"] = []
            for m in common_database_cve_:
                if len(all_cve[m]["affectedversion"]) != 0:
                    version = random.choice(all_cve[m]["affectedversion"])
                G2.nodes[i]["software_version"].append(version)
            ports = copy.deepcopy(ports_)
            for g in common_database_port_cve_:
                if len(all_cve[g]["affectedversion"]) != 0:
                    version = random.choice(all_cve[g]["affectedversion"])
                    port = random.choice(ports)
                    ports.remove(port)
                    port_server_version = (str(port),version[0],version[1])
                G2.nodes[i]["port_server_version"].append(port_server_version)
            account = set()
            for d in range(random.randint(1,2)):
                account.add((random.choice(user),random.choice(password),random.choice(["root","admin","user"])))
            G2.nodes[i]["account"] = list(account)
    G_number = copy.deepcopy(G2)
    Dy_G.append(G_number)#保存0时刻的网络
    # G_0 = G_number.copy()
    G_0 = copy.deepcopy(G_number)
    for t in range(1, T):
        # G_ = Dy_G[t-1].copy()
        G_ = copy.deepcopy(Dy_G[t-1])
        # 常规变化，随机选择0.02的节点增强或减弱防御能力
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
    #设置生成数值模拟网络类型，defense_type = 1,2,3
    defense_type = 1
    # defense_type = 2
    # defense_type = 3

    # 静态\动态网络的生成及保存
    static = 0
    #同一个局域网内的节点有多大概率拥有同一个漏洞
    pro = 0.65

    #节点规模为10
    K = 4
    
    #节点规模为100
    # K = 6
    #节点规模为1000
    # K = 14
    #生成网络
    for c in range(10):
        if static == 1:#静态网络
            graph = generate_fat_tree(K,defense_type,pro)
            z = (f"./number_net/fattree/static/{len(graph.nodes())}_defensetype_{defense_type}_tree{c}.gpickle")
            with open(z, 'wb') as f:
                pickle.dump(graph, f, pickle.HIGHEST_PROTOCOL)
        else:#动态网络
            t_end = 1000
            Gy_graphs = Dy_generate_fat_tree(K,defense_type,pro, T = t_end)
            for i in range(len(Gy_graphs)):
                z = (f"./number_net/fattree/dynamic/{len(Gy_graphs[0].nodes())}_defensetype_{defense_type}_tree{c}/t{i}.gpickle")
                os.makedirs(os.path.dirname(z), exist_ok=True)
                with open(z, 'wb') as f:
                    pickle.dump(Gy_graphs[i], f, pickle.HIGHEST_PROTOCOL)

