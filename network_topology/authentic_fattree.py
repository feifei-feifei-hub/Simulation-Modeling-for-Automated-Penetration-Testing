import networkx as nx
import random
import matplotlib.pyplot as plt
import os
import copy
import pickle
import pandas as pd
import json
from authentic_utils import domain_switch_cve,domain_host_cve,firewall_cve,common_host_cve,common_switch_cve,common_database_cve,commen_change,host_work_off,host_error_off,host_work_on,host_error_on,set_node_attribute

def generate_fat_tree(k,pro):
    user = []
    with open('/root/feifei/8_network_generator/data_cve/user.txt', 'r', encoding='utf-8') as file:
        for line in file:
            user.append(line.strip()) 
    password = []
    with open('/root/feifei/8_network_generator/data_cve/pass.txt', 'r', encoding='utf-8') as file:
        for line in file:
            password.append(line.strip())
    with open('/root/feifei/8_network_generator/data_cve/eng_all_type_list.json', 'r', encoding='utf-8') as file:
        all_type_list = json.load(file)
    all_cve = {}
    
    df = pd.read_excel("/root/feifei/8_network_generator/data_cve/all_cve_cvss_epss.xlsx")
    for index, row in df.iterrows():
        cve_id = row['CVE_ID']  
        values = row.drop('CVE_ID').to_dict()  


        for key, value in values.items():
            if isinstance(value, str) and value.startswith('[') and value.endswith(']'):
 
                values[key] = eval(value)


        all_cve[cve_id] = values
    ports_ = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443, 8888, 9000, 10000, 27017, 27018,
    161, 162, 389, 636, 1433, 1434, 1521, 2049, 2222, 3306, 3389, 5432,
    5900, 5984, 6379, 7001, 8000, 8008, 8081, 8088, 8090, 8443, 8888, 9090,
    9200, 9300, 11211, 27017, 27018, 28017, 50000, 50030, 50060, 50070,
    50075, 50090, 60010, 60030]
    G = nx.Graph()
    num_core_switches = (k // 2) ** 2
    num_agg_switches = k * (k // 2)
    num_edge_switches = k * (k // 2)
    num_servers = num_edge_switches * (k // 2)
    num_nodes = num_core_switches + num_agg_switches + num_edge_switches + num_servers

    # Add core switches
    for i in range(num_core_switches):
        G.add_node('c{}'.format(i), type='switch')
    for i in range(num_agg_switches):
        G.add_node(f'a{i}', type='switch')

    for i in range(num_edge_switches):
        G.add_node(f'e{i}', type='switch')



    for i in range(num_servers):
        G.add_node(f's{i}', type='server')

    for core_id in range(num_core_switches):
        pod_group = core_id // (k // 2)
        for agg_id in range(pod_group * (k//2), (pod_group + 1) * (k//2)):
            G.add_edge(f'c{core_id}', f'a{agg_id}')
    # for i in range(num_core_switches):
    #     for j in range(num_agg_switches):
    #         if j // (k // 2) == i // (k // 2):
    #             G.add_edge('c{}'.format(i), 'a{}'.format(j))

    # Connect aggregation switches to edge switches
    for agg_id in range(num_agg_switches):
        pod = agg_id // (k//2)  # 汇聚交换机所属的 Pod
        edge_start = pod * (k//2)
        for edge_id in range(edge_start, edge_start + (k//2)):
            G.add_edge(f'a{agg_id}', f'e{edge_id}')
    # for i in range(num_agg_switches):
    #     for j in range(num_edge_switches):
    #         if j // (k // 2) == i % (k // 2):
    #             G.add_edge('a{}'.format(i - num_core_switches), 'e{}'.format(j))

    # Connect edge switches to servers
    for edge_id in range(num_edge_switches):
        server_start = edge_id * (k//2)
        for server_offset in range(k//2):
            server_id = server_start + server_offset
            G.add_edge(f'e{edge_id}', f's{server_id}')
    # for i in range(num_edge_switches):
    #     for j in range(k // 2):
    #         G.add_edge('e{}'.format(i - num_core_switches - num_agg_switches), 's{}'.format((i - num_core_switches - num_agg_switches) * (k // 2) + j))

    all_switches = {n for n in G.nodes() if G.nodes[n]['type'] == 'switch'}
    all_servers = {n for n in G.nodes() if G.nodes[n]['type'] == 'server'}
    sorted_nodes = sorted(G.nodes())
    node_mapping = {node: idx  for idx, node in enumerate(sorted_nodes)}
    G2 = nx.Graph()
    G2.add_nodes_from(node_mapping.values())
    all_nodes = set(G2.nodes())
    all_switches = set([node_mapping[node] for node in all_switches])
    all_servers = all_nodes - all_switches

    domain_server = []
    for i in all_switches:
        G2.nodes[i]["type"] = "switch"
        G2.nodes[i]["lan_id"] = "other"
        G2.nodes[i]["port_server_version"] = []
        G2.nodes[i]["system"] = random.choice(["os_windows","os_linux","os_ios","os_mac","os_unix"])#all_cve,all_type,all_type_list

        if random.random() < 0.2:
            domain_server.append(i)

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

            G2.nodes[i]["account"] = []
            domain_account = (random.choice(user),random.choice(password),"domain")
            G2.nodes[i]["account"].append(domain_account)
            account = random.randint(1,2)
            for j in range(account):
                G2.nodes[i]["account"].append((random.choice(user),random.choice(password),random.choices(["root","admin","user"], weights=[0.3, 0.2, 0.5], k=1)[0]))
        else:
            G2.nodes[i]["cve"] = common_switch_cve(G2.nodes[i]["system"])
            G2.nodes[i]["software_version"] = []
            for m in G2.nodes[i]["cve"]:
                #G.append(m)
                if len(all_cve[m]["affectedversion"]) != 0:
                    version = random.choice(all_cve[m]["affectedversion"])
                G2.nodes[i]["software_version"].append(version)

            account = random.randint(1,2)
            G2.nodes[i]["account"] = []
            for j in range(account):
                G2.nodes[i]["account"].append((random.choice(user),random.choice(password),random.choices(["root","admin","user"], weights=[0.3, 0.2, 0.5], k=1)[0]))
    Host_work = random.sample(list(all_servers),int(0.3*len(all_servers)))
    for u, v in G.edges():
        G2.add_edge(node_mapping[u], node_mapping[v])
    Lan_id = []
    Lan_id_cve = {}


    for i in all_servers:
        is_domain = False
        G2.nodes[i]["type"] = "server"
        G2.nodes[i]["account"] = []
        G2.nodes[i]["port_server_version"] = []
        for j in G2.neighbors(i):
            if j in all_switches:
                G2.nodes[i]["lan_id"] = str(j)
                if str(j) not in Lan_id:
                    Lan_id.append(str(j))
                    Lan_id_cve[str(j)] = random.choice(all_type_list["soft"])
                break
        G2.nodes[i]["system"] = random.choice(["os_windows","os_linux","os_ios","os_mac","os_unix"])
        pro_type = random.random()
        if len(set(G2.neighbors(i)) & set(domain_server)) != 0:#
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
                account.add((random.choice(user),random.choice(password),random.choices(["root","admin","user"], weights=[0.3, 0.2, 0.5], k=1)[0]))
            G2.nodes[i]["account"] = list(account)
        elif pro_type < 0.7 and is_domain == False:
            common_host_cve_,common_host_port_cve_ = common_host_cve(G2.nodes[i]["system"])
            if random.random() < pro:
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
                account.add((random.choice(user),random.choice(password),random.choices(["root","admin","user"], weights=[0.3, 0.2, 0.5], k=1)[0]))
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
                account.add((random.choice(user),random.choice(password),random.choices(["root","admin","user"], weights=[0.3, 0.2, 0.5], k=1)[0]))
            G2.nodes[i]["account"] = list(account)
        else:
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
                account.add((random.choice(user),random.choice(password),random.choices(["root","admin","user"], weights=[0.3, 0.2, 0.5], k=1)[0]))
            G2.nodes[i]["account"] = list(account)
    return G2

def Dy_generate_fat_tree(k,pro,T):
    user = []
    with open('/root/feifei/8_network_generator/data_cve/user.txt', 'r', encoding='utf-8') as file:
        for line in file:
            user.append(line.strip()) 
    password = []
    with open('/root/feifei/8_network_generator/data_cve/pass.txt', 'r', encoding='utf-8') as file:
        for line in file:
            password.append(line.strip())
    with open('/root/feifei/8_network_generator/data_cve/eng_all_type_list.json', 'r', encoding='utf-8') as file:
        all_type_list = json.load(file)
    all_cve = {}
    
    df = pd.read_excel("/root/feifei/8_network_generator/data_cve/all_cve_cvss_epss.xlsx")
    for index, row in df.iterrows():
        cve_id = row['CVE_ID']  
        values = row.drop('CVE_ID').to_dict()  

        for key, value in values.items():
            if isinstance(value, str) and value.startswith('[') and value.endswith(']'):
                values[key] = eval(value)

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
    num_core_switches = (k // 2) ** 2
    num_agg_switches = k * (k // 2)
    num_edge_switches = k * (k // 2)
    num_servers = num_edge_switches * (k // 2)
    num_nodes = num_core_switches + num_agg_switches + num_edge_switches + num_servers

    # Add core switches
    for i in range(num_core_switches):
        G.add_node('c{}'.format(i), type='switch')

    # Add aggregation switches
    # for i in range(num_core_switches, num_core_switches + num_agg_switches):
    #     G.add_node('a{}'.format(i - num_core_switches), type='switch')
    for i in range(num_agg_switches):
        G.add_node(f'a{i}', type='switch')

    for i in range(num_edge_switches):
        G.add_node(f'e{i}', type='switch')

    for i in range(num_servers):
        G.add_node(f's{i}', type='server')
    
    # Connect core switches to aggregation switches 
    for core_id in range(num_core_switches):
        pod_group = core_id // (k // 2) 
        for agg_id in range(pod_group * (k//2), (pod_group + 1) * (k//2)):
            G.add_edge(f'c{core_id}', f'a{agg_id}')
    
    # Connect aggregation switches to edge switches
    for agg_id in range(num_agg_switches):
        pod = agg_id // (k//2)  
        edge_start = pod * (k//2)
        for edge_id in range(edge_start, edge_start + (k//2)):
            G.add_edge(f'a{agg_id}', f'e{edge_id}')
    

    # Connect edge switches to servers
    for edge_id in range(num_edge_switches):
        server_start = edge_id * (k//2)
        for server_offset in range(k//2):
            server_id = server_start + server_offset
            G.add_edge(f'e{edge_id}', f's{server_id}')
    
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
    domain_server = []
    for i in all_switches:
        G2.nodes[i]["type"] = "switch"
        G2.nodes[i]["lan_id"] = "other"
        G2.nodes[i]["port_server_version"] = []
        G2.nodes[i]["system"] = random.choice(["os_windows","os_linux","os_ios","os_mac","os_unix"])#all_cve,all_type,all_type_list
        if random.random() < 0.2:
            domain_server.append(i)
            
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
            G2.nodes[i]["account"] = []
            domain_account = (random.choice(user),random.choice(password),"domain")
            G2.nodes[i]["account"].append(domain_account)
            account = random.randint(1,2)
            for j in range(account):
                G2.nodes[i]["account"].append((random.choice(user),random.choice(password),random.choices(["root","admin","user"], weights=[0.3, 0.2, 0.5], k=1)[0]))
        else:
            G2.nodes[i]["cve"] = common_switch_cve(G2.nodes[i]["system"])
            G2.nodes[i]["software_version"] = []
            for m in G2.nodes[i]["cve"]:
                #G.append(m)
                if len(all_cve[m]["affectedversion"]) != 0:
                    version = random.choice(all_cve[m]["affectedversion"])
                G2.nodes[i]["software_version"].append(version)
            
            account = random.randint(1,2)
            G2.nodes[i]["account"] = []
            for j in range(account):
                G2.nodes[i]["account"].append((random.choice(user),random.choice(password),random.choices(["root","admin","user"], weights=[0.3, 0.2, 0.5], k=1)[0]))
    Host_work = random.sample(list(all_servers),int(0.3*len(all_servers)))
    for u, v in G.edges():
        G2.add_edge(node_mapping[u], node_mapping[v])
    Lan_id = []
    Lan_id_cve = {}


    for i in all_servers:
        is_domain = False
        G2.nodes[i]["type"] = "server"
        G2.nodes[i]["account"] = []
        G2.nodes[i]["port_server_version"] = []
        for j in G2.neighbors(i):
            if j in all_switches:
                G2.nodes[i]["lan_id"] = str(j)
                if str(j) not in Lan_id:
                    Lan_id.append(str(j))
                    Lan_id_cve[str(j)] = random.choice(all_type_list["soft"])
                break
        G2.nodes[i]["system"] = random.choice(["os_windows","os_linux","os_ios","os_mac","os_unix"])
        pro_type = random.random()
        if len(set(G2.neighbors(i)) & set(domain_server)) != 0:
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
                account.add((random.choice(user),random.choice(password),random.choices(["root","admin","user"], weights=[0.3, 0.2, 0.5], k=1)[0]))
            G2.nodes[i]["account"] = list(account)
        elif pro_type < 0.7 and is_domain == False:
            common_host_cve_,common_host_port_cve_ = common_host_cve(G2.nodes[i]["system"])
            if random.random() < pro:
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
                account.add((random.choice(user),random.choice(password),random.choices(["root","admin","user"], weights=[0.3, 0.2, 0.5], k=1)[0]))
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
                account.add((random.choice(user),random.choice(password),random.choices(["root","admin","user"], weights=[0.3, 0.2, 0.5], k=1)[0]))
            G2.nodes[i]["account"] = list(account)
        else:
            
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
                account.add((random.choice(user),random.choice(password),random.choices(["root","admin","user"], weights=[0.3, 0.2, 0.5], k=1)[0]))
            G2.nodes[i]["account"] = list(account)
    
    G_number = copy.deepcopy(G2)
    is_work = True
    Dy_G.append(G_number)
    # G_0 = G_number.copy()
    G_0 = copy.deepcopy(G_number)
    for t in range(1, T):
        # G_ = Dy_G[t-1].copy()
        G_ = copy.deepcopy(Dy_G[t-1])
        all_nodes_ = set(G_.nodes())
        all_servers_ = all_nodes_ - all_switches
        G_0,G_ = commen_change(G_0,G_, all_nodes_, all_switches, all_servers_)

        
        if t % 12 == 0 and (t // 12) % 2 == 1:
            is_work = False
            G_ = host_work_off(G_, Host_work)
        elif t % 12 == 0 and (t // 12) % 2 == 0:
            is_work = True
            G_ = host_work_on(G_0, G_, Host_work,t_errors)
        if is_work:
            host_candidata = {n for n in G_.nodes() if G_.nodes[n]['type'] == 'server'}
        else:
            host_candidata = {n for n in G_.nodes() if G_.nodes[n]['type'] == 'server'} - set(Host_work)
        real_error = []
        for h in host_candidata:
            if random.random() < 0.001:
                G_ = host_error_off(G_, [h])
                real_error.append(h)
        if len(real_error) != 0:
            t_errors.append([t,real_error])
        for m in t_errors:
            if m[0] + 72 == t:
                G_ = host_error_on(G_0, G_, m[1])
                t_errors.remove(m)
        Dy_G.append(G_)
    return Dy_G
    

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
    #defense_type = 1,2,3
    # defense_type = 1
    # defense_type = 2
    # defense_type = 3

    static = 1
    #What is the likelihood that nodes within the same local area network share the same vulnerability
    pro = 0.65

    #node_num = 10
    # K = 4
    
    #node_num = 100
    # K = 6
    #node_num = 1000
    K = 14
    for c in range(1):
        if static == 1:#static network
            graph = generate_fat_tree(K,pro)
            z = (f"./authentic_net/fattree/static/{len(graph.nodes())}_fattree{c}.gpickle")
            # z = (f"./authentic_net/test/static/{len(graph.nodes())}_fattree{c}.gpickle")
            os.makedirs(os.path.dirname(z), exist_ok=True)
            with open(z, 'wb') as f:
                pickle.dump(graph, f, pickle.HIGHEST_PROTOCOL)
        else:#dynamic network
            t_end = 100
            Gy_graphs = Dy_generate_fat_tree(K,pro, T = t_end)
            for i in range(len(Gy_graphs)):
                z = (f"./authentic_net/fattree/dynamic/{len(Gy_graphs[0].nodes())}_fattree{c}/t{i}.gpickle")
                # z = (f"./authentic_net/test/static/{len(graph.nodes())}_fattree{c}.gpickle")
                os.makedirs(os.path.dirname(z), exist_ok=True)
                with open(z, 'wb') as f:
                    pickle.dump(Gy_graphs[i], f, pickle.HIGHEST_PROTOCOL)

