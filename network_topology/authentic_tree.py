import matplotlib.pyplot as plt
import networkx as nx
import random
import math
import json
import copy
import sys,os
import numpy as np
from networkx.readwrite import json_graph
import pickle
import pandas as pd
from authentic_utils import domain_switch_cve,domain_host_cve,firewall_cve,common_host_cve,common_switch_cve,common_database_cve,commen_change,host_work_off,host_error_off,host_work_on,host_error_on,set_node_attribute

sys.path.append(os.getcwd())
# from data_cve.CVE_detail import Read_data   
# The number of core switches: core_switch_num, aggregation switches: aggregation_switch_num, edge switches: edge_switch_num, and hosts: host_num.
# Each core switch connects to aggregation switches: core_aggregation = {0: 6}.
# Each aggregation switch connects to edge switches: aggregation_edge = {0: 2, 1: 2, 2: 2, 3: 2, 4: 2, 5: 2}.
def tree(core_switch_num,core_aggregation, aggregation_switch_num,aggregation_edge,edge_switch_num,host_num,pro):
    user = []
    with open('/root/feifei/8_network_generator/data_cve/user.txt', 'r', encoding='utf-8') as file:
        for line in file:
            user.append(line.strip()) 
    password = []
    with open('/root/feifei/8_network_generator/data_cve/pass.txt', 'r', encoding='utf-8') as file:
        for line in file:
            password.append(line.strip())
    #read all_cve,all_type,all_type_list
    with open('/root/feifei/8_network_generator/data_cve/eng_all_type_list.json', 'r', encoding='utf-8') as file:
        all_type_list = json.load(file)
    #read excel file
    all_cve = {}
    
    df = pd.read_excel("/root/feifei/8_network_generator/data_cve/all_cve_cvss_epss.xlsx")
    for index, row in df.iterrows():
        cve_id = row['CVE_ID']  # Get CVE_ID as key
        values = row.drop('CVE_ID').to_dict()  # Other contents as value

        # Handle fields that may be lists
        for key, value in values.items():
            if isinstance(value, str) and value.startswith('[') and value.endswith(']'):
                # Convert string representation of list to actual list
                values[key] = eval(value)

        # Store CVE_ID and other contents in the dictionary
        all_cve[cve_id] = values
    ports_ = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443, 8888, 9000, 10000, 27017, 27018,
    161, 162, 389, 636, 1433, 1434, 1521, 2049, 2222, 3306, 3389, 5432,
    5900, 5984, 6379, 7001, 8000, 8008, 8081, 8088, 8090, 8443, 8888, 9090,
    9200, 9300, 11211, 27017, 27018, 28017, 50000, 50030, 50060, 50070,
    50075, 50090, 60010, 60030]



    lan_ID = 0  # Used to calculate which LAN ID is being generated
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
        G.add_node(i)  # add core switch
        G_core.add_node(i)
        count += 1
        for j in range(core_aggregation[i]):
            j_count = count
            G_aggregation.add_node(j_count)
            G.add_node(j_count)  # add aggregation switch
            G.add_edge(i,j_count)
            count += 1
            for k in range(aggregation_edge[j]):
                k_count = count
                G_edge.add_node(k_count)
                G.add_node(k_count)  # add edge switch
                G.add_edge(j_count,k_count)
                count += 1
    # All switches have been added, now adding attributes to switches
    for i in G.nodes():
        G.nodes[i]["type"] = "switch"
        G.nodes[i]["lan_id"] = "other"
        G.nodes[i]["port_server_version"] = []
        G.nodes[i]["system"] = random.choice(["os_windows","os_linux","os_ios","os_mac","os_unix"])#all_cve,all_type,all_type_list
        #Determine if the current switch is a domain switch.
        if random.random() < 0.2:
            G.nodes[i]["system"] = "os_windows"
            domain_cve = random.choice(all_type_list["domain"])
            G.nodes[i]["cve"] = domain_switch_cve(domain_cve)
            G.nodes[i]["software_version"] = []
            for m in G.nodes[i]["cve"]:
                #G.append(m)
                if len(all_cve[m]["affectedversion"]) != 0:
                    version = random.choice(all_cve[m]["affectedversion"])
                G.nodes[i]["software_version"].append(version)
            account = random.randint(1,3)
            G.nodes[i]["account"] = []
            domain_account = (random.choice(user),random.choice(password),"domain")
            G.nodes[i]["account"].append(domain_account)
            account = random.randint(1,2)
            for j in range(account):
                G.nodes[i]["account"].append((random.choice(user),random.choice(password),random.choices(["root","admin","user"], weights=[0.3, 0.2, 0.5], k=1)[0]))
        else:  # Non-domain switch, regular switch
            G.nodes[i]["cve"] = common_switch_cve(G.nodes[i]["system"])
            G.nodes[i]["software_version"] = []
            for m in G.nodes[i]["cve"]:
                #G.append(m)
                if len(all_cve[m]["affectedversion"]) != 0:
                    version = random.choice(all_cve[m]["affectedversion"])
                G.nodes[i]["software_version"].append(version)
            account = random.randint(1,2)
            G.nodes[i]["account"] = []
            for j in range(account):
                G.nodes[i]["account"].append((random.choice(user),random.choice(password),random.choices(["root","admin","user"], weights=[0.3, 0.2, 0.5], k=1)[0]))
    for i in G_edge.nodes():  # For each access switch
        # Create a fully connected graph within the subnet
        all_node_now = len(G.nodes())
        G_H = nx.Graph()
        G_H.add_node(i,**G.nodes[i])
        count += 1
        common_cve = random.choice(all_type_list["soft"])
        is_domain = False
        # First, determine if the current switch is a domain switch
        for h in G.nodes[i]["account"]:
            if h[2] == "domain":
                domain_account = h
                is_domain = True
                break
        if is_domain:  # Simplified condition check
            # Domain switch, has a domain vulnerability
            for m in G.nodes[i]["cve"]:
                if m in all_type_list["domain"]:
                    domain_cve = m
                    break
        for j in range(host_per_edge):
            G_H.add_node(all_node_now)
            G_H.nodes[all_node_now]["type"] = "server"
            G_H.nodes[all_node_now]["lan_id"] = str(count)
            G_H.nodes[all_node_now]["system"] = random.choice(["os_windows","os_linux","os_ios","os_mac","os_unix"])
            pro_type = random.random()
            G_H.nodes[all_node_now]["software_version"] = []
            G_H.nodes[all_node_now]["port_server_version"] = []

            if is_domain:

                G_H.nodes[all_node_now]["system"] = "os_windows"
                G_H.nodes[all_node_now]["software_version"] = []
                G_H.nodes[all_node_now]["port_server_version"] = []
                domain_host_cve_,domain_host_port_cve_ = domain_host_cve(domain_cve)
                G_H.nodes[all_node_now]["cve"] = list(domain_host_cve_+domain_host_port_cve_)
                for m in domain_host_cve_:
                    if len(all_cve[m]["affectedversion"]) != 0:
                        version = random.choice(all_cve[m]["affectedversion"])
                    G_H.nodes[all_node_now]["software_version"].append(version)
                

                ports = copy.deepcopy(ports_)
                for g in domain_host_port_cve_:
                    if len(all_cve[g]["affectedversion"]) != 0:
                        version = random.choice(all_cve[g]["affectedversion"])
                        port = random.choice(ports)
                        ports.remove(port)
                        port_server_version = (str(port),version[0],version[1])
                    G_H.nodes[all_node_now]["port_server_version"].append(port_server_version)
                account = set()
                account.add(domain_account)
                for j in range(random.randint(1,2)):
                    account.add((random.choice(user),random.choice(password),random.choices(["root","admin","user"], weights=[0.3, 0.2, 0.5], k=1)[0]))
                G_H.nodes[all_node_now]["account"] = list(account)
                break
            elif pro_type < 0.7 and is_domain == False:
                common_host_cve_,common_host_port_cve_ = common_host_cve(G_H.nodes[all_node_now]["system"])
                if random.random() < pro:
                    common_host_cve_.append(common_cve)
                G_H.nodes[all_node_now]["cve"] = list(common_host_cve_+common_host_port_cve_)
                G_H.nodes[all_node_now]["software_version"] = []
                for m in common_host_cve_:
                    if len(all_cve[m]["affectedversion"]) != 0:
                        version = random.choice(all_cve[m]["affectedversion"])
                    G_H.nodes[all_node_now]["software_version"].append(version)
                ports = copy.deepcopy(ports_)
                for g in common_host_port_cve_:
                    if len(all_cve[g]["affectedversion"]) != 0:
                        version = random.choice(all_cve[g]["affectedversion"])
                        port = random.choice(ports)
                        ports.remove(port)
                        port_server_version = (str(port),version[0],version[1])
                    G_H.nodes[all_node_now]["port_server_version"].append(port_server_version)
                account = set()
                for j in range(random.randint(1,2)):
                    account.add((random.choice(user),random.choice(password),random.choices(["root","admin","user"], weights=[0.3, 0.2, 0.5], k=1)[0]))
                G_H.nodes[all_node_now]["account"] = list(account)
            elif pro_type > 0.7 and pro_type < 0.8 and is_domain == False:
                #Firewall
                firewall_cve_,firewall_port_cve_ = firewall_cve(G_H.nodes[all_node_now]["system"])
                G_H.nodes[all_node_now]["cve"] = list(firewall_cve_+firewall_port_cve_)
                G_H.nodes[all_node_now]["software_version"] = []
                for m in firewall_cve_:
                    if len(all_cve[m]["affectedversion"]) != 0:
                        version = random.choice(all_cve[m]["affectedversion"])
                    G_H.nodes[all_node_now]["software_version"].append(version)
                ports= copy.deepcopy(ports_)
                for g in firewall_port_cve_:
                    if len(all_cve[g]["affectedversion"]) != 0:
                        version = random.choice(all_cve[g]["affectedversion"])
                        port = random.choice(ports)
                        ports.remove(port)
                        port_server_version = (str(port),version[0],version[1])
                    G_H.nodes[all_node_now]["port_server_version"].append(port_server_version)
                account = set()
                
                for j in range(random.randint(1,2)):
                    account.add((random.choice(user),random.choice(password),random.choices(["root","admin","user"], weights=[0.3, 0.2, 0.5], k=1)[0]))
                G_H.nodes[all_node_now]["account"] = list(account)
            else:
                #Database or server
                common_database_cve_,common_database_port_cve_ = common_database_cve(G_H.nodes[all_node_now]["system"])
                G_H.nodes[all_node_now]["cve"] = list(common_database_cve_+common_database_port_cve_)
                G_H.nodes[all_node_now]["software_version"] = []
                for m in common_database_cve_:
                    if len(all_cve[m]["affectedversion"]) != 0:
                        version = random.choice(all_cve[m]["affectedversion"])
                    G_H.nodes[all_node_now]["software_version"].append(version)
                ports = copy.deepcopy(ports_)
                for g in common_database_port_cve_:
                    if len(all_cve[g]["affectedversion"]) != 0:
                        version = random.choice(all_cve[g]["affectedversion"])
                        port = random.choice(ports)
                        ports.remove(port)
                        port_server_version = (str(port),version[0],version[1])
                    G_H.nodes[all_node_now]["port_server_version"].append(port_server_version)
                account = set()
                
                for j in range(random.randint(1,2)):
                    account.add((random.choice(user),random.choice(password),random.choices(["root","admin","user"], weights=[0.3, 0.2, 0.5], k=1)[0]))
                G_H.nodes[all_node_now]["account"] = list(account)
            all_node_now += 1
        count += 1
        for j in G_H.nodes():
            for s in G_H.nodes():
                if j != s:
                    G_H.add_edge(j,s)
        #Add the nodes from the subnet to the overall network.
        G = nx.compose(G,G_H)
    # G_number = set_node_attribute(G, defense_type)
    return G

def Dy_tree(core_switch_num,core_aggregation, aggregation_switch_num,aggregation_edge,edge_switch_num,host_num,pro, T = 1000):
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
        cve_id = row['CVE_ID']  # Get CVE_ID as key
        values = row.drop('CVE_ID').to_dict()  # Other content as value

        # Process fields that may be lists
        for key, value in values.items():
            if isinstance(value, str) and value.startswith('[') and value.endswith(']'):
                # Convert string representation of list to actual list
                values[key] = eval(value)

        # Store CVE_ID and other content in dictionary
        all_cve[cve_id] = values
    ports_ = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443, 8888, 9000, 10000, 27017, 27018,
    161, 162, 389, 636, 1433, 1434, 1521, 2049, 2222, 3306, 3389, 5432,
    5900, 5984, 6379, 7001, 8000, 8008, 8081, 8088, 8090, 8443, 8888, 9090,
    9200, 9300, 11211, 27017, 27018, 28017, 50000, 50030, 50060, 50070,
    50075, 50090, 60010, 60030]

    Dy_G = []# Dynamic network graph list
    # Network Dynamics Characteristics: Set two probabilities. One is the Host_work probability, which fixes a portion of nodes and changes them every 24 time points. The other is the Host_error probability, which randomly selects machines (from all nodes except switches) to shut down and restarts them after 72 time points.
    #First, generate the network graph at time 0 and save the sets of switch and host nodes for that time. Then, based on the initial network graph, simulate the dynamic changes.
    
    # Fault time table
    t_errors = []
    is_work = True# Indicates current working hours
    lan_ID = 0# Used to calculate which LAN ID is being generated
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
        G.add_node(i)# add core switch
        G_core.add_node(i)
        count += 1
        for j in range(core_aggregation[i]):
            j_count = count
            G_aggregation.add_node(j_count)
            G.add_node(j_count)# add aggregation switch
            G.add_edge(i,j_count)
            count += 1
            for k in range(aggregation_edge[j]):
                k_count = count
                G_edge.add_node(k_count)
                G.add_node(k_count)
                G.add_edge(j_count,k_count)
                count += 1
    # All switches have been added here
    all_switches = set(G.nodes())
    for i in G.nodes():
        G.nodes[i]["type"] = "switch"
        G.nodes[i]["lan_id"] = "other"
        G.nodes[i]["port_server_version"] = []
        G.nodes[i]["system"] = random.choice(["os_windows","os_linux","os_ios","os_mac","os_unix"])#all_cve,all_type,all_type_list
        if random.random() < 0.2:
            # add domain switch
            domain_cve = random.choice(all_type_list["domain"])
            G.nodes[i]["cve"] = domain_switch_cve(domain_cve)
            G.nodes[i]["software_version"] = []
            for m in G.nodes[i]["cve"]:
                #G.append(m)
                if len(all_cve[m]["affectedversion"]) != 0:
                    version = random.choice(all_cve[m]["affectedversion"])
                G.nodes[i]["software_version"].append(version)
            account = random.randint(1,3)
            G.nodes[i]["account"] = []
            domain_account = (random.choice(user),random.choice(password),"domain")
            G.nodes[i]["account"].append(domain_account)
            account = random.randint(1,2)
            for j in range(account):
                G.nodes[i]["account"].append((random.choice(user),random.choice(password),random.choices(["root","admin","user"], weights=[0.3, 0.2, 0.5], k=1)[0]))
        else:# non-domain switch, regular switch
            G.nodes[i]["cve"] = common_switch_cve(G.nodes[i]["system"])
            G.nodes[i]["software_version"] = []
            for m in G.nodes[i]["cve"]:
                #G.append(m)
                if len(all_cve[m]["affectedversion"]) != 0:
                    version = random.choice(all_cve[m]["affectedversion"])
                G.nodes[i]["software_version"].append(version)
            account = random.randint(1,2)
            G.nodes[i]["account"] = []
            for j in range(account):
                G.nodes[i]["account"].append((random.choice(user),random.choice(password),random.choices(["root","admin","user"], weights=[0.3, 0.2, 0.5], k=1)[0]))
    for i in G_edge.nodes():# For each access switch
        all_node_now = len(G.nodes())
        G_H = nx.Graph()
        G_H.add_node(i,**G.nodes[i])
        count += 1
        common_cve = random.choice(all_type_list["soft"])
        is_domain = False
        # First, determine if the current switch is a domain switch
        for h in G.nodes[i]["account"]:
            if h[2] == "domain":
                domain_account = h
                is_domain = True
                break
        if is_domain == True:
            # Domain switch, has a domain vulnerability
            for m in G.nodes[i]["cve"]:
                if m in all_type_list["domain"]:
                    domain_cve = m
                    break
        for j in range(host_per_edge):
            G_H.add_node(all_node_now)
            G_H.nodes[all_node_now]["type"] = "server"
            G_H.nodes[all_node_now]["lan_id"] = str(count)
            G_H.nodes[all_node_now]["system"] = random.choice(["os_windows","os_linux","os_ios","os_mac","os_unix"])
            G_H.nodes[all_node_now]["software_version"] = []
            G_H.nodes[all_node_now]["port_server_version"] = []
            pro_type = random.random()
            if is_domain:
                G_H.nodes[all_node_now]["system"] = "os_windows"
                G_H.nodes[all_node_now]["software_version"] = []
                G_H.nodes[all_node_now]["port_server_version"] = []
                domain_host_cve_,domain_host_port_cve_ = domain_host_cve(domain_cve)
                G_H.nodes[all_node_now]["cve"] = list(domain_host_cve_+domain_host_port_cve_)
                for m in domain_host_cve_:
                    if len(all_cve[m]["affectedversion"]) != 0:
                        version = random.choice(all_cve[m]["affectedversion"])
                    G_H.nodes[all_node_now]["software_version"].append(version)
                
                ports = copy.deepcopy(ports_)
                for g in domain_host_port_cve_:
                    if len(all_cve[g]["affectedversion"]) != 0:
                        version = random.choice(all_cve[g]["affectedversion"])
                        port = random.choice(ports)
                        ports.remove(port)
                        port_server_version = (str(port),version[0],version[1])
                    G_H.nodes[all_node_now]["port_server_version"].append(port_server_version)
                account = set()
                account.add(domain_account)
                for j in range(random.randint(1,2)):
                    account.add((random.choice(user),random.choice(password),random.choices(["root","admin","user"], weights=[0.3, 0.2, 0.5], k=1)[0]))
                G_H.nodes[all_node_now]["account"] = list(account)
            elif pro_type < 0.7 and is_domain == False:
                # Ordinary host
                common_host_cve_,common_host_port_cve_ = common_host_cve(G_H.nodes[all_node_now]["system"])
                if random.random() < pro:# There is a common vulnerability
                    common_host_cve_.append(common_cve)
                G_H.nodes[all_node_now]["cve"] = list(common_host_cve_+common_host_port_cve_)
                G_H.nodes[all_node_now]["software_version"] = []
                for m in common_host_cve_:
                    if len(all_cve[m]["affectedversion"]) != 0:
                        version = random.choice(all_cve[m]["affectedversion"])
                    G_H.nodes[all_node_now]["software_version"].append(version)
                ports = copy.deepcopy(ports_)
                for g in common_host_port_cve_:
                    if len(all_cve[g]["affectedversion"]) != 0:
                        version = random.choice(all_cve[g]["affectedversion"])
                        port = random.choice(ports)
                        ports.remove(port)
                        port_server_version = (str(port),version[0],version[1])
                    G_H.nodes[all_node_now]["port_server_version"].append(port_server_version)
                account = set()
                for j in range(random.randint(1,2)):
                    account.add((random.choice(user),random.choice(password),random.choices(["root","admin","user"], weights=[0.3, 0.2, 0.5], k=1)[0]))
                G_H.nodes[all_node_now]["account"] = list(account)
            elif pro_type > 0.7 and pro_type < 0.8 and is_domain == False:
                # Firewall
                firewall_cve_,firewall_port_cve_ = firewall_cve(G_H.nodes[all_node_now]["system"])
                G_H.nodes[all_node_now]["cve"] = list(firewall_cve_+firewall_port_cve_)
                G_H.nodes[all_node_now]["software_version"] = []
                for m in firewall_cve_:
                    if len(all_cve[m]["affectedversion"]) != 0:
                        version = random.choice(all_cve[m]["affectedversion"])
                    G_H.nodes[all_node_now]["software_version"].append(version)
                ports= copy.deepcopy(ports_)
                for g in firewall_port_cve_:
                    if len(all_cve[g]["affectedversion"]) != 0:
                        version = random.choice(all_cve[g]["affectedversion"])
                        port = random.choice(ports)
                        ports.remove(port)
                        port_server_version = (str(port),version[0],version[1])
                    G_H.nodes[all_node_now]["port_server_version"].append(port_server_version)
                account = set()
                for j in range(random.randint(1,2)):
                    account.add((random.choice(user),random.choice(password),random.choices(["root","admin","user"], weights=[0.3, 0.2, 0.5], k=1)[0]))
                G_H.nodes[all_node_now]["account"] = list(account)
            else:
                # Database or server
                common_database_cve_,common_database_port_cve_ = common_database_cve(G_H.nodes[all_node_now]["system"])
                G_H.nodes[all_node_now]["cve"] = list(common_database_cve_+common_database_port_cve_)
                G_H.nodes[all_node_now]["software_version"] = []
                for m in common_database_cve_:
                    if len(all_cve[m]["affectedversion"]) != 0:
                        version = random.choice(all_cve[m]["affectedversion"])
                    G_H.nodes[all_node_now]["software_version"].append(version)
                ports = copy.deepcopy(ports_)
                for g in common_database_port_cve_:
                    if len(all_cve[g]["affectedversion"]) != 0:
                        version = random.choice(all_cve[g]["affectedversion"])
                        port = random.choice(ports)
                        ports.remove(port)
                        port_server_version = (str(port),version[0],version[1])
                    G_H.nodes[all_node_now]["port_server_version"].append(port_server_version)
                account = set()
                
                for j in range(random.randint(1,2)):
                    account.add((random.choice(user),random.choice(password),random.choices(["root","admin","user"], weights=[0.3, 0.2, 0.5], k=1)[0]))
                G_H.nodes[all_node_now]["account"] = list(account)

            all_node_now += 1
        count += 1
        for j in G_H.nodes():
            for s in G_H.nodes():
                if j != s:
                    G_H.add_edge(j,s)
        # Add the nodes from the subnet to the overall network.
        G = nx.compose(G,G_H)

    # G_number = set_node_attribute(G, defense_type)
    # Dynamic network changes
    G_number = copy.deepcopy(G)
    Dy_G.append(G_number)  # Save the network at time 0
    # Get the nodes of host types
    all_nodes = set(G_number.nodes())
    all_servers = all_nodes - all_switches
    Host_work = random.sample(list(all_servers), int(0.3 * len(all_servers)))
    # Host_error = random.sample(all_servers,int(0.3*len(all_servers)))
    G_0 = copy.deepcopy(G_number)
    # Select a portion of nodes from G_number.nodes() as Host_work
    for t in range(1, T):
        G_ = copy.deepcopy(Dy_G[t-1])
        # G_ = Dy_G[t-1].deepcopy()
        # Regular changes, randomly select 0.001 of nodes to enhance or weaken defense capabilities
        all_nodes_ = set(G_.nodes())
        # To maintain stability, the switches remain unchanged, but the hosts can change.
        all_servers_ = all_nodes_ - all_switches
        G_0,G_ = commen_change(G_0,G_, all_nodes_, all_switches, all_servers_)
        # Changes in the host's operational status.
        if t % 12 == 0 and (t // 12) % 2 == 1:  # After hours, change every 12 time points.
            is_work = False  # Indicates current is off-work time
            G_ = host_work_off(G_, Host_work)
        elif t % 12 == 0 and (t // 12) % 2 == 0:  # Working hours, change every 12 time points.
            G_ = host_work_on(G_0, G_, Host_work,t_errors)
            is_work = True
        real_error = []
        if is_work:
            #Currently it's working hours, and the candidate nodes for faults are all hosts.
            host_candidata = {n for n in G_.nodes() if G_.nodes[n]['type'] == 'server'}
        else:
            #Currently it's off-work time, and the candidate nodes for faults are host nodes - shut down nodes.
            host_candidata = {n for n in G_.nodes() if G_.nodes[n]['type'] == 'server'} - set(Host_work)
        for h in host_candidata:
            #If the generated random number is less than 0.001, it indicates a host failure.
            if random.random() < 0.001:
                G_ = host_error_off(G_, [h])
                real_error.append(h)
        if len(real_error) != 0:  # This moment has produced a fault
            t_errors.append([t, real_error])  # Record fault moment
        for m in t_errors:
            if m[0] + 72 == t:
                G_ = host_error_on(G_0, G_, m[1])
                t_errors.remove(m)
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
    #node number 10
    # core_switch_num =1
    # core_aggregation={0:2}
    # aggregation_switch_num = sum(core_aggregation.values())
    # aggregation_edge={0:2,1:2}
    # edge_switch_num = sum(aggregation_edge.values())
    # host_num = 8

    # #node number 100
    # core_switch_num =1
    # core_aggregation={0:3}
    # aggregation_switch_num = sum(core_aggregation.values())
    # aggregation_edge={0:3,1:3,2:3}
    # edge_switch_num = sum(aggregation_edge.values())
    # host_num = 90

    #node number 1000
    core_switch_num =1#Number of core switches, root node of the tree.
    core_aggregation={0:7}#Number of aggregation switches connected to each core switch.
    aggregation_switch_num = sum(core_aggregation.values())#Number of aggregation switches.
    aggregation_edge={0:7,1:3,2:7,3:7,4:6,5:6,6:7}#Number of access switches connected to each aggregation switch.
    ##Number of access switches is the sum of all values in aggregation_edge.
    edge_switch_num = sum(aggregation_edge.values())#Number of access switches.
    host_num = 950



    pro = 0.65#Probability of having the same vulnerability in the same local area network.
    # np.random.seed(2077)
    #Setting the type of network for numerical simulation, defense_type = 1,2,3
    # defense_type = 1
    # defense_type = 2
    # defense_type = 3
    #Setting whether the network is static or dynamic, static = 0,1  0 indicates dynamic, 1 indicates static

    # static = 0
    static = 1
    for c in range(1):
        if static == 1:#Static network
            graph = tree(core_switch_num,core_aggregation, aggregation_switch_num,aggregation_edge,edge_switch_num,host_num,pro)
    # nx.draw(graph, with_labels=True, alpha=0.8, node_size=500)
    # plt.savefig("123.png")
            z = (f"./authentic_net/tree/static/{len(graph.nodes())}_tree{c}.gpickle")
            # z = (f"./authentic_net/test/static/{len(graph.nodes())}_tree{c}.gpickle")
            os.makedirs(os.path.dirname(z), exist_ok=True)
            with open(z, 'wb') as f:
                pickle.dump(graph, f, pickle.HIGHEST_PROTOCOL)
        else:#Dynamic network
            t_start = 0
            t_end = 1000
            Gy_graphs = Dy_tree(core_switch_num,core_aggregation, aggregation_switch_num,aggregation_edge,edge_switch_num,host_num,pro, T = t_end)
            for i in range(len(Gy_graphs)):
                z = (f"./authentic_net/tree/dynamic/{len(Gy_graphs[0].nodes())}_tree{c}/t{i}.gpickle")
                # z = (f"./authentic_net/test/dynamic/{len(Gy_graphs[0].nodes())}_tree{c}/t{i}.gpickle")
                os.makedirs(os.path.dirname(z), exist_ok=True)
                with open(z, 'wb') as f:
                    pickle.dump(Gy_graphs[i], f, pickle.HIGHEST_PROTOCOL)


    
