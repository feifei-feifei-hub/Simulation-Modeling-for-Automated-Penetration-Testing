# Input  layers ;
#  total number of nodes ;
# Layer node proportion: layers_percent = []
# Number of subnets in each layer Lan_num 
# The proportion of switches in each layer's total data: switchs_percent = [], at least 1 switch in each layer except the last
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

 
def partitioned_layered_garph_generatin(layers,total,layers_percent,Lan_num,switchs_percent,pro):
    user = []
    with open('/root/feifei/8_network_generator/data_cve/user.txt', 'r', encoding='utf-8') as file:
        for line in file:
            user.append(line.strip()) 
    password = []
    with open('/root/feifei/8_network_generator/data_cve/pass.txt', 'r', encoding='utf-8') as file:
        for line in file:
            password.append(line.strip())
    #all_cve,all_type,all_type_list
    with open('/root/feifei/8_network_generator/data_cve/eng_all_type_list.json', 'r', encoding='utf-8') as file:
        all_type_list = json.load(file)
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

        # Store CVE_ID and other contents in dictionary
        all_cve[cve_id] = values
    ports_ = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443, 8888, 9000, 10000, 27017, 27018,
    161, 162, 389, 636, 1433, 1434, 1521, 2049, 2222, 3306, 3389, 5432,
    5900, 5984, 6379, 7001, 8000, 8008, 8081, 8088, 8090, 8443, 8888, 9090,
    9200, 9300, 11211, 27017, 27018, 28017, 50000, 50030, 50060, 50070,
    50075, 50090, 60010, 60030]
    layers_num = [int(total*i) for i in layers_percent]#Host count per layer
    print(layers_num)  # Print the number of hosts in each layer
    graph_list = {}
    each_Lan_node_num = []#Total number of nodes in each LAN
    lan_switchs_num = []#Number of switches in each LAN
    lan_switch_ID= []#ID of each switch
    start = 0
    end = 0
    lan_ID = 0#ID for the current LAN being generated
    each_lan_node_id = []
    for i in range(layers):
        each_Lan = layers_num[i]/Lan_num[i]#Each layer has multiple LANs, with the same number of nodes in each LAN
        count = 0
        #start and end are defined for generating switch ID
        while count < Lan_num[i]:
            each_Lan_node_num.append(int(each_Lan))#Each LAN has the total number of nodes
            lan_switchs_num.append(math.ceil(switchs_percent[i]*each_Lan))#Each LAN has the number of switches
            lan_switch_ID_ = set()#IDs of switches within the LAN
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
        #This LAN's common CVE
        for j in G_lans[i]:
            G_lans[i].nodes[j]["type"] = "server"
            G_lans[i].nodes[j]["lan_id"] = str(i)
            G_lans[i].nodes[j]["system"] = a
            G_lans[i].nodes[j]["port_server_version"] = []
            G_lans[i].nodes[j]["software_version"] = []
            G_lans[i].nodes[j]["cve"] = []
            if i == len(each_Lan_node_num)-1:#The last layer is the database
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
                    account.add((random.choice(user),random.choice(password),random.choices(["root","admin","user"], weights=[0.3, 0.2, 0.5], k=1)[0]))
                G_lans[i].nodes[j]["account"] = list(account)
            else:
                G_lans[i].nodes[j]["cve"].append(k)





    #Connect switches across adjacent layers only, no same-layer connections.
    G_switchs = nx.Graph()
    count1 = 0
    while count1 < len(lan_switchs_num)-1:
        # for i in lan_switch_ID[count1]:
        #     for j in lan_switch_ID[count1+1]:
        #         G_switchs.add_edge(i,j)
        #Randomly select some upper-layer switches to connect to lower-layer switches
        for i in lan_switch_ID[count1]:
            num_connections = random.randint(1, len(lan_switch_ID[count1+1]))
            connected_switches = random.sample(lan_switch_ID[count1+1], num_connections)
            for j in connected_switches:
                G_switchs.add_edge(i, j)
        count1 += 1
    switch_cve = []
    domain_server = []
    for i in G_switchs:
        G_switchs.nodes[i]["type"] = "switch"#Generate CVE from switch-related vulnerabilities
        G_switchs.nodes[i]["lan_id"] = "other"
        G_switchs.nodes[i]["port_server_version"] = []
        G_switchs.nodes[i]["system"] = random.choice(["os_windows","os_linux","os_ios","os_mac","os_unix"])
        if random.random() < 0.2:
            domain_server.append(i)
            #This is a domain switch
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
            #Set accounts for domain switches
            G_switchs.nodes[i]["account"] = []
            domain_account = (random.choice(user),random.choice(password),"domain")
            G_switchs.nodes[i]["account"].append(domain_account)
            account = random.randint(1,2)
            for j in range(account):
                G_switchs.nodes[i]["account"].append((random.choice(user),random.choice(password),random.choices(["root","admin","user"], weights=[0.3, 0.2, 0.5], k=1)[0]))
        else:#Non-domain switch, regular switch
            G_switchs.nodes[i]["cve"] = common_switch_cve(G_switchs.nodes[i]["system"])
            G_switchs.nodes[i]["software_version"] = []
            for m in G_switchs.nodes[i]["cve"]:
                #G.append(m)
                if len(all_cve[m]["affectedversion"]) != 0:
                    version = random.choice(all_cve[m]["affectedversion"])
                G_switchs.nodes[i]["software_version"].append(version)
            #Set accounts for regular switches
            account = random.randint(1,2)
            G_switchs.nodes[i]["account"] = []
            for j in range(account):
                G_switchs.nodes[i]["account"].append((random.choice(user),random.choice(password),random.choices(["root","admin","user"], weights=[0.3, 0.2, 0.5], k=1)[0]))
    # Host_work = random.sample(list(all_servers),int(0.3*len(all_servers)))


    #Connect switches to LANs 
    all_graph = []
    for i in G_lans.values():
        all_graph.append(i)
    all_graph.append(G_switchs)
    G = nx.compose_all(all_graph) 
    #remove connections between switches within the same LAN
    for i in lan_switch_ID:
        if len(i) > 1:
            #print(i)
            for j in i:
                for h in i:
                    if j != h:
                        G.add_edge(j,h)
                        G.remove_edge(j,h)
    # Randomly delete some edges connecting hosts and switches
    for i in G.nodes():
        if G.nodes[i]["type"] == "server":
            # neineighbors = list(G.neighbors(i))
            switch_neighbors = [j for j in G.neighbors(i) if G.nodes[j]["type"] == "switch"]
            if not switch_neighbors:
                continue
            to_remove = []
            for j in switch_neighbors:
                if random.random() < 0.4:
                    to_remove.append(j)
            if len(to_remove) == len(switch_neighbors):
                saved = random.choice(to_remove)
                to_remove.remove(saved)
            # Remove selected edges
            for j in to_remove:
                G.remove_edge(i, j)
            # for j in neineighbors:
            #     if G.nodes[j]["type"] == "switch":
            #         if random.random() < 0.4 and len(list(G.neighbors(i))) > 1:
            #             G.remove_edge(i,j)


    # nx.draw(G, with_labels=True, alpha=0.8, node_size=500)
    # plt.savefig("graph.png") 
    # plt.show() 
    
    all_switches = {n for n in G.nodes() if G.nodes[n]['type'] == 'switch'}
    all_servers = {n for n in G.nodes() if G.nodes[n]['type'] == 'server'}
    Host_work = random.sample(list(all_servers),int(0.3*len(all_servers)))
    sorted_nodes = sorted(G.nodes())
    # Add attributes to G. The attributes for switches and the last layer of database nodes have been set. Now set the attributes for other nodes.
    pro_type = random.random()
    for i in all_servers:
        is_domain = False
        G.nodes[i]["type"] = "server"
        # First check if this node has already been set with attributes
        Lan_id_cve = {}
        if "account" not in G.nodes[i].keys():
            #Node attributes not set.
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
                G.nodes[i]["cve"] = list(domain_host_cve_+domain_host_port_cve_)#Reset all vulnerabilities on the domain host.
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
                    account.add((random.choice(user),random.choice(password),random.choices(["root","admin","user"], weights=[0.3, 0.2, 0.5], k=1)[0]))
                G.nodes[i]["account"] = list(account)
            elif pro_type < 0.7 and is_domain == False:
                common_host_cve_,common_host_port_cve_ = common_host_cve(G.nodes[i]["system"])
                if random.random() > pro:# Delete existing vulnerabilities
                    G.nodes[i]["cve"] = list(common_host_cve_+common_host_port_cve_)
                else:# Add new vulnerabilities to existing ones
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
                    account.add((random.choice(user),random.choice(password),random.choices(["root","admin","user"], weights=[0.3, 0.2, 0.5], k=1)[0]))
                G.nodes[i]["account"] = list(account)
            elif pro_type>0.7 and pro_type<0.8 and is_domain == False:
                # Firewall
                firewall_cve_,firewall_port_cve_ = firewall_cve(G.nodes[i]["system"])
                if random.random() > pro:# Delete existing vulnerabilities
                    G.nodes[i]["cve"] = list(firewall_cve_+firewall_port_cve_)
                else:# Add new vulnerabilities to existing ones
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
                    account.add((random.choice(user),random.choice(password),random.choices(["root","admin","user"], weights=[0.3, 0.2, 0.5], k=1)[0]))
                G.nodes[i]["account"] = list(account)
            else:
                # Database
                common_database_cve_,common_database_port_cve_ = common_database_cve(G.nodes[i]["system"])
                if random.random() > pro:# Delete existing vulnerabilities
                    G.nodes[i]["cve"] = list(common_database_cve_+common_database_port_cve_)
                else:# Add new vulnerabilities to existing ones
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
                    account.add((random.choice(user),random.choice(password),random.choices(["root","admin","user"], weights=[0.3, 0.2, 0.5], k=1)[0]))
                G.nodes[i]["account"] = list(account)
    return G#generated graph G


def Dy_partitioned_layered_garph_generatin(layers,total,layers_percent,Lan_num,switchs_percent,pro,T):
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
    layers_num = [int(total*i) for i in layers_percent]#Number of hosts per layer
    #print(layers_num)
    graph_list = {}
    each_Lan_node_num = []#Total number of nodes in each LAN
    lan_switchs_num = []#Number of switches in each LAN
    lan_switch_ID= []#ID of each switch
    start = 0
    end = 0
    lan_ID = 0#Used to calculate which LAN ID is being generated
    each_lan_node_id = []
    for i in range(layers):
        each_Lan = layers_num[i]/Lan_num[i]#Each layer has multiple LANs, and the number of nodes within each LAN is the same
        count = 0
        #start and end are defined as the starting and ending points for generating switch IDs
        while count < Lan_num[i]:
            each_Lan_node_num.append(int(each_Lan))#Total number of nodes in each LAN
            lan_switchs_num.append(math.ceil(switchs_percent[i]*each_Lan))#Number of switches in each LAN
            lan_switch_ID_ = set()#ID of each switch
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
            if i == len(each_Lan_node_num)-1:#The last layer is the database    
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
                    account.add((random.choice(user),random.choice(password),random.choices(["root","admin","user"], weights=[0.3, 0.2, 0.5], k=1)[0]))
                G_lans[i].nodes[j]["account"] = list(account)
            else:
                G_lans[i].nodes[j]["cve"].append(k)
              

    #Connect switches across adjacent layers only, no same-layer connections.
    G_switchs = nx.Graph()
    count1 = 0
    while count1 < len(lan_switchs_num)-1:
        # for i in lan_switch_ID[count1]:
        #     for j in lan_switch_ID[count1+1]:
        #         G_switchs.add_edge(i,j)
        #Connect a portion of upper-layer switches to lower-layer switches randomly
        for i in lan_switch_ID[count1]:
            num_connections = random.randint(1, len(lan_switch_ID[count1+1]))
            connected_switches = random.sample(lan_switch_ID[count1+1], num_connections)
            for j in connected_switches:
                G_switchs.add_edge(i, j)
        count1 += 1
    switch_cve = []
    domain_server = []
    for i in G_switchs:
        G_switchs.nodes[i]["type"] = "switch"#From switch-related vulnerabilities generate cve
        G_switchs.nodes[i]["lan_id"] = "other"
        G_switchs.nodes[i]["port_server_version"] = []
        G_switchs.nodes[i]["system"] = random.choice(["os_windows","os_linux","os_ios","os_mac","os_unix"])
        if random.random() < 0.2:
            domain_server.append(i)
            #This is a domain switch
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
            #Set accounts for domain switches
            G_switchs.nodes[i]["account"] = []
            domain_account = (random.choice(user),random.choice(password),"domain")
            G_switchs.nodes[i]["account"].append(domain_account)
            account = random.randint(1,2)
            for j in range(account):
                G_switchs.nodes[i]["account"].append((random.choice(user),random.choice(password),random.choices(["root","admin","user"], weights=[0.3, 0.2, 0.5], k=1)[0]))
        else:#Non-domain switch, regular switch
            G_switchs.nodes[i]["cve"] = common_switch_cve(G_switchs.nodes[i]["system"])
            G_switchs.nodes[i]["software_version"] = []
            for m in G_switchs.nodes[i]["cve"]:
                #G.append(m)
                if len(all_cve[m]["affectedversion"]) != 0:
                    version = random.choice(all_cve[m]["affectedversion"])
                G_switchs.nodes[i]["software_version"].append(version)
            #Set accounts for regular switches
            account = random.randint(1,2)
            G_switchs.nodes[i]["account"] = []
            for j in range(account):
                G_switchs.nodes[i]["account"].append((random.choice(user),random.choice(password),random.choices(["root","admin","user"], weights=[0.3, 0.2, 0.5], k=1)[0]))
    # Host_work = random.sample(list(all_servers),int(0.3*len(all_servers)))

    #Connect the generated switches to the local area network
    all_graph = []
    for i in G_lans.values():
        all_graph.append(i)
    all_graph.append(G_switchs)
    G = nx.compose_all(all_graph) 
    #Switches in the same LAN cannot be connected, so these edges must be removed.
    for i in lan_switch_ID:
        if len(i) > 1:
            #print(i)
            for j in i:
                for h in i:
                    if j != h:
                        G.add_edge(j,h)
                        G.remove_edge(j,h)
    # Randomly remove some edges connecting hosts and switches
    for i in G.nodes():
        if G.nodes[i]["type"] == "server":
            # neineighbors = list(G.neighbors(i))
            switch_neighbors = [j for j in G.neighbors(i) if G.nodes[j]["type"] == "switch"]
            if not switch_neighbors:
                continue
            to_remove = []
            for j in switch_neighbors:
                if random.random() < 0.4:
                    to_remove.append(j)
            if len(to_remove) == len(switch_neighbors):
                saved = random.choice(to_remove)
                to_remove.remove(saved)
            # Remove the selected edges
            for j in to_remove:
                G.remove_edge(i, j)
            # for j in neineighbors:
            #     if G.nodes[j]["type"] == "switch":
            #         if random.random() < 0.4 and len(list(G.neighbors(i))) > 1:
            #             G.remove_edge(i,j)


    # nx.draw(G, with_labels=True, alpha=0.8, node_size=500)
    # plt.savefig("graph.png")  
    # plt.show() 
    all_switches = {n for n in G.nodes() if G.nodes[n]['type'] == 'switch'}
    all_servers = {n for n in G.nodes() if G.nodes[n]['type'] == 'server'}
    Host_work = random.sample(list(all_servers),int(0.3*len(all_servers)))
    all_nodes = set(G.nodes())
    sorted_nodes = sorted(G.nodes())
    pro_type = random.random()
    for i in all_servers:
        is_domain = False
        G.nodes[i]["type"] = "server"
        # First, check if this node has already been set with attributes
        Lan_id_cve = {}
        if "account" not in G.nodes[i].keys():
            # This node has not been set with attributes
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
                G.nodes[i]["cve"] = list(domain_host_cve_+domain_host_port_cve_)
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
                    account.add((random.choice(user),random.choice(password),random.choices(["root","admin","user"], weights=[0.3, 0.2, 0.5], k=1)[0]))
                G.nodes[i]["account"] = list(account)
            elif pro_type < 0.7 and is_domain == False:
                common_host_cve_,common_host_port_cve_ = common_host_cve(G.nodes[i]["system"])
                if random.random() > pro:# Delete existing vulnerabilities
                    G.nodes[i]["cve"] = list(common_host_cve_+common_host_port_cve_)
                else:# Add new vulnerabilities to existing ones
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
                    account.add((random.choice(user),random.choice(password),random.choices(["root","admin","user"], weights=[0.3, 0.2, 0.5], k=1)[0]))
                G.nodes[i]["account"] = list(account)
            elif pro_type>0.7 and pro_type<0.8 and is_domain == False:
                # This is a firewall
                firewall_cve_,firewall_port_cve_ = firewall_cve(G.nodes[i]["system"])
                if random.random() > pro:# Delete existing vulnerabilities
                    G.nodes[i]["cve"] = list(firewall_cve_+firewall_port_cve_)
                else:# Add new vulnerabilities to existing ones
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
                    account.add((random.choice(user),random.choice(password),random.choices(["root","admin","user"], weights=[0.3, 0.2, 0.5], k=1)[0]))
                G.nodes[i]["account"] = list(account)
            else:
                # This is a database
                common_database_cve_,common_database_port_cve_ = common_database_cve(G.nodes[i]["system"])
                if random.random() > pro:# Delete existing vulnerabilities
                    G.nodes[i]["cve"] = list(common_database_cve_+common_database_port_cve_)
                else:# Add new vulnerabilities to existing ones
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
                    account.add((random.choice(user),random.choice(password),random.choices(["root","admin","user"], weights=[0.3, 0.2, 0.5], k=1)[0]))
                G.nodes[i]["account"] = list(account)
    # G_number = set_node_attribute(G, defense_type)
    G_number = copy.deepcopy(G)
    Dy_G = []
    t_errors = []
    Dy_G.append(G_number)#save the initial network at time t=0
    # G_0 = G_number.copy()
    is_work = True
    G_0 = copy.deepcopy(G_number)
    for t in range(1, T):
        # G_ = Dy_G[t-1].copy()
        G_ = copy.deepcopy(Dy_G[t-1])
        all_nodes_ = set(G_.nodes())
        # To maintain stability, switches do not change, but hosts can change
        all_servers_ = all_nodes_ - all_switches
        G_0,G_ = commen_change(G_0,G_, all_nodes_, all_switches, all_servers_)

        # Host working state changes
        if t % 12 == 0 and (t // 12) % 2 == 1:# Off work time, change every 12 time points
            is_work = False
            G_ = host_work_off(G_, Host_work)
        elif t % 12 == 0 and (t // 12) % 2 == 0:# On work time, change every 12 time points
            is_work = True
            G_ = host_work_on(G_0, G_, Host_work,t_errors)

        # Host fault state changes
        real_error = []
        if is_work:
            # Current is working time, fault candidate nodes are all hosts
            host_candidata = {n for n in G_.nodes() if G_.nodes[n]['type'] == 'server'}
        else:
            # Current is rest time, fault candidate nodes are host nodes - shutdown nodes
            host_candidata = {n for n in G_.nodes() if G_.nodes[n]['type'] == 'server'} - set(Host_work)
        for h in host_candidata:
            # If the generated random number is less than 0.001, it indicates that this host has failed
            if random.random() < 0.001:
                G_ = host_error_off(G_, [h])
                real_error.append(h)
        if len(real_error) != 0:# Fault occurred at this moment
            t_errors.append([t,real_error])# Record fault moment
        for m in t_errors:
            if m[0] + 72 == t:
                G_ = host_error_on(G_0, G_, m[1])
                t_errors.remove(m)
        Dy_G.append(G_)
    return Dy_G# Generated network graph
    




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
    # Set the type of numerical simulation network, defense_type = 1,2,3
    # defense_type = 1
    # defense_type = 2
    # defense_type = 3

    # Static/Dynamic network generation and saving
    # static = 0 # Dynamic network
    static = 1 # Static network

    #node scale 10
    # layers = 3
    # total = 20
    # layers_percent = [0.6,0.3,0.1]
    # Lan_num = [2,1,1]
    # switchs_percent=[0.2,0.2,0.2]
    #node scale 100
    # layers = 4
    # total = 100
    # layers_percent = [0.5,0.3,0.1,0.1]
    # Lan_num = [5,2,2,1]
    # switchs_percent=[0.2,0.2,0.2,0.2]
    #node scale 1000
    layers = 4
    total = 1000
    layers_percent = [0.5,0.3,0.1,0.1]
    Lan_num = [5,2,2,1]
    switchs_percent=[0.2,0.2,0.2,0.2]

    for c in range(1):
        pro = 0.65#同一个局域网内部的节点哟多大的可能性拥有同一个cve
        # np.random.seed(2077)
        if static == 1:#static network
            graph = partitioned_layered_garph_generatin(layers,total,layers_percent,Lan_num,switchs_percent,pro)
            # z = (f"./authentic_net/partitioned_layered/static/{len(graph.nodes())}_net{c}.gpickle")
            z = (f"./authentic_net/test/static/{len(graph.nodes())}_net{c}.gpickle")
            os.makedirs(os.path.dirname(z), exist_ok=True)
            with open(z, 'wb') as f:
                pickle.dump(graph, f, pickle.HIGHEST_PROTOCOL)
        #print(graph.nodes(data = True))
        #nx.write_gpickle(graph, "test_1000_2.gpickle")
        else:#dynamic network
            t_end = 100
            Gy_graphs = Dy_partitioned_layered_garph_generatin(layers,total,layers_percent,Lan_num,switchs_percent,pro, T = t_end)
            for i in range(len(Gy_graphs)):
                # z = (f"./authentic_net/partitioned_layered/dynamic/{len(Gy_graphs[0].nodes())}_net{c}/t{i}.gpickle")
                z = (f"./authentic_net/test/dynamic/{len(Gy_graphs[0].nodes())}_net{c}/t{i}.gpickle")
                os.makedirs(os.path.dirname(z), exist_ok=True)
                with open(z, 'wb') as f:
                    pickle.dump(Gy_graphs[i], f, pickle.HIGHEST_PROTOCOL)
        
