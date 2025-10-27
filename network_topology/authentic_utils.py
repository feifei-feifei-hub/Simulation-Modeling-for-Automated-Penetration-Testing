import numpy as np
import random
from networkx.readwrite import json_graph
import json

# def get_node_candidate_cve(file_path = '/root/feifei/8_network_generator/data_cve/eng_all_type_list.json'):
#     with open(file_path, 'r', encoding='utf-8') as file:
#         data = json.load(file)
#     all_keys = list(data.keys())
#     # cve_port
#     candidata_domain_switch_cve =  list(data["switch"].values()) + list(data["router"].values()) + list(data["os_windows"].values())
    
#     candidata_domain_host_cve = list(data["os_windows"].values()) + list(data["soft"].values()) + list(data["soft_windows"].values()) + list(data["os_unix"].values())

def domain_switch_cve(domain_cve,file_path = '/root/feifei/8_network_generator/data_cve/eng_all_type_list.json'):
    with open(file_path, 'r', encoding='utf-8') as file:
        data = json.load(file)
        candidata_domain_switch_cve =  list(data["switch"]) + list(data["os_windows"])
        domain_switch_cve = random.sample(candidata_domain_switch_cve, random.randint(1,2))
        if domain_cve not in domain_switch_cve:
            domain_switch_cve.append(domain_cve)
        return domain_switch_cve
def domain_host_cve(domain_cve,file_path = '/root/feifei/8_network_generator/data_cve/eng_all_type_list.json'):
    with open(file_path, 'r', encoding='utf-8') as file:
        data = json.load(file)
        candidata_domain_host_cve = list(data["os_windows"]) + list(data["soft"]) + list(data["soft_os_windows"])
        candidata_domain_host_port_cve = list(data["web"]) + list(data["remote"])
        domain_host_cve = random.sample(candidata_domain_host_cve, random.randint(1,2))
        if domain_cve not in domain_host_cve:
            domain_host_cve.append(domain_cve)
        domain_host_port_cve = random.sample(candidata_domain_host_port_cve, random.randint(1,2))
        return domain_host_cve,domain_host_port_cve 
def firewall_cve(sys, file_path = '/root/feifei/8_network_generator/data_cve/eng_all_type_list.json'):
    
    with open(file_path, 'r', encoding='utf-8') as file:
        data = json.load(file)
        candidata_firewall_port_cve =  list(data["firewall"]) 
        candidata_firewall_cve = list(data[sys]) + list(data["soft"]) + list(data[f"soft_{sys}"]) 
        firewall_cve = random.sample(candidata_firewall_cve, random.randint(1,2))
        firewall_port_cve = random.sample(candidata_firewall_port_cve, random.randint(1,2))
        return firewall_cve,firewall_port_cve
def common_host_cve(sys, file_path = '/root/feifei/8_network_generator/data_cve/eng_all_type_list.json'):
    
    with open(file_path, 'r', encoding='utf-8') as file:
        data = json.load(file)
        candidata_common_host_port_cve =  list(data["web"]) + list(data["remote"])
        candidata_common_host_cve = list(data[sys]) + list(data["soft"]) + list(data[f"soft_{sys}"]) 
        common_host_cve = random.sample(candidata_common_host_cve, random.randint(1,2))
        common_host_port_cve = random.sample(candidata_common_host_port_cve, random.randint(1,2))
        return common_host_cve,common_host_port_cve
def common_switch_cve(sys, file_path = '/root/feifei/8_network_generator/data_cve/eng_all_type_list.json'):
    with open(file_path, 'r', encoding='utf-8') as file:
        data = json.load(file)
        candidata_common_switch_cve =  list(data["switch"]) + list(data[sys]) 
        common_switch_cve = random.sample(candidata_common_switch_cve, random.randint(1,2))
        return common_switch_cve
def common_database_cve(sys, file_path = '/root/feifei/8_network_generator/data_cve/eng_all_type_list.json'):
    
    with open(file_path, 'r', encoding='utf-8') as file:
        data = json.load(file)
        candidata_common_database_cve =  list(data["database"]) + list(data["server"]) + list(data[sys]) + list(data["soft"]) + list(data[f"soft_{sys}"])
        candidata_common_database_port_cve = list(data["web"]) + list(data["remote"])
        common_database_cve = random.sample(candidata_common_database_cve, random.randint(1,2))
        common_database_port_cve = random.sample(candidata_common_database_port_cve, random.randint(1,2))
        return common_database_cve,common_database_port_cve



def commen_change(G_0,G, all_nodes, all_switches, all_servers):
    change_node = random.sample(list(all_nodes), max(int(0.001*len(all_nodes)),1))
    #Repair vulnerabilities with a probability of P = 0.5
    for i in change_node:
        if random.random() < 0.5:
            if G.nodes[i]["cve"] != []:
                cve = random.choice(G.nodes[i]["cve"])
                G.nodes[i]["cve"].remove(cve)
                G_0.nodes[i]["cve"].remove(cve)
    return G_0,G

def host_work_off(G, Host_work):
    for i in Host_work:
        if i in G.nodes():
            G.remove_node(i)
    return G
def host_error_off(G, Host_error):
    
    for i in Host_error:
        if i in G.nodes():
            G.remove_node(i)
    return G
def host_work_on(G_0,G, Host_work,t_errors):
    error_nodes = []
    for i in t_errors:
        error_nodes.append(i[1][0])
    for i in Host_work:
        if i not in G.nodes() and i not in error_nodes:
            node_0_attrs = G_0.nodes[i]
            G.add_node(i, **node_0_attrs)
            for j in G_0.neighbors(i):
                if j in G.nodes():
                    G.add_edge(i,j)
    return G
    
def host_error_on(G_0,G, Host_error):
    for i in Host_error:
        if i not in G.nodes():
            node_0_attrs = G_0.nodes[i]
            G.add_node(i, **node_0_attrs)
        for j in G_0.neighbors(i):
            if j in G.nodes():
                G.add_edge(i,j)
    return G


def set_node_attribute(G, defense_type):
    #Add node attributes (numeric type): Set high defense low detection (1), low detection low defense (2), high detection high defense (3).
    if defense_type == 1:
        #The first four attributes have a minimum value of 5, the last attribute has a maximum value of 3.
        #Attribute values are a list
        for i in G.nodes():
            G.nodes[i]["defense"] =[random.randint(5, 10) for _ in range(4)]
            G.nodes[i]["detection"] = random.randint(0, 3)
    elif defense_type == 2:#Low detection low defense
        for i in G.nodes():
            G.nodes[i]["defense"] = [random.randint(0, 5) for _ in range(4)]
            G.nodes[i]["detection"] = random.randint(0, 3)
    elif defense_type == 3:#High detection high defense
        for i in G.nodes():
            G.nodes[i]["defense"] = [random.randint(5, 10) for _ in range(4)]
            G.nodes[i]["detection"] = random.randint(5, 10)
    return G

if __name__ == '__main__':
    # get_node_candidate_cve()
    domain_switch_cve(h = "111")