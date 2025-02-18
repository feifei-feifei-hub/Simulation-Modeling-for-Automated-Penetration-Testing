import numpy as np
import random
from networkx.readwrite import json_graph
import json

#定义各种类型的节点的候选漏洞列表
# def get_node_candidate_cve(file_path = '/root/feifei/8_network_generator/data_cve/eng_all_type_list.json'):
#     with open(file_path, 'r', encoding='utf-8') as file:
#         data = json.load(file)
#     #向外开放端口的漏洞
#     all_keys = list(data.keys())
#     # cve_port
#     # 节点类型包括：域控交换机、域控主机、防火墙、普通主机、普通交换机、数据库或服务器
#     candidata_domain_switch_cve =  list(data["switch"].values()) + list(data["router"].values()) + list(data["os_windows"].values())#没有添加域控相关漏洞是因为最开始判断该节点是否为域控环境节点时就已经确定了域控漏洞
    
#     candidata_domain_host_cve = list(data["os_windows"].values()) + list(data["soft"].values()) + list(data["soft_windows"].values()) + list(data["os_unix"].values())

def domain_switch_cve(domain_cve,file_path = '/root/feifei/8_network_generator/data_cve/eng_all_type_list.json'):
    with open(file_path, 'r', encoding='utf-8') as file:
        data = json.load(file)
        candidata_domain_switch_cve =  list(data["switch"]) + list(data["os_windows"])#没有添加域控相关漏洞是因为最开始判断该节点是否为域控环境节点时就已经确定了域控漏洞
        #从中随机选择1-2个漏洞
        domain_switch_cve = random.sample(candidata_domain_switch_cve, random.randint(1,2))
        if domain_cve not in domain_switch_cve:
            domain_switch_cve.append(domain_cve)
        return domain_switch_cve#返回的是包含域漏洞的CVE的列表
def domain_host_cve(domain_cve,file_path = '/root/feifei/8_network_generator/data_cve/eng_all_type_list.json'):
    with open(file_path, 'r', encoding='utf-8') as file:
        data = json.load(file)
        candidata_domain_host_cve = list(data["os_windows"]) + list(data["soft"]) + list(data["soft_os_windows"])
        candidata_domain_host_port_cve = list(data["web"]) + list(data["remote"])
        #从中随机选择1-2个漏洞
        domain_host_cve = random.sample(candidata_domain_host_cve, random.randint(1,2))
        if domain_cve not in domain_host_cve:
            domain_host_cve.append(domain_cve)
        domain_host_port_cve = random.sample(candidata_domain_host_port_cve, random.randint(1,2))
        return domain_host_cve,domain_host_port_cve #返回的是包含域漏洞的CVE的列表
def firewall_cve(sys, file_path = '/root/feifei/8_network_generator/data_cve/eng_all_type_list.json'):
    #如果节点是一个防火墙
    with open(file_path, 'r', encoding='utf-8') as file:
        data = json.load(file)
        candidata_firewall_port_cve =  list(data["firewall"]) 
        candidata_firewall_cve = list(data[sys]) + list(data["soft"]) + list(data[f"soft_{sys}"]) 
        #从中随机选择1-2个漏洞
        firewall_cve = random.sample(candidata_firewall_cve, random.randint(1,2))
        firewall_port_cve = random.sample(candidata_firewall_port_cve, random.randint(1,2))
        return firewall_cve,firewall_port_cve#返回的是包含防火墙漏洞的CVE的列表
def common_host_cve(sys, file_path = '/root/feifei/8_network_generator/data_cve/eng_all_type_list.json'):
    #如果节点是一个普通主机
    with open(file_path, 'r', encoding='utf-8') as file:
        data = json.load(file)
        candidata_common_host_port_cve =  list(data["web"]) + list(data["remote"])
        candidata_common_host_cve = list(data[sys]) + list(data["soft"]) + list(data[f"soft_{sys}"]) 
        #从中随机选择1-2个漏洞
        common_host_cve = random.sample(candidata_common_host_cve, random.randint(1,2))
        common_host_port_cve = random.sample(candidata_common_host_port_cve, random.randint(1,2))
        return common_host_cve,common_host_port_cve#返回的是包含普通主机漏洞的CVE的
def common_switch_cve(sys, file_path = '/root/feifei/8_network_generator/data_cve/eng_all_type_list.json'):
    #如果节点是一个普通交换机
    with open(file_path, 'r', encoding='utf-8') as file:
        data = json.load(file)
        candidata_common_switch_cve =  list(data["switch"]) + list(data[sys]) 
        #从中随机选择1-2个漏洞
        common_switch_cve = random.sample(candidata_common_switch_cve, random.randint(1,2))
        return common_switch_cve#返回的是包含普通交换机漏洞的CVE的列表
def common_database_cve(sys, file_path = '/root/feifei/8_network_generator/data_cve/eng_all_type_list.json'):
    #如果节点是一个数据库或服务器
    with open(file_path, 'r', encoding='utf-8') as file:
        data = json.load(file)
        candidata_common_database_cve =  list(data["database"]) + list(data["server"]) + list(data[sys]) + list(data["soft"]) + list(data[f"soft_{sys}"])
        candidata_common_database_port_cve = list(data["web"]) + list(data["remote"])
        #从中随机选择1-2个漏洞
        common_database_cve = random.sample(candidata_common_database_cve, random.randint(1,2))
        common_database_port_cve = random.sample(candidata_common_database_port_cve, random.randint(1,2))
        return common_database_cve,common_database_port_cve#返回的是包含数据库或服务器漏洞的CVE的列表



def commen_change(G_0,G, all_nodes, all_switches, all_servers):
    #代表真实类型的网络图中的常规变化
    change_node = random.sample(all_nodes, max(int(0.02*len(all_nodes)),1))
    #以一定的概率修复漏洞P= 0.5
    for i in change_node:
        if random.random() < 0.5:
            if G.nodes[i]["cve"] != []:
                cve = random.choice(G.nodes[i]["cve"])
                G.nodes[i]["cve"].remove(cve)
                G_0.nodes[i]["cve"].remove(cve)
    return G_0,G

def host_work_off(G, Host_work):
    #删除所有的Host_work节点
    for i in Host_work:
        if i in G.nodes():
            G.remove_node(i)
    return G
def host_error_off(G, Host_error):
    #删除所有的Host_error节点
    for i in Host_error:
        if i in G.nodes():
            G.remove_node(i)
    return G
def host_work_on(G_0,G, Host_work):
    #在节点G中添加所有的Host_work节点，并根据G_0,增加相应的边
    for i in Host_work:
        if i not in G.nodes():
            node_0_attrs = G_0.nodes[i]
            G.add_node(i, **node_0_attrs)
        for j in G_0.neighbors(i):
            if j in G.nodes():
                G.add_edge(i,j)
    return G
    
def host_error_on(G_0,G, Host_error):
    #在节点G中添加所有的Host_error节点，并根据G_0,增加相应的边
    for i in Host_error:
        if i not in G.nodes():
            node_0_attrs = G_0.nodes[i]
            G.add_node(i, **node_0_attrs)
        for j in G_0.neighbors(i):
            if j in G.nodes():
                G.add_edge(i,j)
    return G


def set_node_attribute(G, defense_type):
    #增加节点属性值（数值类型），设置高防御低检测（1），低检测低防御（2），高检测高防御（3）
    if defense_type == 1:
        #前4个属性最小值为5，后一个属性最大值为3
        #属性值为一个列表
        for i in G.nodes():
            G.nodes[i]["defense"] =[random.randint(5, 10) for _ in range(4)]
            G.nodes[i]["detection"] = random.randint(0, 3)
    elif defense_type == 2:#低检测低防御
        for i in G.nodes():
            G.nodes[i]["defense"] = [random.randint(0, 5) for _ in range(4)]
            G.nodes[i]["detection"] = random.randint(0, 3)
    elif defense_type == 3:#高检测高防御
        for i in G.nodes():
            G.nodes[i]["defense"] = [random.randint(5, 10) for _ in range(4)]
            G.nodes[i]["detection"] = random.randint(5, 10)
    return G

if __name__ == '__main__':
    # get_node_candidate_cve()
    domain_switch_cve(h = "111")