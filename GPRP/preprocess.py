import matplotlib.pyplot as plt
import networkx as nx
import random
import math
import json
import sys,os
from networkx.readwrite import json_graph
from collections import defaultdict
# from torch_geometric.datasets import Reddit
import numpy as np
import pickle
from copy import deepcopy
sys.path.append(os.getcwd())
from GPRP.data_cve.data import Read_data 
from GPRP.graph_pre_train.GPT_GNN.data import * 

map_list = np.load("map_list.npy",allow_pickle = True).item()     

net_type = 'fat'#fat, mix, self
for c in range(17):
    
    if c < 10:
        z = (f"./GPRP/datadrive/{net_type}_dataset/pre_data/pre1000_{c}.gpickle")
    elif c >= 10 and c < 15:
        z = (f"./GPRP/datadrive/{net_type}_dataset/pre_data/train1000_{c}.gpickle")
    elif c == 15:
        z = (f"./GPRP/datadrive/{net_type}_dataset/pre_data/test1000_{c}.gpickle")
    #f = (f"./datadrive/dataset/pre_data/pre1000_{c}.gpickle")
    with open(z, 'rb') as f:
        G = pickle.load(f)
    #G = nx.read_gpickle("test_1000.gpickle")
    #print(list(G.nodes(data=True)) )
    
    ori_graph = deepcopy(G)
    #x_state_ = np.zeros((len(G.nodes),9))
    x_state = np.zeros((len(G.nodes),len(map_list)))
    
    y_lable = np.zeros((len(G.nodes),50))
    all_cve, _ = Read_data(path = "GPRP/data_cve/fei_cve_20230728.xlsx").data()
    all_cve_label = {}
    n = 0
    for i in all_cve.keys():
        all_cve_label[i] = n
        n += 1


    #Read_data
    for i in ori_graph.nodes(data=True):
        #print(i)
        for j in i[1].keys():
            if j == "lan_id":
                x_state[i[0]][map_list[str(G.nodes[i[0]]['lan_id'])]] = 1
            if j == "type" :
                x_state[i[0]][map_list[G.nodes[i[0]]['type']]] = 1
            if j == "system" :
                x_state[i[0]][map_list[str(G.nodes[i[0]]['system'])]] = 1
            if j == 'software_ver' :
                count = 3
                for m in i[1][j]:
                    x_state[i[0]][map_list[m]] = 1
                    count += 1
            elif j == 'cve':
                count = 7
                # ab = 0
                # a = [0,0,0,0,0]
                for m in i[1][j]:
                    
                    h = all_cve_label[m]
                    y_lable[i[0],int(h)] = 1
                    # a[ab] = h
                    # ab += 1
                    count += 1
                




    y_lable = torch.tensor(y_lable)
    
    # nx.draw(G, with_labels=True, alpha=0.8, node_size=500)
    # plt.show()
    # print(G.nodes())
    # print(G.edges())
    graph_net = Graph()

    el = defaultdict(  #target_id
                    lambda: defaultdict( #source_id(
                    lambda: int # time
                        ))
    for i,j in tqdm(G.edges()):
        #print(i,j)
        el[i][j] = 1
        el[j][i] = 1

    target_type = 'def'
    graph_net.edge_list['def']['def']['def'] = el
    n = list(el.keys())
    degree = np.zeros(np.max(n)+1)
    for i in n:
        degree[i] = len(el[i])
    x = np.concatenate((x_state, np.log(degree).reshape(-1, 1)), axis=-1)
    graph_net.node_feature['def'] = pd.DataFrame({'emb': list(x)})#

    idx = np.arange(len(graph_net.node_feature[target_type]))
    np.random.seed(43)
    np.random.shuffle(idx)

    if c < 10:
        graph_net.pre_target_nodes   = idx
    elif c >= 10 and c < 15:
        graph_net.train_target_nodes = idx[ :int(len(idx) * 0.8)]
        graph_net.valid_target_nodes = idx[ int(len(idx) * 0.8) : ]
    elif c == 15:
        graph_net.test_target_nodes  = idx

    # graph_net.train_target_nodes = idx[int(len(idx) * 0.7) : int(len(idx) * 0.8)]
    # graph_net.valid_target_nodes = idx[int(len(idx) * 0.8) : int(len(idx) * 0.9)]
    # graph_net.test_target_nodes  = idx[int(len(idx) * 0.9) : ]

    graph_net.y = y_lable
    if c < 10:

        dill.dump(graph_net, open(f'GPRP/datadrive/{net_type}_dataset/pre_graph_{c}.pk', 'wb'))
        #np.save("eval/data/edge_list_",graph_net.edge_list['def']['def']['def'])
        with open(f"eval/{net_type}_data/pre_edge_list_{c}.json","w", encoding='utf-8') as f: 
            f.write(json.dumps(el,ensure_ascii=False))
        np.save(f"eval/{net_type}_data/pre_X_{c}",x)
        np.save(f"eval/{net_type}_data/pre_Y_{c}",(graph_net.y.numpy()))
    elif c >= 10 and c < 15:
        dill.dump(graph_net, open(f'GPRP/datadrive/{net_type}_dataset/train_graph_{c}.pk', 'wb'))
        #np.save("eval/data/edge_list_",graph_net.edge_list['def']['def']['def'])
        with open(f"eval/{net_type}_data/train_edge_list_{c}.json","w", encoding='utf-8') as f: 
            f.write(json.dumps(el,ensure_ascii=False))
        np.save(f"eval/{net_type}_data/train_nodes_{c}",graph_net.train_target_nodes)
        np.save(f"eval/{net_type}_data/valid_nodes_{c}",graph_net.valid_target_nodes)
        np.save(f"eval/{net_type}_data/train_X_{c}",x)
        np.save(f"eval/{net_type}_data/train_Y_{c}",(graph_net.y.numpy()))
    elif c == 15:
        dill.dump(graph_net, open(f'GPRP/datadrive/{net_type}_dataset/test_graph_{c}.pk', 'wb'))
        #np.save("eval/data/edge_list_",graph_net.edge_list['def']['def']['def'])
        with open(f"eval/{net_type}_data/test_edge_list_{c}.json","w", encoding='utf-8') as f: 
            f.write(json.dumps(el,ensure_ascii=False))
        np.save(f"eval/{net_type}_data/test_nodes_{c}",graph_net.test_target_nodes)
        np.save(f"eval/{net_type}_data/test_X_{c}",x)
        np.save(f"eval/{net_type}_data/test_Y_{c}",(graph_net.y.numpy()))


    


    print("Finish!!!!!!")







