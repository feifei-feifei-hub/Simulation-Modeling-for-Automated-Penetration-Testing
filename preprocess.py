import matplotlib.pyplot as plt
import networkx as nx
import random
import math
import json
import sys,os
from networkx.readwrite import json_graph
from collections import defaultdict
from torch_geometric.datasets import Reddit
import numpy as np
import pickle
from copy import deepcopy
sys.path.append(os.getcwd())
from data_cve.CVE_detail import Read_data 
from graph_pre_train.GPT_GNN.data import * 

map_list = np.load("map_list.npy",allow_pickle = True).item()     
# 加载映射文件，映射文件不需要每一次都更新
for c in range(17):
    #从保存的图中读取网络结构
    if c < 10:
        z = (f"./datadrive/dataset/pre_data/pre1000_{c}.gpickle")
    elif c >= 10 and c < 15:
        z = (f"./datadrive/dataset/pre_data/train1000_{c}.gpickle")
    elif c == 15:
        z = (f"./datadrive/dataset/pre_data/test1000_{c}.gpickle")
    #f = (f"./datadrive/dataset/pre_data/pre1000_{c}.gpickle")
    with open(z, 'rb') as f:
        G = pickle.load(f)
    #G = nx.read_gpickle("test_1000.gpickle")
    #print(list(G.nodes(data=True)) )
    
    ori_graph = deepcopy(G)
    #x_state_ = np.zeros((len(G.nodes),9))
    x_state = np.zeros((len(G.nodes),len(map_list)))
    #类型1，局域网位置1，系统1，软件6，一共9维
    y_lable = np.zeros((len(G.nodes),50))#label,把每个节点的cve当作label
    all_cve, _ = Read_data(path = "data_cve/fei_cve_20230728.xlsx").data()
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
                    #x_state[i[0]][count] = map_list[m]#x_state中间就不可以出现cve相关的东西
                    h = all_cve_label[m]
                    y_lable[i[0],int(h)] = 1
                    # a[ab] = h
                    # ab += 1
                    count += 1
                # y_lable.append(a)
    #state就是ori_graph的特征矩阵，等于原来文件中的dataset.data.x.numpy()





    y_lable = torch.tensor(y_lable)
    #print(y_lable)#0是交换机，1是主机

        
    # 查看节点值及其属性

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
        el[i][j] = 1#reddit边的关系转变为 {1:{128:1,152:1,...},2:{133:1,152:1,...,...}}#.item()用于在只包含一个元素的tensor中提取值
        el[j][i] = 1

    target_type = 'def'
    graph_net.edge_list['def']['def']['def'] = el
    n = list(el.keys())
    degree = np.zeros(np.max(n)+1)
    for i in n:
        degree[i] = len(el[i])#target_id的邻居节点
    x = np.concatenate((x_state, np.log(degree).reshape(-1, 1)), axis=-1)
    graph_net.node_feature['def'] = pd.DataFrame({'emb': list(x)})#node_feature只有节点度数

    idx = np.arange(len(graph_net.node_feature[target_type]))#返回一个有终点和起点的固定步长的排列
    np.random.seed(43)
    np.random.shuffle(idx)#打乱顺序

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

        dill.dump(graph_net, open(f'datadrive/dataset/pre_graph_{c}.pk', 'wb'))
        #np.save("andy_liu/data/edge_list_",graph_net.edge_list['def']['def']['def'])
        with open(f"andy_liu/data/pre_edge_list_{c}.json","w", encoding='utf-8') as f: ## 设置'utf-8'编码
            f.write(json.dumps(el,ensure_ascii=False))
        np.save(f"andy_liu/data/pre_X_{c}",x)
        np.save(f"andy_liu/data/pre_Y_{c}",(graph_net.y.numpy()))
    elif c >= 10 and c < 15:
        dill.dump(graph_net, open(f'datadrive/dataset/train_graph_{c}.pk', 'wb'))
        #np.save("andy_liu/data/edge_list_",graph_net.edge_list['def']['def']['def'])
        with open(f"andy_liu/data/train_edge_list_{c}.json","w", encoding='utf-8') as f: ## 设置'utf-8'编码
            f.write(json.dumps(el,ensure_ascii=False))
        np.save(f"andy_liu/data/train_nodes_{c}",graph_net.train_target_nodes)
        np.save(f"andy_liu/data/valid_nodes_{c}",graph_net.valid_target_nodes)
        np.save(f"andy_liu/data/train_X_{c}",x)
        np.save(f"andy_liu/data/train_Y_{c}",(graph_net.y.numpy()))
    elif c == 15:
        dill.dump(graph_net, open(f'datadrive/dataset/test_graph_{c}.pk', 'wb'))
        #np.save("andy_liu/data/edge_list_",graph_net.edge_list['def']['def']['def'])
        with open(f"andy_liu/data/test_edge_list_{c}.json","w", encoding='utf-8') as f: ## 设置'utf-8'编码
            f.write(json.dumps(el,ensure_ascii=False))
        np.save(f"andy_liu/data/test_nodes_{c}",graph_net.test_target_nodes)
        np.save(f"andy_liu/data/test_X_{c}",x)
        np.save(f"andy_liu/data/test_Y_{c}",(graph_net.y.numpy()))


    # dill.dump(graph_net, open('datadrive/dataset/graph_net1000.pk', 'wb'))
    # #np.save("andy_liu/data/edge_list_",graph_net.edge_list['def']['def']['def'])
    # with open("andy_liu/data/edge_list_.json","w", encoding='utf-8') as f: ## 设置'utf-8'编码
    #     f.write(json.dumps(el,ensure_ascii=False))
    # np.save("andy_liu/data/test_nodes_",graph_net.test_target_nodes)
    # np.save("andy_liu/data/train_nodes_",graph_net.train_target_nodes)
    # np.save("andy_liu/data/valid_nodes_",graph_net.valid_target_nodes)
    # np.save("andy_liu/data/X_",x)
    # np.save("andy_liu/data/Y_",(graph_net.y.numpy()))



    print("Finish!!!!!!")







