# import matplotlib.pyplot as plt
# import networkx as nx
# import random
# import math
# import json
import sys,os
# from networkx.readwrite import json_graph
# from collections import defaultdict
# from torch_geometric.datasets import Reddit

sys.path.append(os.getcwd())
from data_cve.CVE_detail import Read_data 


def map_list():
    map_list = {}
    map_list["switch"] = 0
    map_list["server"] = 1
    #[0,1] The first two digits represent the node type: switch/server.
    for i in range(0,350):
        map_list[str(i)] = i+2
    #[2:21] The next digits represent which lan_id the node belongs to.
    map_list["windows"] = len(map_list) + 1
    map_list["linux"] = len(map_list) + 1
    #"windows","linux"
    cve = Read_data()
    for i in cve.all_cve:
        print(cve.all_cve[i]["affectedversion"])
        print(cve.all_cve[i]["targetname"])
        for m in cve.all_cve[i]["targetname"]:
            if len(cve.all_cve[i]["affectedversion"]) == 0:
                map_list[(m,"PAD")] = len(map_list) + 1
            else:
                for n in cve.all_cve[i]["affectedversion"]:
                    map_list[(m,n)] = len(map_list) + 1
    #（software+version)
    for i in cve.all_cve:
        map_list[i] = len(map_list) + 1
    # cve

    return map_list
map_list_ = map_list()
print(map_list_)
# filename = open('map_list.txt','w')#dict转txt
# for k,v in map_list_.items():
#     filename.write(k+':'+v)
#     filename.write('\n')
# filename.close()
import numpy as np

np.save("map_list.npy",map_list_)         

#map_list_ = np.load("map_list.npy",allow_pickle = True).item()    




        