import os
import numpy as np
import torch
from collections import defaultdict
from utils import load_json, norm_prob

class Graph:
    def __init__(self, args, device, start=10, end=15):
        args = vars(args) 
        self.node_feature = {c: torch.from_numpy(np.load(os.path.join(args['data_dir'], f'train_X_{c}.npy'))).float().to(device) for c in range(start, end)}
        # self.edge_list = np.load(os.path.join(args.data_dir, 'edge_list.npy'))
        self.edge_list = dict()
        for c in range(start, end):
            edge_list = load_json(os.path.join(args['data_dir'], f'train_edge_list_{c}.json'))
            edge_list = {int(i):list(map(int, j.keys())) for i,j in edge_list.items()}
            self.edge_list[c] = edge_list
        self.y = {c: torch.from_numpy(np.load(os.path.join(args['data_dir'], f'train_Y_{c}.npy'))).to(device) for c in range(start, end)}
        self.train_nodes = {c: np.load(os.path.join(args['data_dir'], f'train_nodes_{c}.npy')) for c in range(start, end)}
        self.valid_nodes = {c: np.load(os.path.join(args['data_dir'], f'valid_nodes_{c}.npy')) for c in range(start, end)}

        self.sample_depth = args['sample_depth']
        self.sample_width = args['sample_width']
        self.batch_size = args['batch_size']
        self.device = device

    def NC_sample(self, mode, c):
        np.random.seed(np.random.randint(2**32 - 1))
        nodes = eval(f'self.{mode}_nodes[{c}]')#将字符串转换为相应的对象，并返回表达式的结果。
        samp_nodes = np.random.choice(nodes, self.batch_size, replace=False) if len(nodes)>self.batch_size else nodes
        feature, edge_list = self.sample_subgraph(samp_nodes, c)
        # node_feature = torch.from_numpy(feature).float().to(self.device)
        node_feature = feature
        node_type = torch.zeros([feature.shape[0]], device=self.device, dtype=int)
        edge_index = torch.LongTensor([[si, ti] for ti, si in edge_list]).to(self.device).t()
        edge_type = torch.zeros([len(edge_list)], device=self.device, dtype=int)
        edge_time = torch.ones([len(edge_list)], device=self.device, dtype=int) * 120
        x_ids = np.arange(self.batch_size) if len(nodes)>self.batch_size else np.arange(len(nodes))
        return node_feature, node_type, edge_time, edge_index, edge_type, x_ids, self.y[c][samp_nodes], samp_nodes

    def add_budget(self, k, layer_data, budget, c):
        edge_list = self.edge_list[c]
        if k in edge_list:
            adl = edge_list[k]
            sampled_ids = np.random.choice(adl, self.sample_width, replace = False) if len(adl)>self.sample_width else adl
            for source_id in sampled_ids:
                if source_id not in layer_data:
                    budget[source_id] += 1. / len(sampled_ids)
        return budget

    def sample_subgraph(self, samp_nodes, c):
        budget = defaultdict(int)
        layer_data  = {id_:num for num, id_ in enumerate(samp_nodes)}
        for target_id in samp_nodes:
            budget = self.add_budget(target_id, layer_data, budget, c)

        for _ in range(self.sample_depth):
            keys = np.array(list(budget.keys()))
            if self.sample_width > len(keys):
                sampled_ids = np.arange(len(keys))
            else:
                score = norm_prob(list(budget.values()))
                sampled_ids = np.random.choice(len(score), self.sample_width, p=score, replace = False) 
            sampled_keys = keys[sampled_ids]
            for k in sampled_keys: 
                layer_data[k] = len(layer_data)
            for k in sampled_keys:
                budget = self.add_budget(k, layer_data, budget, c)
                budget.pop(k)
        
        chosen_nodes = np.array(list(layer_data.keys()))
        feature = self.node_feature[c][chosen_nodes]
        edge_list = [[v, v] for v in layer_data.values()]
        for target_key in layer_data:
            if target_key in self.edge_list[c]:
                target_ser = layer_data[target_key]
                for source_key in self.edge_list[c][target_key]:
                    if source_key in layer_data:
                        edge_list.append([target_ser, layer_data[source_key]])
        return feature, edge_list

class iiiiGraph:
    def __init__(self, args, device, start=0, end=8):
        self.node_feature = {c: torch.from_numpy(np.load(os.path.join(args['data_dir'], f'train_X_{c}.npy'))).float().to(device) for c in range(start, end)}
        # self.edge_list = np.load(os.path.join(args.data_dir, 'edge_list.npy'))
        self.edge_list = dict()
        for c in range(start, end):
            edge_list = load_json(os.path.join(args['data_dir'], f'train_edge_list_{c}.json'))
            edge_list = {int(i):list(map(int, j.keys())) for i,j in edge_list.items()}
            self.edge_list[c] = edge_list
        self.y = {c: torch.from_numpy(np.load(os.path.join(args['data_dir'], f'train_Y_{c}.npy'))).to(device) for c in range(start, end)}
        self.train_nodes = {c: np.load(os.path.join(args['data_dir'], f'train_nodes_{c}.npy')) for c in range(start, end)}
        self.valid_nodes = {c: np.load(os.path.join(args['data_dir'], f'valid_nodes_{c}.npy')) for c in range(start, end)}

        self.sample_depth = args['sample_depth']
        self.sample_width = args['sample_width']
        self.batch_size = args['batch_size']
        self.device = device

    def NC_sample(self, mode, c):
        np.random.seed(np.random.randint(2**32 - 1))
        nodes = eval(f'self.{mode}_nodes[{c}]')#将字符串转换为相应的对象，并返回表达式的结果。
        samp_nodes = np.random.choice(nodes, self.batch_size, replace=False) if len(nodes)>self.batch_size else nodes
        feature, edge_list = self.sample_subgraph(samp_nodes, c)
        # node_feature = torch.from_numpy(feature).float().to(self.device)
        node_feature = feature
        node_type = torch.zeros([feature.shape[0]], device=self.device, dtype=int)
        edge_index = torch.LongTensor([[si, ti] for ti, si in edge_list]).to(self.device).t()
        edge_type = torch.zeros([len(edge_list)], device=self.device, dtype=int)
        edge_time = torch.ones([len(edge_list)], device=self.device, dtype=int) * 120
        x_ids = np.arange(self.batch_size) if len(nodes)>self.batch_size else np.arange(len(nodes))
        return node_feature, node_type, edge_time, edge_index, edge_type, x_ids, self.y[c][samp_nodes], samp_nodes

    def add_budget(self, k, layer_data, budget, c):
        edge_list = self.edge_list[c]
        if k in edge_list:
            adl = edge_list[k]
            sampled_ids = np.random.choice(adl, self.sample_width, replace = False) if len(adl)>self.sample_width else adl
            for source_id in sampled_ids:
                if source_id not in layer_data:
                    budget[source_id] += 1. / len(sampled_ids)
        return budget

    def sample_subgraph(self, samp_nodes, c):
        budget = defaultdict(int)
        layer_data  = {id_:num for num, id_ in enumerate(samp_nodes)}
        for target_id in samp_nodes:
            budget = self.add_budget(target_id, layer_data, budget, c)

        for _ in range(self.sample_depth):
            keys = np.array(list(budget.keys()))
            if self.sample_width > len(keys):
                sampled_ids = np.arange(len(keys))
            else:
                score = norm_prob(list(budget.values()))
                sampled_ids = np.random.choice(len(score), self.sample_width, p=score, replace = False) 
            sampled_keys = keys[sampled_ids]
            for k in sampled_keys: 
                layer_data[k] = len(layer_data)
            for k in sampled_keys:
                budget = self.add_budget(k, layer_data, budget, c)
                budget.pop(k)
        
        chosen_nodes = np.array(list(layer_data.keys()))
        feature = self.node_feature[c][chosen_nodes]
        edge_list = [[v, v] for v in layer_data.values()]
        for target_key in layer_data:
            if target_key in self.edge_list[c]:
                target_ser = layer_data[target_key]
                for source_key in self.edge_list[c][target_key]:
                    if source_key in layer_data:
                        edge_list.append([target_ser, layer_data[source_key]])
        return feature, edge_list


class Graph_test(Graph):
    def __init__(self, args, device, c=15):
        self.node_feature = {c: torch.from_numpy(np.load(os.path.join(args['data_dir'], f'test_X_{c}.npy'))).float().to(device)}
        # self.edge_list = np.load(os.path.join(args.data_dir, 'edge_list.npy'))
        self.edge_list = dict()
        edge_list = load_json(os.path.join(args['data_dir'], f'test_edge_list_{c}.json'))
        edge_list = {int(i):list(map(int, j.keys())) for i,j in edge_list.items()}
        self.edge_list[c] = edge_list
        # self.edge_list = load_json(os.path.join(args.data_dir, f'test_edge_list_{c}.json'))
        # self.edge_list = {int(i):list(map(int, j.keys())) for i,j in self.edge_list.items()}
        self.y = {c: torch.from_numpy(np.load(os.path.join(args['data_dir'], f'test_Y_{c}.npy'))).to(device)}
        # self.train_nodes = np.load(os.path.join(args.data_dir, f'train_nodes_{c}.npy'))
        # self.valid_nodes = np.load(os.path.join(args.data_dir, f'valid_nodes_{c}.npy'))
        self.test_nodes = {c: np.load(os.path.join(args['data_dir'], f'test_nodes_{c}.npy'))}
        self.sample_depth = args['sample_depth']
        self.sample_width = args['sample_width']
        self.batch_size = args['batch_size']
        self.device = device
        self.c =c