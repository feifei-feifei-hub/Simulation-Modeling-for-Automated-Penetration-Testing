import argparse
import numpy as np
import torch
import json

def configure():
    parser = argparse.ArgumentParser(description='Fine-Tuning on node classification task')
    # Dataset arguments
    parser.add_argument('--premodel', type=str, default='1208selfpre+hgt+128+200+0.001+25+4+1+32+10+8.pk', help='premodel name')
    model_name_ = parser.parse_args()
    model_name = model_name_.premodel
    parser.add_argument('--conv_name', type=str, default=model_name.split('+')[1],
                    choices=['hgt', 'gcn','gat', 'rgcn' ,'han', 'sage'], help='The name of GNN filter. By default is Heterogeneous Graph Transformer (hgt)')
    parser.add_argument('--batch_size', type=int, default=int(model_name.split('+')[2]), help='Number of output nodes for training')
    parser.add_argument('--n_hid', type=int, default=int(model_name.split('+')[3]), help='Number of hidden dimension')
    parser.add_argument('--n_epoch', type=int, default=10, help='Number of epoch to run')
    parser.add_argument('--n_layers', type=int, default=int(model_name.split('+')[6]), help='Number of attention head')
    parser.add_argument('--sample_depth', type=int, default=int(model_name.split('+')[7]), help='Number of GNN layers')
    parser.add_argument('--sample_width', type=int, default=int(model_name.split('+')[8]), help='Number of attention head')
    parser.add_argument('--n_batch', type=int, default=int(model_name.split('+')[9]), help='')
    parser.add_argument('--n_heads', type=int, default=int(model_name.split('+')[10].split('.')[0]), help='Number of attention head')

    parser.add_argument('--data_dir', type=str, default='data/', help='The address of preprocessed graph.')
    parser.add_argument('--use_pretrain', type=int, default=1)
    parser.add_argument('--pretrain_model_dir', type=str, default=f'GPRP/models/pre_model/{model_name}', help='The address for pretrained model.')
    parser.add_argument('--model_dir', type=str, default='GPRP/models/fin_node',
                        help='The address for storing the models and optimization results.')
    parser.add_argument('--task_name', type=str, default='node', help='The name of the stored models and optimization results.')
    parser.add_argument('--cuda', type=int, default=3, help='Avaiable GPU ID')
    
    
    # parser.add_argument('--sample_depth', type=int, default=1, help='How many numbers to sample the graph')
    # parser.add_argument('--sample_width', type=int, default=32, help='How many nodes to be sampled per layer per type')
    
    # Model arguments 
    #parser.add_argument('--conv_name', type=str, default='gcn',
    #                    choices=['hgt', 'gcn', 'gat', 'rgcn', 'han', 'hetgnn'], help='The name of GNN filter. By default is Heterogeneous Graph Transformer (hgt)')
    # parser.add_argument('--n_hid', type=int, default=400, help='Number of hidden dimension')
    # parser.add_argument('--n_heads', type=int, default=8, help='Number of attention head')
    # parser.add_argument('--n_layers', type=int, default=3, help='Number of GNN layers')
    parser.add_argument('--prev_norm', help='Whether to add layer-norm on the previous layers', action='store_true')
    parser.add_argument('--last_norm', help='Whether to add layer-norm on the last layers',     action='store_true')
    parser.add_argument('--dropout', type=int, default=0.2, help='Dropout ratio')

    # Optimization arguments
    parser.add_argument('--optimizer', type=str, default='adamw',
                        choices=['adamw', 'adam', 'sgd', 'adagrad'], help='optimizer to use.')
    parser.add_argument('--data_percentage', type=int, default=0.1, help='Percentage of training and validation data to use')
    # parser.add_argument('--n_epoch', type=int, default=150, help='Number of epoch to run')
    parser.add_argument('--n_pool', type=int, default=8, help='Number of process to sample subgraph')    
    # parser.add_argument('--n_batch', type=int, default=15, help='Number of batch (sampled graphs) for each epoch') 
    #parser.add_argument('--batch_size', type=int, default=64, help='Number of output nodes for training')    
    parser.add_argument('--clip', type=int, default=0.5, help='Gradient Norm Clipping') 
    args = parser.parse_args()
    return args

def configure_link():
    parser = argparse.ArgumentParser(description='Fine-Tuning on node classification task')
    parser.add_argument('--net_type', type=str, default='fat',
                    help='Type of network architecture') 
    # Dataset arguments
    parser.add_argument('--premodel', type=str, default='1208selfpre+hgt+128+200+0.001+25+4+1+32+10+8.pk', help='premodel name')
    model_name_ = parser.parse_args()
    model_name = model_name_.premodel
    # parser.add_argument('--premodel', type=str, default=model_name, help='premodel name')
    parser.add_argument('--conv_name', type=str, default=model_name.split('+')[1],
                    choices=['hgt', 'gcn','gat', 'rgcn' ,'han', 'sage'], help='The name of GNN filter. By default is Heterogeneous Graph Transformer (hgt)')
    parser.add_argument('--batch_size', type=int, default=int(model_name.split('+')[2]), help='Number of output nodes for training')
    parser.add_argument('--n_hid', type=int, default=int(model_name.split('+')[3]), help='Number of hidden dimension')
    parser.add_argument('--n_epoch', type=int, default=10, help='Number of epoch to run')
    parser.add_argument('--n_layers', type=int, default=int(model_name.split('+')[6]), help='Number of attention head')
    parser.add_argument('--sample_depth', type=int, default=int(model_name.split('+')[7]), help='Number of GNN layers')
    parser.add_argument('--sample_width', type=int, default=int(model_name.split('+')[8]), help='Number of attention head')
    parser.add_argument('--n_batch', type=int, default=int(model_name.split('+')[9]), help='')
    parser.add_argument('--n_heads', type=int, default=int(model_name.split('+')[10].split('.')[0]), help='Number of attention head')





    parser.add_argument('--data_dir', type=str, default='data/', help='The address of preprocessed graph.')
    parser.add_argument('--use_pretrain', type=int, default=1)
    parser.add_argument('--pretrain_model_dir', type=str, default=f'GPRP/models/pre_model/{model_name}', help='The address for pretrained model.')
    parser.add_argument('--model_dir', type=str, default='GPRP/models/fin_link',
                        help='The address for storing the models and optimization results.')
    parser.add_argument('--task_name', type=str, default='link', help='The name of the stored models and optimization results.')
    parser.add_argument('--cuda', type=int, default=3, help='Avaiable GPU ID')     
    # parser.add_argument('--sample_depth', type=int, default=1, help='How many numbers to sample the graph')
    # parser.add_argument('--sample_width', type=int, default=32, help='How many nodes to be sampled per layer per type')
    
    # Model arguments 
    # parser.add_argument('--conv_name', type=str, default='gcn',
    #                     choices=['hgt', 'gcn', 'gat', 'rgcn', 'han', 'hetgnn'], help='The name of GNN filter. By default is Heterogeneous Graph Transformer (hgt)')
    # parser.add_argument('--n_hid', type=int, default=400, help='Number of hidden dimension')
    # parser.add_argument('--n_heads', type=int, default=8, help='Number of attention head')
    # parser.add_argument('--n_layers', type=int, default=3, help='Number of GNN layers')
    parser.add_argument('--prev_norm', help='Whether to add layer-norm on the previous layers', action='store_true')
    parser.add_argument('--last_norm', help='Whether to add layer-norm on the last layers',     action='store_true')
    parser.add_argument('--dropout', type=int, default=0.2, help='Dropout ratio')

    # Optimization arguments
    parser.add_argument('--optimizer', type=str, default='adamw',
                        choices=['adamw', 'adam', 'sgd', 'adagrad'], help='optimizer to use.')
    parser.add_argument('--data_percentage', type=int, default=0.1, help='Percentage of training and validation data to use')
    # parser.add_argument('--n_epoch', type=int, default=150, help='Number of epoch to run')
    parser.add_argument('--n_pool', type=int, default=8, help='Number of process to sample subgraph')    
    # parser.add_argument('--n_batch', type=int, default=15, help='Number of batch (sampled graphs) for each epoch') 
    # parser.add_argument('--batch_size', type=int, default=64, help='Number of output nodes for training')    
    parser.add_argument('--clip', type=int, default=0.5, help='Gradient Norm Clipping') 
    args = parser.parse_args()
    return args

def iiiiconfigure():
    parser = argparse.ArgumentParser(description='Fine-Tuning on node classification task')
    # Dataset arguments
    parser.add_argument('--premodel', type=str, default='1208selfpre+hgt+128+200+0.001+25+4+1+32+10+8.pk', help='premodel name')
    model_name_ = parser.parse_args()
    model_name = model_name_.premodel
    parser.add_argument('--conv_name', type=str, default=model_name.split('+')[1],
                    choices=['hgt', 'gcn','gat', 'rgcn' ,'han', 'sage'], help='The name of GNN filter. By default is Heterogeneous Graph Transformer (hgt)')
    parser.add_argument('--cccc',type = int,default = 0,help = 'the number of train graph')
    parser.add_argument('--batch_size', type=int, default=int(model_name.split('+')[2]), help='Number of output nodes for training')
    parser.add_argument('--n_hid', type=int, default=int(model_name.split('+')[3]), help='Number of hidden dimension')
    parser.add_argument('--n_epoch', type=int, default=10, help='Number of epoch to run')
    parser.add_argument('--n_layers', type=int, default=int(model_name.split('+')[6]), help='Number of attention head')
    parser.add_argument('--sample_depth', type=int, default=int(model_name.split('+')[7]), help='Number of GNN layers')
    parser.add_argument('--sample_width', type=int, default=int(model_name.split('+')[8]), help='Number of attention head')
    parser.add_argument('--n_batch', type=int, default=int(model_name.split('+')[9]), help='')
    parser.add_argument('--n_heads', type=int, default=int(model_name.split('+')[10].split('.')[0]), help='Number of attention head')

    parser.add_argument('--data_dir', type=str, default='newdata/', help='The address of preprocessed graph.')
    parser.add_argument('--use_pretrain', type=int, default=1)
    parser.add_argument('--pretrain_model_dir', type=str, default=f'GPRP/models/pre_model/{model_name}', help='The address for pretrained model.')
    parser.add_argument('--model_dir', type=str, default='GPRP/models/fin_node',
                        help='The address for storing the models and optimization results.')
    parser.add_argument('--task_name', type=str, default='node', help='The name of the stored models and optimization results.')
    parser.add_argument('--cuda', type=int, default=3, help='Avaiable GPU ID')
    
    
    # parser.add_argument('--sample_depth', type=int, default=1, help='How many numbers to sample the graph')
    # parser.add_argument('--sample_width', type=int, default=32, help='How many nodes to be sampled per layer per type')
    
    # Model arguments 
    #parser.add_argument('--conv_name', type=str, default='gcn',
    #                    choices=['hgt', 'gcn', 'gat', 'rgcn', 'han', 'hetgnn'], help='The name of GNN filter. By default is Heterogeneous Graph Transformer (hgt)')
    # parser.add_argument('--n_hid', type=int, default=400, help='Number of hidden dimension')
    # parser.add_argument('--n_heads', type=int, default=8, help='Number of attention head')
    # parser.add_argument('--n_layers', type=int, default=3, help='Number of GNN layers')
    parser.add_argument('--prev_norm', help='Whether to add layer-norm on the previous layers', action='store_true')
    parser.add_argument('--last_norm', help='Whether to add layer-norm on the last layers',     action='store_true')
    parser.add_argument('--dropout', type=int, default=0.2, help='Dropout ratio')

    # Optimization arguments
    parser.add_argument('--optimizer', type=str, default='adamw',
                        choices=['adamw', 'adam', 'sgd', 'adagrad'], help='optimizer to use.')
    parser.add_argument('--data_percentage', type=int, default=0.1, help='Percentage of training and validation data to use')
    # parser.add_argument('--n_epoch', type=int, default=150, help='Number of epoch to run')
    parser.add_argument('--n_pool', type=int, default=8, help='Number of process to sample subgraph')    
    # parser.add_argument('--n_batch', type=int, default=15, help='Number of batch (sampled graphs) for each epoch') 
    #parser.add_argument('--batch_size', type=int, default=64, help='Number of output nodes for training')    
    parser.add_argument('--clip', type=int, default=0.5, help='Gradient Norm Clipping') 
    args = parser.parse_args()
    return args

def iiiiconfigure_link():
    parser = argparse.ArgumentParser(description='Fine-Tuning on node classification task')
    # Dataset arguments
    parser.add_argument('--premodel', type=str, default='1208selfpre+hgt+128+200+0.001+25+4+1+32+10+8.pk', help='premodel name')
    model_name_ = parser.parse_args()
    model_name = model_name_.premodel
    # parser.add_argument('--premodel', type=str, default=model_name, help='premodel name')
    parser.add_argument('--conv_name', type=str, default=model_name.split('+')[1],
                    choices=['hgt', 'gcn','gat', 'rgcn' ,'han', 'sage'], help='The name of GNN filter. By default is Heterogeneous Graph Transformer (hgt)')
    parser.add_argument('--cccc',type = int,default = 0,help = 'the number of train graph')
    parser.add_argument('--batch_size', type=int, default=int(model_name.split('+')[2]), help='Number of output nodes for training')
    parser.add_argument('--n_hid', type=int, default=int(model_name.split('+')[3]), help='Number of hidden dimension')
    parser.add_argument('--n_epoch', type=int, default=10, help='Number of epoch to run')
    parser.add_argument('--n_layers', type=int, default=int(model_name.split('+')[6]), help='Number of attention head')
    parser.add_argument('--sample_depth', type=int, default=int(model_name.split('+')[7]), help='Number of GNN layers')
    parser.add_argument('--sample_width', type=int, default=int(model_name.split('+')[8]), help='Number of attention head')
    parser.add_argument('--n_batch', type=int, default=int(model_name.split('+')[9]), help='')
    parser.add_argument('--n_heads', type=int, default=int(model_name.split('+')[10].split('.')[0]), help='Number of attention head')





    parser.add_argument('--data_dir', type=str, default='newdata/', help='The address of preprocessed graph.')
    parser.add_argument('--use_pretrain', type=int, default=1)
    parser.add_argument('--pretrain_model_dir', type=str, default=f'GPRP/models/pre_model/{model_name}', help='The address for pretrained model.')
    parser.add_argument('--model_dir', type=str, default='GPRP/models/fin_link',
                        help='The address for storing the models and optimization results.')
    parser.add_argument('--task_name', type=str, default='link', help='The name of the stored models and optimization results.')
    parser.add_argument('--cuda', type=int, default=3, help='Avaiable GPU ID')     
    # parser.add_argument('--sample_depth', type=int, default=1, help='How many numbers to sample the graph')
    # parser.add_argument('--sample_width', type=int, default=32, help='How many nodes to be sampled per layer per type')
    
    # Model arguments 
    # parser.add_argument('--conv_name', type=str, default='gcn',
    #                     choices=['hgt', 'gcn', 'gat', 'rgcn', 'han', 'hetgnn'], help='The name of GNN filter. By default is Heterogeneous Graph Transformer (hgt)')
    # parser.add_argument('--n_hid', type=int, default=400, help='Number of hidden dimension')
    # parser.add_argument('--n_heads', type=int, default=8, help='Number of attention head')
    # parser.add_argument('--n_layers', type=int, default=3, help='Number of GNN layers')
    parser.add_argument('--prev_norm', help='Whether to add layer-norm on the previous layers', action='store_true')
    parser.add_argument('--last_norm', help='Whether to add layer-norm on the last layers',     action='store_true')
    parser.add_argument('--dropout', type=int, default=0.2, help='Dropout ratio')

    # Optimization arguments
    parser.add_argument('--optimizer', type=str, default='adamw',
                        choices=['adamw', 'adam', 'sgd', 'adagrad'], help='optimizer to use.')
    parser.add_argument('--data_percentage', type=int, default=0.1, help='Percentage of training and validation data to use')
    # parser.add_argument('--n_epoch', type=int, default=150, help='Number of epoch to run')
    parser.add_argument('--n_pool', type=int, default=8, help='Number of process to sample subgraph')    
    # parser.add_argument('--n_batch', type=int, default=15, help='Number of batch (sampled graphs) for each epoch') 
    # parser.add_argument('--batch_size', type=int, default=64, help='Number of output nodes for training')    
    parser.add_argument('--clip', type=int, default=0.5, help='Gradient Norm Clipping') 
    args = parser.parse_args()
    return args


def to_torch(feature, time, edge_list, graph):
    '''
        Transform a sampled sub-graph into pytorch Tensor
        node_dict: {node_type: <node_number, node_type_ID>} node_number is used to trace back the nodes in original graph.
        edge_dict: {edge_type: edge_type_ID}
    '''
    node_dict = {}
    node_feature = []
    node_type    = []
    node_time    = []
    edge_index   = []
    edge_type    = []
    edge_time    = []
    
    node_num = 0
    types = graph.get_types()
    for t in types:
        node_dict[t] = [node_num, len(node_dict)]
        node_num     += len(feature[t])

    if 'fake_paper' in feature:
        node_dict['fake_paper'] = [node_num, node_dict['paper'][1]]
        node_num     += len(feature['fake_paper'])
        types += ['fake_paper']
        
    for t in types:
        node_feature += list(feature[t])
        node_time    += list(time[t])
        node_type    += [node_dict[t][1] for _ in range(len(feature[t]))]
        
    edge_dict = {e[2]: i for i, e in enumerate(graph.get_meta_graph())}
    edge_dict['self'] = len(edge_dict)

    for target_type in edge_list:
        for source_type in edge_list[target_type]:
            for relation_type in edge_list[target_type][source_type]:
                for ii, (ti, si) in enumerate(edge_list[target_type][source_type][relation_type]):
                    tid, sid = ti + node_dict[target_type][0], si + node_dict[source_type][0]
                    edge_index += [[sid, tid]]
                    edge_type  += [edge_dict[relation_type]]   
                    '''
                        Our time ranges from 1900 - 2020, largest span is 120.
                    '''
                    edge_time  += [node_time[tid] - node_time[sid] + 120]
    node_feature = torch.FloatTensor(node_feature)
    node_type    = torch.LongTensor(node_type)
    edge_time    = torch.LongTensor(edge_time)
    edge_index   = torch.LongTensor(edge_index).t()
    edge_type    = torch.LongTensor(edge_type)
    return node_feature, node_type, edge_time, edge_index, edge_type, node_dict, edge_dict

def norm_prob(array):
    score = np.power(array, 2)
    score = score / np.sum(score)
    return score

def write_json(info_dict, out_dir, serial_key=False):
    if serial_key:
        info_dict = {'_'.join([str(i) for i in k]):v for k,v in info_dict.items()}
    with open(out_dir, "w") as f:
        json.dump(info_dict, f)

def load_json(input_dir, serial_key=False):
    ret_dict = json.load(open(input_dir))
    if serial_key:
        ret_dict = {tuple([int(i) for i in k.split('_')]):[tuple(l) for l in v] for k,v in ret_dict.items()}
    return ret_dict

def dcg_at_k(r, k):
    r = np.asfarray(r)[:k]
    if r.size:
        return r[0] + np.sum(r[1:] / np.log2(np.arange(2, r.size + 1)))
    return 0.

def ndcg_at_k(r, k):
    dcg_max = dcg_at_k(sorted(r, reverse=True), k)
    if not dcg_max:
        return 0.
    return dcg_at_k(r, k) / dcg_max

def mean_reciprocal_rank(rs):
    rs = (np.asarray(r).nonzero()[0] for r in rs)
    return [1. / (r[0] + 1) if r.size else 0. for r in rs]

