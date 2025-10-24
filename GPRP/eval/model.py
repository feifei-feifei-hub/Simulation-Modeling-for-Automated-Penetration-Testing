import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, GATConv, RGCNConv,SAGEConv,HANConv,GAE
from torch_geometric.nn.conv import MessagePassing
from torch_geometric.nn.inits import glorot, uniform
from torch_geometric.utils import softmax
import math

class Classifier(nn.Module):
    def __init__(self, n_hid, n_out):
        super(Classifier, self).__init__()
        self.n_hid    = n_hid
        self.n_out    = n_out
        self.linear   = nn.Linear(n_hid,  n_out)
        
    def forward(self, x):
        tx = self.linear(x)
        return tx.squeeze()
    
    def __repr__(self):
        return '{}(n_hid={}, n_out={})'.format(
            self.__class__.__name__, self.n_hid, self.n_out)
    
class Linkprediction(nn.Module):
    def __init__(self, n_hid, n_out, temperature = 0.1):
        super(Linkprediction, self).__init__()
        self.n_hid          = n_hid
        self.linear    = nn.Linear(n_hid,  n_out)
        self.sqrt_hd     = math.sqrt(n_out)
        self.drop        = nn.Dropout(0.2)
        self.cosine      = nn.CosineSimilarity(dim=1)#torch.nn.CosineSimilarity函数计算两个高维特征图(B,C,H,W)中各个像素位置的特征相似度,余弦相似度距离
        self.cache       = None
        self.temperature = temperature
    def forward(self, x, ty):
        tx = self.drop(self.linear(x))
        return self.cosine(tx, ty) / self.temperature


class Matcher(nn.Module):
    def __init__(self, n_hid, n_out, temperature = 0.1):
        super(Matcher, self).__init__()
        self.n_hid       = n_hid
        self.linear      = nn.Linear(n_hid,  n_out)
        self.sqrt_hd     = math.sqrt(n_out)
        self.drop        = nn.Dropout(0.2)
        self.cosine      = nn.CosineSimilarity(dim=1)
        self.cache       = None
        self.temperature = temperature

    def forward(self, x, ty, use_norm = True):
        tx = self.drop(self.linear(x))
        if use_norm:
            return self.cosine(tx, ty) / self.temperature
        else:
            return (tx * ty).sum(dim=-1) / self.sqrt_hd
        
    def __repr__(self):
        return '{}(n_hid={})'.format(
            self.__class__.__name__, self.n_hid)

class GNN(nn.Module):
    def __init__(self, in_dim, n_hid, num_types, num_relations, n_heads, n_layers, dropout = 0.2, conv_name = 'hgt', prev_norm = False, last_norm = False, use_RTE = True):
        super(GNN, self).__init__()
        self.gcs = nn.ModuleList()
        self.num_types = num_types
        self.in_dim    = in_dim
        self.n_hid     = n_hid
        self.adapt_ws  = nn.ModuleList()
        self.drop      = nn.Dropout(dropout)
        for t in range(num_types):
            self.adapt_ws.append(nn.Linear(in_dim, n_hid))
        for l in range(n_layers - 1):
            self.gcs.append(GeneralConv(conv_name, n_hid, n_hid, num_types, num_relations, n_heads, dropout, use_norm = prev_norm, use_RTE = use_RTE))
        self.gcs.append(GeneralConv(conv_name, n_hid, n_hid, num_types, num_relations, n_heads, dropout, use_norm = last_norm, use_RTE = use_RTE))

    def forward(self, node_feature, node_type, edge_time, edge_index, edge_type):
        res = torch.zeros(node_feature.size(0), self.n_hid, device=node_feature.device)
        for t_id in range(self.num_types):
            idx = (node_type == int(t_id))
            if idx.sum() == 0: continue
            res[idx] = torch.tanh(self.adapt_ws[t_id](node_feature[idx]))
        meta_xs = self.drop(res)
        del res
        for gc in self.gcs:
            meta_xs = gc(meta_xs, node_type, edge_index, edge_type, edge_time)
        return meta_xs   

class RNNModel(nn.Module):
    def __init__(self, n_word, ninp, nhid, nlayers, dropout=0.2):
        super(RNNModel, self).__init__()
        self.drop = nn.Dropout(dropout)
        self.rnn = nn.LSTM(nhid, nhid, nlayers)
        self.encoder = nn.Embedding(n_word, nhid)
        self.decoder = nn.Linear(nhid, n_word)
        self.adp     = nn.Linear(ninp + nhid, nhid)
    def forward(self, inp, hidden = None):
        emb = self.encoder(inp)
        if hidden is not None:
            emb = torch.cat((emb, hidden), dim=-1)
            emb = F.gelu(self.adp(emb))
        output, _ = self.rnn(emb)
        decoded = self.decoder(self.drop(output))
        return decoded
    def from_w2v(self, w2v):
        initrange = 0.1
        self.encoder.weight.data = w2v
        self.decoder.weight = self.encoder.weight
        
        self.encoder.weight.requires_grad = False
        self.decoder.weight.requires_grad = False

class GeneralConv(nn.Module):
    def __init__(self, conv_name, in_hid, out_hid, num_types, num_relations, n_heads, dropout, use_norm = True, use_RTE = True):
        super(GeneralConv, self).__init__()
        self.conv_name = conv_name
        if self.conv_name == 'hgt':
            self.base_conv = HGTConv(in_hid, out_hid, num_types, num_relations, n_heads, dropout, use_norm, use_RTE)
        elif self.conv_name == 'gcn':
            self.base_conv = GCNConv(in_hid, out_hid)
        elif self.conv_name == 'gat':
            self.base_conv = GATConv(in_hid, out_hid // n_heads, heads=n_heads)
        elif self.conv_name == 'rgcn':
            self.base_conv = RGCNConv(in_hid, out_hid, num_relations)
        elif self.conv_name == 'sage':
            self.base_conv = SAGEConv(in_hid, out_hid)
        elif self.conv_name == 'han':
            metadata = (
                            ['def'],
                            [
                                ('def','def','def')
                            ]
                        )
            self.base_conv = HANConv(in_hid, out_hid, metadata,heads=n_heads, dropout=dropout)
        elif self.conv_name == 'gae':
            self.base_conv = GAE(in_hid, out_hid)
    def forward(self, meta_xs, node_type, edge_index, edge_type, edge_time):
        if self.conv_name == 'hgt':
            return self.base_conv(meta_xs, node_type, edge_index, edge_type, edge_time)
        elif self.conv_name == 'gcn':
            return self.base_conv(meta_xs, edge_index)
        elif self.conv_name == 'gat':
            return self.base_conv(meta_xs, edge_index)
        elif self.conv_name == 'rgcn':
            return self.base_conv(meta_xs, edge_index, edge_type)
        elif self.conv_name == 'sage':
            return self.base_conv(meta_xs, edge_index)
        elif self.conv_name == 'han':
            if type(meta_xs) != dict:
                x_dict = {'def': meta_xs}
            else:
                x_dict = meta_xs
            edge_index_dict = {('def','def','def'):edge_index}
            return self.base_conv(x_dict,edge_index_dict)
        elif self.conv_name == 'gae':
            a = self.base_conv(meta_xs, edge_index)
            return a
        

class HGTConv(MessagePassing):
    def __init__(self, in_dim, out_dim, num_types, num_relations, n_heads, dropout = 0.2, use_norm = True, use_RTE = True, **kwargs):
        super(HGTConv, self).__init__(node_dim=0, aggr='add', **kwargs)
        self.in_dim        = in_dim
        self.out_dim       = out_dim
        self.num_types     = num_types
        self.num_relations = num_relations
        self.total_rel     = num_types * num_relations * num_types
        self.n_heads       = n_heads
        self.d_k           = out_dim // n_heads
        self.sqrt_dk       = math.sqrt(self.d_k)
        self.use_norm      = use_norm
        self.att           = None
        self.k_linears   = nn.ModuleList()
        self.q_linears   = nn.ModuleList()
        self.v_linears   = nn.ModuleList()
        self.a_linears   = nn.ModuleList()
        self.norms       = nn.ModuleList()
        for t in range(num_types):
            self.k_linears.append(nn.Linear(in_dim,   out_dim))
            self.q_linears.append(nn.Linear(in_dim,   out_dim))
            self.v_linears.append(nn.Linear(in_dim,   out_dim))
            self.a_linears.append(nn.Linear(out_dim,  out_dim))
            if use_norm:
                self.norms.append(nn.LayerNorm(out_dim))
        self.relation_pri   = nn.Parameter(torch.ones(num_relations, self.n_heads))
        self.relation_att   = nn.Parameter(torch.Tensor(num_relations, n_heads, self.d_k, self.d_k))
        self.relation_msg   = nn.Parameter(torch.Tensor(num_relations, n_heads, self.d_k, self.d_k))
        self.skip           = nn.Parameter(torch.ones(num_types))
        self.drop           = nn.Dropout(dropout)
        self.emb            = RelTemporalEncoding(in_dim)
        glorot(self.relation_att)
        glorot(self.relation_msg)
        
    def forward(self, node_inp, node_type, edge_index, edge_type, edge_time):
        return self.propagate(edge_index, node_inp=node_inp, node_type=node_type, edge_type=edge_type, edge_time = edge_time)

    def message(self, edge_index_i, node_inp_i, node_inp_j, node_type_i, node_type_j, edge_type, edge_time):
        data_size = edge_index_i.size(0)
        res_att     = torch.zeros(data_size, self.n_heads, device=node_inp_i.device)
        res_msg     = torch.zeros(data_size, self.n_heads, self.d_k, device=node_inp_i.device)
        for source_type in range(self.num_types):
            sb = (node_type_j == int(source_type))
            k_linear = self.k_linears[source_type]
            v_linear = self.v_linears[source_type] 
            for target_type in range(self.num_types):
                tb = (node_type_i == int(target_type)) & sb
                q_linear = self.q_linears[target_type]
                for relation_type in range(self.num_relations):
                    idx = (edge_type == int(relation_type)) & tb
                    if idx.sum() == 0: continue
                    target_node_vec = node_inp_i[idx]
                    source_node_vec = self.emb(node_inp_j[idx], edge_time[idx])
                    q_mat = q_linear(target_node_vec).view(-1, self.n_heads, self.d_k)
                    k_mat = k_linear(source_node_vec).view(-1, self.n_heads, self.d_k)
                    k_mat = torch.bmm(k_mat.transpose(1,0), self.relation_att[relation_type]).transpose(1,0)
                    res_att[idx] = (q_mat * k_mat).sum(dim=-1) * self.relation_pri[relation_type] / self.sqrt_dk
                    v_mat = v_linear(source_node_vec).view(-1, self.n_heads, self.d_k)
                    res_msg[idx] = torch.bmm(v_mat.transpose(1,0), self.relation_msg[relation_type]).transpose(1,0)   
        self.att = softmax(res_att, edge_index_i)
        res = res_msg * self.att.view(-1, self.n_heads, 1)
        del res_att, res_msg
        return res.view(-1, self.out_dim)

    def update(self, aggr_out, node_inp, node_type):
        aggr_out = F.gelu(aggr_out)
        res = torch.zeros(aggr_out.size(0), self.out_dim, device=node_inp.device)
        for target_type in range(self.num_types):
            idx = (node_type == int(target_type))
            if idx.sum() == 0:
                continue
            trans_out = self.a_linears[target_type](aggr_out[idx])
            alpha = torch.sigmoid(self.skip[target_type])
            if self.use_norm:
                res[idx] = self.norms[target_type](trans_out * alpha + node_inp[idx] * (1 - alpha))
            else:
                res[idx] = trans_out * alpha + node_inp[idx] * (1 - alpha)
        return self.drop(res)

    def __repr__(self):
        return '{}(in_dim={}, out_dim={}, num_types={}, num_types={})'.format(
            self.__class__.__name__, self.in_dim, self.out_dim,
            self.num_types, self.num_relations)

class RelTemporalEncoding(nn.Module):
    def __init__(self, n_hid, max_len = 240, dropout = 0.2):
        super(RelTemporalEncoding, self).__init__()
        self.drop = nn.Dropout(dropout)
        position = torch.arange(0., max_len).unsqueeze(1)
        div_term = 1 / (10000 ** (torch.arange(0., n_hid * 2, 2.)) / n_hid / 2)
        self.emb = nn.Embedding(max_len, n_hid * 2)
        self.emb.weight.data[:, 0::2] = torch.sin(position * div_term) / math.sqrt(n_hid)
        self.emb.weight.data[:, 1::2] = torch.cos(position * div_term) / math.sqrt(n_hid)
        self.emb.requires_grad = False
        self.lin = nn.Linear(n_hid * 2, n_hid)

    def forward(self, x, t):
        return x + self.lin(self.drop(self.emb(t)))