import os
import random
from sklearn.metrics import f1_score, roc_auc_score, log_loss,roc_auc_score
#import os
os.environ['CUDA_LAUNCH_BLOCKING'] = '1'
import dill
from graph import Graph, Graph_test
from model import *
from warnings import filterwarnings
#from sklearn.metrics import f1_score
from utils import configure_link, mean_reciprocal_rank, ndcg_at_k
from collections import OrderedDict, defaultdict
import multiprocessing as mp
from torch_geometric.utils import negative_sampling
import warnings
warnings.filterwarnings("ignore")


class Trainer:
    def __init__(self, args):
        for key, val in vars(args).items(): setattr(self, key, val);
        self.device = torch.device(f"cuda:{args.cuda}") if args.cuda!=-1 else torch.device("cpu")
        self.graph = Graph(args, self.device)
        self.gnn = GNN(in_dim=self.graph.node_feature[10].shape[-1], n_hid=self.n_hid, num_types=1, num_relations=2, n_heads=self.n_heads, n_layers=self.n_layers,
                       dropout=self.dropout, conv_name=self.conv_name, prev_norm=self.prev_norm, last_norm=self.last_norm, use_RTE=False)
        if self.use_pretrain:
            model_dict = torch.load(self.pretrain_model_dir, map_location= self.device)
            out_dict = OrderedDict({key[4:]:model_dict[key] for key in model_dict if 'gnn' in key})
            self.gnn.load_state_dict(out_dict, strict=False)
        #self.classifier = Classifier(self.n_hid, self.graph.y.size(-1))
        self.linkpre = Linkprediction(self.n_hid,self.n_hid,)
        #self.model = nn.Sequential(self.gnn, self.classifier).to(self.device)#把两个模型序贯组合成一个模型
        self.model = nn.Sequential(self.gnn, self.linkpre).to(self.device)#把两个模型序贯组合成一个模型
        self.criterion = nn.BCEWithLogitsLoss()#链路预测里面没有用到
        self.optimizer = torch.optim.AdamW(self.model.parameters(), lr=5e-4)
        self.scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(self.optimizer, 500, eta_min=1e-6)
    
    def train(self):
        stats, res, best_val, train_step = [], [], 0, 0
        for epoch in np.arange(self.n_epoch)+1:
            valid_datas = []
            train_datas = []
            valid_pairs_all = []
            for c in range(10,11):
                valid_data = self.graph.NC_sample('valid', c)
                train_data = [self.graph.NC_sample('train', c) for _ in range(self.n_batch)]
                valid_datas.append(valid_data)
                train_datas.append(train_data)
                valid_pairs = {}
                for i in valid_data[-1]:#这里应该设置一个节点属性，定义为被发现还是没有被发现，被发现的才能作为训练集
                    valid_pairs[i] = self.graph.edge_list[c][i]
                valid_pairs_all.append(valid_pairs)
            train_losses = []
            self.model.train()
            for train_data in train_datas:
                for node_feature, node_type, edge_time, edge_index, edge_type, x_ids, ylabel, samp_nodes in train_data:
                    node_rep = self.gnn.forward(node_feature, node_type, edge_time, edge_index, edge_type)
                    train_neg_edge_index = neg_sampling(edge_index, force_undirected = True)
                    train_pos_y = torch.ones(edge_index.size(1), device=self.device)
                    train_neg_y = torch.zeros(train_neg_edge_index.size(1), device=self.device)
                    train_y = torch.cat([train_pos_y, train_neg_y], dim=0)
                    edge_index = torch.cat([edge_index, train_neg_edge_index], dim=1)
                    #打乱顺序
                    arr = list(range(0, train_y.size(0)))
                    random.shuffle(arr)
                    train_y = train_y[arr]
                    edge_index = torch.stack((edge_index[0][arr],edge_index[1][arr]),dim = 0)
                    head = edge_index[0]; tail = edge_index[1]
                    train_head_vecs = node_rep[head]; train_tail_vecs = node_rep[tail]

                    res = self.linkpre.forward(train_head_vecs, train_tail_vecs)
                    loss = F.binary_cross_entropy_with_logits(res, train_y)
                    self.optimizer.zero_grad() 
                    torch.cuda.empty_cache()
                    loss.backward()
                    torch.nn.utils.clip_grad_norm_(self.model.parameters(), args.clip)
                    self.optimizer.step()

                    train_losses += [loss.cpu().detach().tolist()]; train_step += 1
                    self.scheduler.step(train_step)

            self.model.eval()
            with torch.no_grad():
                node_feature, node_type, edge_time, edge_index, edge_type, x_ids, ylabel, samp_nodes = valid_data
                node_rep = self.gnn.forward(node_feature, node_type, edge_time, edge_index, edge_type)
                eval_neg_edge_index = neg_sampling(edge_index,force_undirected = True)
                eval_pos_y = torch.ones(edge_index.size(1), device=self.device)
                eval_neg_y = torch.zeros(eval_neg_edge_index.size(1), device=self.device)
                eval_y = torch.cat([eval_pos_y, eval_neg_y], dim=0)
                edge_index = torch.cat([edge_index, eval_neg_edge_index], dim=1)
                #打乱顺序
                arr = list(range(0, eval_y.size(0)))
                random.shuffle(arr)
                eval_y = eval_y[arr]
                edge_index = torch.stack((edge_index[0][arr], edge_index[1][arr]),dim = 0)
                head = edge_index[0]
                tail = edge_index[1]
                eval_head_vecs = node_rep[head]
                eval_tail_vecs = node_rep[tail]
                res = self.linkpre.forward(eval_head_vecs, eval_tail_vecs)
                loss = F.binary_cross_entropy_with_logits(res, eval_y)
        
                '''
                    Calculate Valid NDCG. Update the best model based on highest NDCG score.
                '''
                #准确率计算AUC指标

                valid_AUC = roc_auc_score(eval_y.cpu().numpy(), np.where(torch.sigmoid(res.squeeze()).cpu().numpy()>0.5,1,0))
                if valid_AUC > best_val:
                    best_val = valid_AUC
                    torch.save(self.model, os.path.join(args.model_dir, args.task_name+ '_' + str(args.use_pretrain) + '_' + args.conv_name))
                print(("Epoch: %d  LR: %.5f Train Loss: %.2f  Valid Loss: %.2f  Valid AUC: %.4f") % \
                    (epoch, self.optimizer.param_groups[0]['lr'], np.average(train_losses), loss.cpu().detach().tolist(), valid_AUC))
                stats += [[np.average(train_losses), loss.cpu().detach().tolist()]]
        del res, loss,  valid_datas,train_datas
#AUC
        #         if valid_ndcg > best_val:
        #             best_val = valid_ndcg
        #             torch.save(self.model, os.path.join(args.model_dir, args.task_name + '_' + args.conv_name + "link"))
        #             print('UPDATE!!!')
        #         print(("Epoch: %d   LR: %.5f Train Loss: %.2f  Valid Loss: %.2f  Valid NDCG: %.4f  Valid MRR: %.4f") % \
        #                 (epoch, self.param_groups[0]['lr'], np.average(train_losses), \
        #             loss.cpu().detach().tolist(), valid_ndcg, valid_mrr))
        #         stats += [[np.average(train_losses), loss.cpu().detach().tolist()]]
        # del res, loss, train_data, valid_data
    
    @torch.no_grad()
    def test(self):
        best_model = torch.load(os.path.join(args.model_dir, args.task_name+ '_' + str(args.use_pretrain) + '_' + args.conv_name)).to(self.device)
        best_model.eval()
        gnn, linkpre = best_model
        test_res = []
        self.test_graph = Graph_test(args, self.device)
        #self.graph = Graph(args, 15, self.device)
        for _ in range(10):#10次测试的平均值
            test_data =  self.test_graph.NC_sample('test', self.test_graph.c)
            node_feature, node_type, edge_time, edge_index, edge_type, x_ids, ylabel, samp_nodes = test_data
            node_rep = gnn.forward(node_feature, node_type, edge_time, edge_index, edge_type)

            test_neg_edge_index = neg_sampling(edge_index,force_undirected = True)
            test_pos_y = torch.ones(edge_index.size(1), device=self.device)
            test_neg_y = torch.zeros(test_neg_edge_index.size(1), device=self.device)
            test_y = torch.cat([test_pos_y, test_neg_y], dim=0) 
            edge_index = torch.cat([edge_index, test_neg_edge_index], dim=1)
            #打乱顺序
            arr =list(range(0, test_y.size(0)))
            random.shuffle(arr)
            test_y = test_y[arr]
            edge_index = torch.stack((edge_index[0][arr],edge_index[1][arr]),dim = 0)
            head = edge_index[0]
            tail = edge_index[1]

            test_head_vecs = node_rep[head]
            test_tail_vecs = node_rep[tail]
            res = linkpre.forward(test_head_vecs, test_tail_vecs)
            loss = F.binary_cross_entropy_with_logits(res, test_y)
    
            '''
                Calculate Valid NDCG. Update the best model based on highest NDCG score.
            '''
            test_AUC = roc_auc_score(test_y.cpu().numpy(), np.where(torch.sigmoid(res.squeeze()).cpu().numpy()>0.5,1,0))
            test_res.append(test_AUC)
        print('Best Test AUC: %.4f' % np.average(test_res))
        print("test_res:",test_res)
            

def neg_sampling(edge_index, force_undirected):
    return negative_sampling(edge_index, force_undirected = force_undirected)

if __name__ == '__main__':
    args = configure_link()
    trainer = Trainer(args)
    trainer.train()
    trainer.test()
