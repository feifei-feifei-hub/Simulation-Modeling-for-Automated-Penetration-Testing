import sys
from GPT_GNN.data import *
from GPT_GNN.model import *
from warnings import filterwarnings
filterwarnings("ignore")
dill._dill._reverse_typemap['CodeType'] = dill._dill._create_code
import argparse

parser = argparse.ArgumentParser(description='Pre-training HGT on a given graph (heterogeneous / homogeneous)')

'''
   GPT-GNN arguments 
'''
parser.add_argument('--attr_ratio', type=float, default=0.5,
                    help='Ratio of attr-loss against link-loss, range: [0-1]') 
parser.add_argument('--attr_type', type=str, default='vec',
                    choices=['text', 'vec'],
                    help='The type of attribute decoder')
# parser.add_argument('--neg_samp_num', type=int, default=255,
#                     help='Maximum number of negative sample for each target node.')
parser.add_argument('--neg_samp_num', type=int, default=127,
                    help='Maximum number of negative sample for each target node.')
parser.add_argument('--queue_size', type=int, default=128,
                    help='Max size of adaptive embedding queue.')
parser.add_argument('--w2v_dir', type=str, default='/GPRP/datadrive/dataset/w2v_all',
                    help='The address of preprocessed graph.')

'''
    Dataset arguments
'''
parser.add_argument('--data_dir', type=str, default='./GPRP/datadrive/dataset/graph_net1000.pk',
                    help='The address of preprocessed graph.')
parser.add_argument('--pretrain_model_dir', type=str, default='models/new_pre_model',
                    help='The address for storing the pre-trained models.')
parser.add_argument('--cuda', type=int, default=1,
                    help='Avaiable GPU ID')      
parser.add_argument('--sample_depth', type=int, default=1,
                    help='How many layers within a mini-batch subgraph')
parser.add_argument('--sample_width', type=int, default=32,  
                    help='How many nodes to be sampled per layer per type')

'''
   Model arguments 
'''
parser.add_argument('--conv_name', type=str, default='hgt',
                    choices=['hgt', 'gcn', 'gat', 'rgcn', 'han', 'hetgnn'],
                    help='The name of GNN filter. By default is Heterogeneous Graph Transformer (hgt)')
parser.add_argument('--n_hid', type=int, default=800,
                    help='Number of hidden dimension')
parser.add_argument('--n_heads', type=int, default=8,
                    help='Number of attention head')
parser.add_argument('--n_layers', type=int, default=3,
                    help='Number of GNN layers')
parser.add_argument('--prev_norm', help='Whether to add layer-norm on the previous layers', action='store_true')
parser.add_argument('--last_norm', help='Whether to add layer-norm on the last layers',     action='store_true')
parser.add_argument('--dropout', type=int, default=0.2,
                    help='Dropout ratio')

'''
    Optimization arguments
'''
parser.add_argument('--max_lr', type=float, default=0.01,
                    help='Maximum learning rate.')
parser.add_argument('--scheduler', type=str, default='cycle',
                    help='Name of learsning rate scheduler.' , choices=['cycle', 'cosine'])
parser.add_argument('--n_epoch', type=int, default=40,
                    help='Number of epoch to run')
parser.add_argument('--n_pool', type=int, default=8,
                    help='Number of process to sample subgraph')    
parser.add_argument('--n_batch', type=int, default=5,
                    help='Number of batch (sampled graphs) for each epoch') #每一个epoch采样的sampled graphs的数量
parser.add_argument('--batch_size', type=int, default=128,
                    help='Number of output nodes for training')    
parser.add_argument('--clip', type=float, default=0.5,
                    help='Gradient Norm Clipping')  

args = parser.parse_args()
args_print(args)


if args.cuda != -1:
    device = torch.device("cuda:" + str(args.cuda))
else:
    device = torch.device("cpu")


print('Start Loading Graph Data...')
graphs = []
pre_target_nodes = []
train_target_nodes = []
for c in range(11):
    if c < 10:#预训练图
        graph_reddit_: Graph = dill.load(open(f'GPRP/datadrive/dataset/pre_graph_{c}.pk', 'rb'))
        pre_target_node = graph_reddit_.pre_target_nodes
        pre_target_node = np.concatenate([pre_target_node, np.ones(len(pre_target_node))]).reshape(2, -1).transpose()#-1表示列数自动计算，transpose()函数的作用就是调换数组的行列值的索引值
        pre_target_nodes.append(pre_target_node)
        graphs.append(graph_reddit_)

    elif c >= 10 and c <11:#训练图
        graph_reddit_: Graph = dill.load(open(f'GPRP/datadrive/dataset/train_graph_{c}.pk', 'rb'))
        train_target_node = graph_reddit_.train_target_nodes
        train_target_node = np.concatenate([train_target_node, np.ones(len(train_target_node))]).reshape(2, -1).transpose()
#转换过来就是array([[id,1],[id,1]])
        train_target_nodes.append(train_target_node)
        graphs.append(graph_reddit_)
    
print('Finish Loading Graph Data!')

target_type = 'def'
rel_stop_list = ['self']


def GPT_sample(seed, target_nodes, time_range, batch_size, num_graph, feature_extractor):
    np.random.seed(seed)
    graph_reddit = graphs[num_graph]
    samp_target_nodes = target_nodes[np.random.choice(len(target_nodes), batch_size)]#target_nodes在前几个进程就是pre_target_nodes训练数据集，最后一个就是测试数据集
    threshold   = 0.5
    feature, times, edge_list, _, attr = sample_subgraph(graph_reddit, time_range, \
                inp = {target_type: samp_target_nodes}, feature_extractor = feature_extractor, \
                    sampled_depth = args.sample_depth, sampled_number = args.sample_width)
    rem_edge_list = defaultdict(  #source_type
                        lambda: defaultdict(  #relation_type
                            lambda: [] # [target_id, source_id] 
                                ))
    
    ori_list = {}
    for source_type in edge_list[target_type]:
        ori_list[source_type] = {}
        for relation_type in edge_list[target_type][source_type]:
            ori_list[source_type][relation_type] = np.array(edge_list[target_type][source_type][relation_type])
            el = []
            for target_ser, source_ser in edge_list[target_type][source_type][relation_type]:
                if target_ser < source_ser:
                    if relation_type not in rel_stop_list and target_ser < batch_size and \
                           np.random.random() > threshold:
                        rem_edge_list[source_type][relation_type] += [[target_ser, source_ser]]
                        continue
                    el += [[target_ser, source_ser]]
                    el += [[source_ser, target_ser]]
            el = np.array(el)
            edge_list[target_type][source_type][relation_type] = el
            
            if relation_type == 'self':
                continue
                
    '''
        Adding feature nodes:
    '''
    n_target_nodes = len(feature[target_type])
    feature[target_type] = np.concatenate((feature[target_type], np.zeros([batch_size, feature[target_type].shape[1]])))
    times[target_type]   = np.concatenate((times[target_type], times[target_type][:batch_size]))

    for source_type in edge_list[target_type]:
        for relation_type in edge_list[target_type][source_type]:
            el = []
            for target_ser, source_ser in edge_list[target_type][source_type][relation_type]:
                if target_ser < batch_size:
                    if relation_type == 'self':
                        el += [[target_ser + n_target_nodes, target_ser + n_target_nodes]]
                    else:
                        el += [[target_ser + n_target_nodes, source_ser]]
            if len(el) > 0:
                edge_list[target_type][source_type][relation_type] = \
                    np.concatenate((edge_list[target_type][source_type][relation_type], el))


    rem_edge_lists = {}
    
    #print('attr:',len(attr))
    for source_type in rem_edge_list:
        rem_edge_lists[source_type] = {}
        for relation_type in rem_edge_list[source_type]:
            rem_edge_lists[source_type][relation_type] = np.array(rem_edge_list[source_type][relation_type])
    del rem_edge_list
    
          
    return to_torch(feature, times, edge_list, graph_reddit), rem_edge_lists, ori_list, \
            attr[:batch_size], (n_target_nodes, n_target_nodes + batch_size)




def prepare_data(pool):
    jobs = []
    for i in np.arange(10):
        num_graph = i
        jobs.append(pool.apply_async(GPT_sample, args=(randint(), pre_target_nodes[i], {1: True}, args.batch_size,num_graph, feature_reddit)))
    for i in np.arange(1):
        num_graph = i+10
        jobs.append(pool.apply_async(GPT_sample, args=(randint(), train_target_nodes[i], {1: True}, args.batch_size,num_graph, feature_reddit)))
    return jobs#最后几个jobs和其他jobs的区别就是，最后几个用test数据


pool = mp.Pool(args.n_pool)
st = time.time()
jobs = prepare_data(pool)
repeat_num = int(len(pre_target_nodes[0]) / args.batch_size // 1)#因为每一张图都只采样一个子图进行训练，所有这里是1，然后一张图一次训练完要重复int(len(pre_target_nodes[0]) / args.batch_size // 1)次
#这里先运行一下是什么意思？#一张图一次采样args.batch_size*1个节点，要采样repeat_num才能采样完

data, rem_edge_list, ori_edge_list, _, _ = GPT_sample(randint(), pre_target_nodes[0], {1: True}, args.batch_size, 0, feature_reddit)
node_feature, node_type, edge_time, edge_index, edge_type, node_dict, edge_dict = data
types = graphs[0].get_types()

#graph_reddit是最后一个graph
gnn = GNN(conv_name = args.conv_name, in_dim = len(graphs[0].node_feature[target_type]['emb'].values[0]), n_hid = args.n_hid, \
          n_heads = args.n_heads, n_layers = args.n_layers, dropout = args.dropout, num_types = len(types), \
          num_relations = len(graphs[0].get_meta_graph()) + 1, prev_norm = args.prev_norm, last_norm = args.last_norm, use_RTE = False)

if args.attr_type == 'text':  
    from gensim.models import Word2Vec
    w2v_model = Word2Vec.load(args.w2v_dir)
    n_tokens = len(w2v_model.wv.vocab)
    attr_decoder = RNNModel(n_word = n_tokens, ninp = gnn.n_hid, \
               nhid = w2v_model.vector_size, nlayers = 2)
    attr_decoder.from_w2v(torch.FloatTensor(w2v_model.wv.vectors))
else:
    attr_decoder = Matcher(gnn.n_hid, gnn.in_dim)

gpt_gnn = GPT_GNN(gnn = gnn, rem_edge_list = rem_edge_list, attr_decoder = attr_decoder, \
            types = types, neg_samp_num = args.neg_samp_num, device = device)
gpt_gnn.init_emb.data = node_feature[node_type == node_dict[target_type][1]].mean(dim=0).detach()
gpt_gnn = gpt_gnn.to(device)


best_val   = 100000
train_step = 0
stats = []
optimizer = torch.optim.AdamW(gpt_gnn.parameters(), weight_decay = 1e-2, eps=1e-06, lr = args.max_lr)

if args.scheduler == 'cycle':#total_steps = 一张图的重复采样次数×n_batch数目*n_epoch数目，抛开n_epoch，那就是repeat_num * args.n_batch = 被采样的节点总数目/batch_size
    scheduler = torch.optim.lr_scheduler.OneCycleLR(optimizer, pct_start=0.02, anneal_strategy='linear', final_div_factor=100,\
                        max_lr = args.max_lr, total_steps = repeat_num*10*args.n_epoch)
elif args.scheduler == 'cosine':
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, repeat_num * args.n_batch, eta_min=1e-6)

print('Start Pretraining...')
count__= 0
for epoch in np.arange(args.n_epoch) + 1:
    torch.cuda.empty_cache()
    print("count__",count__)
    gpt_gnn.neg_queue_size = args.queue_size * epoch // args.n_epoch#论文里面提到的负采样队列
    for batch in np.arange(repeat_num) + 1:
        print("count__batch",count__)
        train_data = [job.get() for job in jobs[:10]]
        valid_data = [job.get() for job in jobs[10:11]]
        pool.close()
        pool.join()
        pool = mp.Pool(args.n_pool)
        jobs = prepare_data(pool)
        et = time.time()
        print('Data Preparation: %.1fs' % (et - st))

        train_link_losses = []
        train_attr_losses = []
        gpt_gnn.train()
        for data, rem_edge_list, ori_edge_list, attr, (start_idx, end_idx) in train_data:
            node_feature, node_type, edge_time, edge_index, edge_type, node_dict, edge_dict = data
            node_feature = node_feature.detach()
            node_feature[start_idx : end_idx] = gpt_gnn.init_emb
            node_emb = gpt_gnn.gnn(node_feature.to(device), node_type.to(device), edge_time.to(device), \
                                   edge_index.to(device), edge_type.to(device))
            
            loss_link, _ = gpt_gnn.link_loss(node_emb, rem_edge_list, ori_edge_list, node_dict, target_type, use_queue = True, update_queue=True)
            if args.attr_type == 'text':
                loss_attr = gpt_gnn.text_loss(node_emb[start_idx : end_idx], attr, w2v_model, device)
            else:
                loss_attr = gpt_gnn.feat_loss(node_emb[start_idx : end_idx], torch.FloatTensor(attr).to(device))
                #Matcher(gnn.n_hid, gnn.in_dim)，计算特征之间的距离


            loss = loss_link * (1 - args.attr_ratio) + loss_attr * args.attr_ratio


            optimizer.zero_grad() 
            loss.backward()
            torch.nn.utils.clip_grad_norm_(gpt_gnn.parameters(), args.clip)
            optimizer.step()

            train_link_losses += [loss_link.item()]
            train_attr_losses += [loss_attr.item()]
            scheduler.step()
            count__ = count__ + 1
        '''
            Valid
        '''
        gpt_gnn.eval()
        valid_losses = []
        #train_attr_losses = []
        with torch.no_grad():
            for data, rem_edge_list, ori_edge_list, attr, (start_idx, end_idx) in valid_data:
                #data, rem_edge_list, ori_edge_list, attr, (start_idx, end_idx) = valid_data
                node_feature, node_type, edge_time, edge_index, edge_type, node_dict, edge_dict = data
                node_feature = node_feature.detach()
                node_feature[start_idx : end_idx] = gpt_gnn.init_emb
                node_emb = gpt_gnn.gnn(node_feature.to(device), node_type.to(device), edge_time.to(device), \
                                        edge_index.to(device), edge_type.to(device))
                loss_link, ress = gpt_gnn.link_loss(node_emb, rem_edge_list, ori_edge_list, node_dict, target_type, use_queue = False, update_queue=True)
                loss_link = loss_link.item()
                if args.attr_type == 'text':   
                    loss_attr = gpt_gnn.text_loss(node_emb[start_idx : end_idx], attr, w2v_model, device)
                else:
                    loss_attr = gpt_gnn.feat_loss(node_emb[start_idx : end_idx], torch.FloatTensor(attr).to(device))

                ndcgs = []
                for i in ress:
                    ai = np.zeros(len(i[0]))
                    ai[0] = 1
                    ndcgs += [ndcg_at_k(ai[j.cpu().numpy()], len(j)) for j in i.argsort(descending = True)]  
                    del i

                valid_loss = loss_link * (1 - args.attr_ratio) + loss_attr * args.attr_ratio
                
                valid_losses.append(float(valid_loss.cpu().numpy()))
        st = time.time()
        print(("Epoch: %d, (%d / %d) %.1fs  LR: %.5f Train Loss: (%.3f, %.3f)  Valid Loss: %.3f   Norm: %.3f  queue: %d") % \
            (epoch, batch, repeat_num, (st-et), optimizer.param_groups[0]['lr'], np.average(train_link_losses), np.average(train_attr_losses), \
            np.average(valid_losses), node_emb.norm(dim=1).mean(), gpt_gnn.neg_queue_size))  
       #问题 train_attr_losses是一个负值， valid_losses也是一个负值
        if np.average(valid_losses) < best_val:
            best_val = np.average(valid_losses)
            print('UPDATE!!!')
            torch.save(gpt_gnn.state_dict(), os.path.join(args.pretrain_model_dir, f"mixpre+{args.conv_name}+{args.batch_size}+{args.n_hid}+{args.max_lr}+{args.n_epoch}+{args.n_layers}+{args.sample_depth}+{args.sample_width}+{args.n_batch}+{args.n_heads}.pk"))
        # stats += [[np.average(train_link_losses),  loss_link, loss_attr, valid_loss]]

print("Finish!!!!!!!")
