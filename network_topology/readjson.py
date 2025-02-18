
import networkx as nx
import simplejson as json
def load(fname):
    G = nx.DiGraph()
    d = json.load(open(fname))
    G.add_nodes_from(d['nodes'])
    G.add_edges_from(d['edges'])
    return G
fname = "./graph.json"
#G = nx.read_gpickle(fname)
#print(G)


