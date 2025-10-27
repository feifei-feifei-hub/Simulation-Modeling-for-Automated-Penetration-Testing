import networkx as nx
import matplotlib.pyplot as plt
import os
import numpy as np
import dill

def print_network_info(file_path):
    """
    Read the network graph file and print the nodes, node attributes, and link information.
    
    Parameters:
    file_path (str): Network graph file path, e.g. 'fattree/t0.gpickle'
    """
    try:
        if not os.path.exists(file_path):
            print(f"Error: File '{file_path}' does not exist")
            return
        
        G = dill.load(open( file_path, 'rb'))
        
        print(f"Network graph '{file_path}' basic information:")
        print(f"Number of nodes: {G.number_of_nodes()}")
        print(f"Number of edges: {G.number_of_edges()}")
        print("-" * 50)
        
        # Print node attributes
        print("Node attributes:")
        for node, attrs in G.nodes(data=True):
            print(f"Node {node}: {attrs}")
        print("-" * 50)
        
        # Print edges
        print("Edges:")
        for u, v in G.edges():
            print(f"Edge ({u}, {v})")
            
    except Exception as e:
        print(f"Error reading file: {e}")

def visualize_and_save_network(file_path, output_path=None, figsize=(12, 8)):
    """
    Read the network graph file and visualize it, saving as an image.
    
    Parameters:
    file_path (str): Network graph file path, e.g. 'fattree/t0.gpickle'
    output_path (str, optional): Output image path. If None, the input filename will be used to replace the extension.
    figsize (tuple, optional): Image size, default is (12, 8)
    """
    try:
        if not os.path.exists(file_path):
            print(f"Error: File '{file_path}' does not exist")
            return
        
        G = dill.load(open( file_path, 'rb'))
        
        if output_path is None:
            output_path = os.path.splitext(file_path)[0] + '.png'
        
        plt.figure(figsize=figsize)
        
        if nx.is_connected(G):
            pos = nx.spring_layout(G, k=1/np.sqrt(G.number_of_nodes()), iterations=50)
        else:
            pos = nx.spring_layout(G, k=1/np.sqrt(G.number_of_nodes()), iterations=50)
        
        nx.draw_networkx_nodes(G, pos, node_size=200, node_color='lightblue')
        nx.draw_networkx_edges(G, pos, width=1, alpha=0.5)
        
        nx.draw_networkx_labels(G, pos, font_size=8)
        
        # Set title
        plt.title(f"Network graph: {os.path.basename(file_path)}")
        
        # Remove axis
        plt.axis('off')
        
        plt.tight_layout()
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        print(f"The network graph has been saved to: {output_path}")
        
        # plt.show()
        
    except Exception as e:
        print(f"Error occurred while visualizing the network graph: {e}")

# 
if __name__ == "__main__":
    file_path = "/root/feifei/8_network_generator_py312/number_net/test/dynamic/20_defensetype_1_net0/t0.gpickle"
    
    # print_network_info(file_path)
    
    visualize_and_save_network(file_path)