import networkx as nx
import matplotlib.pyplot as plt
import os
import numpy as np
import dill

def print_network_info(file_path):
    """
    读取网络图文件并打印节点、节点属性及链路信息
    
    参数:
    file_path (str): 网络图文件路径，如 'fattree/t0.gpickle'
    """
    try:
        # 检查文件是否存在
        if not os.path.exists(file_path):
            print(f"错误: 文件 '{file_path}' 不存在")
            return
        
        # 读取网络图文件
        G = dill.load(open( file_path, 'rb'))
        
        # 打印基本信息
        print(f"网络图 '{file_path}' 基本信息:")
        print(f"节点数量: {G.number_of_nodes()}")
        print(f"边数量: {G.number_of_edges()}")
        print("-" * 50)
        
        # 打印节点及属性
        print("节点及属性:")
        for node, attrs in G.nodes(data=True):
            print(f"节点 {node}: {attrs}")
        print("-" * 50)
        
        # 打印边
        print("边:")
        for u, v in G.edges():
            print(f"边 ({u}, {v})")
            
    except Exception as e:
        print(f"读取文件时出错: {e}")

def visualize_and_save_network(file_path, output_path=None, figsize=(12, 8)):
    """
    读取网络图文件并可视化，保存为图像
    
    参数:
    file_path (str): 网络图文件路径，如 'fattree/t0.gpickle'
    output_path (str, optional): 输出图像路径。如果为None，则使用输入文件名替换扩展名
    figsize (tuple, optional): 图像大小，默认为(12, 8)
    """
    try:
        # 检查文件是否存在
        if not os.path.exists(file_path):
            print(f"错误: 文件 '{file_path}' 不存在")
            return
        
        # 读取网络图文件
        G = dill.load(open( file_path, 'rb'))
        
        # 设置输出路径
        if output_path is None:
            output_path = os.path.splitext(file_path)[0] + '.png'
        
        # 创建图形
        plt.figure(figsize=figsize)
        
        # 选择布局算法
        if nx.is_connected(G):
            pos = nx.spring_layout(G, k=1/np.sqrt(G.number_of_nodes()), iterations=50)
        else:
            pos = nx.spring_layout(G, k=1/np.sqrt(G.number_of_nodes()), iterations=50)
        
        # 绘制节点和边
        nx.draw_networkx_nodes(G, pos, node_size=200, node_color='lightblue')
        nx.draw_networkx_edges(G, pos, width=1, alpha=0.5)
        
        # 绘制标签
        nx.draw_networkx_labels(G, pos, font_size=8)
        
        # 设置标题
        plt.title(f"网络图: {os.path.basename(file_path)}")
        
        # 移除坐标轴
        plt.axis('off')
        
        # 保存图像
        plt.tight_layout()
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        print(f"网络图已保存至: {output_path}")
        
        # 显示图像
        # plt.show()
        
    except Exception as e:
        print(f"可视化网络图时出错: {e}")

# 使用示例
if __name__ == "__main__":
    # 示例文件路径
    file_path = "/root/feifei/8_network_generator_py312/number_net/test/dynamic/20_defensetype_1_net0/t0.gpickle"
    
    # 打印网络信息
    # print_network_info(file_path)
    
    # 可视化并保存网络图
    visualize_and_save_network(file_path)