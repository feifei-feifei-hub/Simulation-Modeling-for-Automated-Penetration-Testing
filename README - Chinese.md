1. 程序运行准备
（1）NVD官网下载数据集压缩包至cve_data文件夹
（2）库版本
gensim                    4.3.0           
networkx                  3.1                
nni                       3.0                      
numpy                     1.24.3             
numpy-base                1.24.3            
nvidia-ml-py              12.535.133               
openpyxl                  3.0.10           
pandas                    2.0.3            
python                    3.8.18               
python-dateutil           2.8.2                
python-tzdata             2023.3              
python_abi                3.8                     
pythonwebhdfs             0.2.3                   
pytorch                   1.12.1          
torchaudio                0.12.1              
torchvision               0.13.1               
urllib3                   1.26.16            
zipp                      3.11.0            
zlib                      1.2.13                 
2.  网络生成器及相关参数
(1)生成Hypothetical network的文件
network_topology/number_tree.py  生成Tree Topology Network
network_topology/number_fattree.py 生成FatTree Topology Network
network_topology/number_normal.py 生成artitioned and Layered Topology Network
其中参数defense_type 代表的含义为
defense_type = 1，高防御低检测
defense_type = 2，低检测低防御
defense_type = 3，高检测高防御
(2)生成Authentic network的文件
network_topology/authentic_tree.py 生成Tree Topology Network
network_topology/authentic_fattree.py 生成FatTree Topology Network
network_topology/authentic_normal.py 生成artitioned and Layered Topology Network
（3）运行网络生成器
Hypothetical network ：以树状网络为例
设置网络参数、defense_type、静态/动态网络参数(动态网络还需要设置终止时间)  运行number_tree.py：python number_tree.py
Authentic network：以树状网络为例
设置网络参数、静态/动态网络参数(动态网络还需要设置终止时间)  运行authentic_tree.py: python authentic_tree.py
3. 网络数据集
百度网盘链接：
https:……
提取码：
vufi
说明：
静态网络：
生成：在每种网络设置组合下均生成5个标准网络
命名规则：{节点总数目}_defense_type_{1or2or3}_{网络类型{标准网络变化}}.

动态网络：
生成：每种网络设置组合下均生成1个标准网络，及其在T= 100/1000时间内的变化
命名规则：{节点总数目}_defense_type_{1or2or3}_{网络类型{标准网络变化}}/t{时刻}