# Network Topology Generator

This repository contains scripts to generate various types of network topologies, both hypothetical and authentic, with different defense and detection capabilities. Below are the instructions to set up and run the code.

Yunfei Wang*, Shixuan Liu, Wenhao Wang, Changling Zhou, Chao Zhang, Jiandong Jin, Cheng Zhu.
*equal contribution

A link to our paper can be found on arXiv: [https://arxiv.org/abs/2502.11588](#)

## 1. Prerequisites

### (1) Dataset Preparation
- Download the dataset from the NVD (National Vulnerability Database) website and place the compressed file in the `cve_data` folder.

### (2) Required Packages
Ensure you have the following Python libraries installed with the specified versions:
python  3.12+

```plaintext
dill==0.4.0
matplotlib==3.10.6
networkx==3.5
openpyxl==3.1.5
pandas==2.3.2
simplejson==3.20.1
setuptools==80.9.0
wheel==0.45.1
```

### (3) Installation

- **Create a conda environment:** `conda create -n py312 python=3.12`

- **Activate the conda environment:** `conda activate py312`

- **Install the required packages using pip:** `pip install -r requirements.txt`

## 2. Network Generator and Parameters

### (1) Hypothetical Network Generation
- **Tree Topology Network**: `network_topology/number_tree.py`
- **FatTree Topology Network**: `network_topology/number_fattree.py`
- **Partitioned and Layered Topology Network**: `network_topology/number_normal.py`

#### Defense Types:
- `defense_type = 1`: High defense, low detection
- `defense_type = 2`: Low detection, low defense
- `defense_type = 3`: High detection, high defense

### (2) Authentic Network Generation
- **Tree Topology Network**: `network_topology/authentic_tree.py`
- **FatTree Topology Network**: `network_topology/authentic_fattree.py`
- **Partitioned and Layered Topology Network**: `network_topology/authentic_normal.py`

### (3) Running the Network Generators
- **Hypothetical Network (e.g., Tree Topology)**:
  - Set network parameters, `defense_type`, and static/dynamic network parameters (for dynamic networks, also set the termination time).
  - Run the script: `python number_tree.py`

- **Authentic Network (e.g., Tree Topology)**:
  - Set network parameters and static/dynamic network parameters (for dynamic networks, also set the termination time).
  - Run the script: `python authentic_tree.py`

## 3. Network Datasets

### Download Link:
- **Baidu Netdisk**: [https://pan.baidu.com/s/1nUFRID4UuAHTjzUcSzhkGg](#)
- **Extraction Code**: `vufi`

### Description:
- **Static Networks**:
  - **Generation**: Five standard networks are generated for each network setting combination.
  - **Naming Convention**: `{total_number_of_nodes}_defense_type_{1or2or3}_{network_type{standard_network_variation}}`.

- **Dynamic Networks**:
  - **Generation**: One standard network is generated for each network setting combination, along with its changes over T=100/1000 time units.
  - **Naming Convention**: `{total_number_of_nodes}_{network_type{standard_network_variation}}/t{time_unit}`.


