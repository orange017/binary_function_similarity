import json
import networkx as nx
import matplotlib.pyplot as plt
from itertools import count

node_ids = count()

def exp_tree_to_graph(exp_tree):
    G = nx.Graph()
    if isinstance(exp_tree, str):
        root = next(node_ids)
        G.add_node(root, label=exp_tree)
        return G, root
    elif isinstance(exp_tree, tuple):
        root = next(node_ids)
        G.add_node(root, label="tuple")
        for sub in exp_tree:
            H, h_root = exp_tree_to_graph(sub)
            G.update(H)
            G.add_edge(root, h_root)
        return G, root

def process(j_data):
    for idb_path, idb_data in j_data.items():
        arch = idb_data.pop("arch", None)
        for fva, func_data in idb_data.items():
            for bva, bb_data in func_data["basic_blocks"].items():
                if not j_data[idb_path][fva]["basic_blocks"][bva].get("exp_tree", None):
                    continue # already processed
                exp_tree_list = j_data[idb_path][fva]["basic_blocks"][bva].get("exp_tree", None)
                if not exp_tree_list:
                    continue
                # print(exp_tree_list)
                for exp_tree in exp_tree_list:
                    try:
                        x = eval(exp_tree)
                        print(exp_tree)
                        g, root = exp_tree_to_graph(x)
                        print(g.nodes())
                        print(g.edges())
                        return
                    except SyntaxError:
                        pass



if __name__ == "__main__":
    path = r"C:\Users\user\Desktop\main\binary_function_similarity\IDA_scripts\IDA_acfg_vexir\x64-gcc-9-O0_clambc_acfg_vexir.json"
    with open(path) as fp:
        j_data = json.load(fp)
    process(j_data)