import json
import networkx as nx
import matplotlib.pyplot as plt
from itertools import count
import click

node_ids = count()


def draw_digraph(graph: nx.DiGraph):
    plt.figure(figsize=(12, 8))
    pos = nx.spring_layout(graph, seed=100)
    nx.draw_networkx_nodes(
        graph,
        pos,
        node_size=1000
    )
    nx.draw_networkx_edges(
        graph,
        pos,
        arrows=True,
        arrowstyle='-|>',
        arrowsize=20
    )
    node_labels = nx.get_node_attributes(graph, "label")
    nx.draw_networkx_labels(
        graph, 
        pos, 
        labels=node_labels
    )

    edge_labels = nx.get_edge_attributes(graph, "label")
    print(edge_labels)
    if edge_labels:
        nx.draw_networkx_edge_labels(
            graph,
            pos,
            edge_labels=edge_labels
        )
    plt.axis("off")
    plt.tight_layout()
    plt.show()


def exp_tree_to_graph(exp_tree):
    G = nx.Graph()

    def build(tree):
        if isinstance(tree, str):
            node = next(node_ids)
            G.add_node(node, label=tree)
            return node
        op, operands = tree
        root = next(node_ids)
        G.add_node(root, label=op)
        for operand in operands:
            child = build(operand)
            G.add_edge(root, child)
        return root

    root = build(exp_tree)
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
                G = nx.DiGraph()
                prev_root = None
                for exp_tree in exp_tree_list:
                    try:
                        x = eval(exp_tree)
                        print(exp_tree)
                        g, r = exp_tree_to_graph(x)
                        G = nx.compose(G, g)
                        if prev_root is not None:
                            G.add_edge(prev_root, r)
                        prev_root = r
                    except SyntaxError:
                        pass
                draw_digraph(G)
                #return


@click.command()
@click.option("-i", "--input-path", required=True)
def main(input_path: str):
    with open(input_path) as fp:
        j_data = json.load(fp)
    process(j_data)

if __name__ == "__main__":
    main()