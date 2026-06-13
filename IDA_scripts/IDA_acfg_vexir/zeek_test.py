import os
import click
import json
import base64

from strand_extractor import StrandHash
from collections import Counter

def compare(jvexir_data, jzeek_data):
    total, success = 0, 0
    for idb, idb_data in jzeek_data.items():
        for fva, zeek_shash in idb_data["hashes"].items():
            print(f"Process function at {fva}")
            func_data = jvexir_data[idb][fva]
            hash_to_freq = Counter()
            for bva, bb_data in func_data["basic_blocks"].items():
                bb_bytes = base64.b64decode(bb_data["b64_bytes"])
                exp_tree = func_data["basic_blocks"][bva]["exp_tree"]
                print(len(exp_tree), len(bb_bytes))
                for e in exp_tree:
                    # print(e)
                    h = StrandHash(exp_tree)
                    hash_to_freq.update((h.shash(),))
            vexir_shash = ";".join([f"{val}:{freq}" for val, freq in sorted(hash_to_freq.items())])
            total += 1
            if vexir_shash == zeek_shash:
                success += 1
            else:
                # print(len(vexir_shash), len(zeek_shash))
                pass
                #print(vexir_shash)
                #print(zeek_shash)
    print(f"[{success}/{total}]")    

@click.command()
@click.option("-z", "--zeek-dir", required=True, help=' Zeek preprocessing output dir.')
@click.option("-v", "--vexir-dir", required=True, help='IDA_acfg_vexir directory.')
def main(zeek_dir: str, vexir_dir: str):
    for j_file in os.listdir(vexir_dir):
        # ZEEK: arm32-clang-3.5-O0_libz.so.1.2.11_acfg_disasm_zeek.json
        # VEXIR: arm32-clang-3.5-O0_libz.so.1.2.11_acfg_vexir.json
        if not j_file.endswith(".json"):
            continue
        zeek_name = j_file.replace("acfg_vexir.json", "acfg_disasm_zeek.json")
        jvexir_path = os.path.join(vexir_dir, j_file)
        jzeek_path = os.path.join(zeek_dir, zeek_name)
        if not os.path.isfile(jzeek_path):
            print(f"Not found {zeek_name}")
            continue
        with open(jzeek_path, "r") as fp:
            jzeek_data = json.load(fp)
        with open(jvexir_path, "r") as fp:
            jvexir_data = json.load(fp)
        compare(jvexir_data, jzeek_data)
        break


if __name__ == "__main__":
    main()