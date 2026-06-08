import os
import click
import json

def compare(jvexir_data, jzeek_data):
    for idb, idb_data in jzeek_data.items():
        for fva, zeek_shash in idb_data["hashes"].items():
            print(fva)
            vexir_shash = jvexir_data[idb][fva]["shash"]
            if vexir_shash != zeek_shash:
                print(f"Warning: {idb} {fva}")
                print("VEXIR:", vexir_shash)
                print("ZEEK: ", zeek_shash)
    

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