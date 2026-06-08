import click
from tqdm import tqdm
import os
import json
import base64
import pickle
from collections import defaultdict

import strand_extractor
from strand_extractor import StrandsExtractor, StrandHash
import function_embedding as emb
import pyvex
from func_timeout import func_timeout, FunctionTimedOut

def extract_irsbs(bytes_, arch, opt_level=2, start_addr=0x400000):
    off = 0
    addr = start_addr
    irsbs = []
    while off < len(bytes_):
        irsb = pyvex.lift(
            bytes_[off:], addr, strand_extractor.arch_to_pyvex_arch_map[arch], opt_level=opt_level)
        irsbs.append(irsb)
        addr += irsb.size
        off += irsb.size
    return irsbs

def extract_irsbs_with_timeout(bytes_, arch, opt_level=2, start_addr=0x400000):
    try:
        irsbs = func_timeout(
            20,
            extract_irsbs,
            args=(bytes_, arch, opt_level, start_addr)
        )
    except FunctionTimedOut:
        irsbs = []
    return irsbs

def _extract_strands_from_irsbs(irsb, arch):
    se = StrandsExtractor(irsb, arch)
    stmt_idx_to_exp_tree = se.extract_strands()
    return stmt_idx_to_exp_tree

def extract_strands_from_irsbs(irsb, arch):
    try:
        stmt_idx_to_exp_tree = func_timeout(
            20,
            _extract_strands_from_irsbs,
            args=(irsb, arch)
        )
    except FunctionTimedOut:
        stmt_idx_to_exp_tree = {"error": "timeout"}
    return stmt_idx_to_exp_tree

def acfg_disasm2vexir(j_data):
    for idb_path, idb_data in j_data.items():
        arch = idb_data.pop("arch")
        for fva, func_data in tqdm(idb_data.items(), desc=f"Processing {idb_path}"):
            for bva, bb_data in func_data["basic_blocks"].items():
                bb_bytes = base64.b64decode(bb_data["b64_bytes"])
                irsbs = extract_irsbs_with_timeout(bb_bytes, arch)
                if len(irsbs) == 0:
                    print(f"[M] Warning: failed to lift to IR for {idb_path} {fva} {bva}")
                    for insn in bb_data["bb_disasm"]:
                        print(f"    {insn}")
                    continue
                for irsb in irsbs:
                    stmt_idx_to_exp_tree = extract_strands_from_irsbs(irsb, arch)
                    if "error" in stmt_idx_to_exp_tree:
                        print(f"[M] Warning: failed to extract strands for {idb_path} {fva} {bva}")
                        for insn in bb_data["bb_disasm"]:
                            print(f"    {insn}")
                        break
                    j_data[idb_path][fva]["basic_blocks"][bva]["exp_tree"] = stmt_idx_to_exp_tree
    return j_data

@click.command()
@click.option("-i", "--input-dir", required=True, help='IDA_acfg_disasm JSON dir.')
@click.option("-o", "--output-dir", required=True, help='Output directory.')
def main(input_dir: str, output_dir: str):
    if not os.path.isdir(input_dir):
        print("[M] Error: input dir not exists")
        return
    if not os.path.isdir(output_dir):
        os.makedirs(output_dir)
    
    for j_file in os.listdir(input_dir):
        if not j_file.endswith(".json"):
            continue
        j_path = os.path.join(input_dir, j_file)
        out_path = os.path.join(output_dir, j_file.replace("_acfg_disasm.json", "_acfg_vexir.json"))
        if os.path.exists(out_path):
            print(f"[M] Warning: output file already exists, skip {out_path}")
            continue
        with open(j_path, "r") as fp:
            j_data = json.load(fp)
            j_out = acfg_disasm2vexir(j_data)
            #if len(j_out) < 1000:
            #    print(json.dumps(j_out, indent=4))
        
        with open(out_path, "w") as fp:
            json.dump(j_out, fp)


if __name__ == "__main__":
    main()