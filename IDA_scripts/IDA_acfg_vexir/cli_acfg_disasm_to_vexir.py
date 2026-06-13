import click
from tqdm import tqdm
import os
import json
import base64
from collections import Counter
from multiprocessing import Pool
import time
from pathlib import Path
from strand_extractor import StrandsExtractor, StrandHash
import archinfo
import pyvex
import sys


arch_to_pyvex_arch_map = {
    'x86': archinfo.ArchX86(),
    'x86-32': archinfo.ArchX86(),
    'x64': archinfo.ArchAMD64(),
    'x86-64': archinfo.ArchAMD64(),
    'arm32': archinfo.ArchARM(),
    'arm-32': archinfo.ArchARM(),
    'arm64': archinfo.ArchAArch64(),
    'arm-64': archinfo.ArchAArch64(),
    'mips32': archinfo.ArchMIPS32(),
    'mips-32': archinfo.ArchMIPS32(),
    'mips64': archinfo.ArchMIPS64(),
    'mips-64': archinfo.ArchMIPS64(),
}

def extract_build_info(file_path: str):
    filename = os.path.basename(file_path)
    slist = filename.split("_")
    lib = slist[1]
    arch, comp, ver, opt = slist[0].split("-")
    bit = "32" if "32" in arch.replace("86", "32") else "64"
    arch = arch.replace("32", "").replace("64", "").replace("86", "")
    return { "lib": lib, "arch": arch, "bit": bit, "comp": comp, "ver": ver, "opt": opt }


def convert_filename_to_arch(file_path):
    info = extract_build_info(file_path)
    arch, bitness = info["arch"], info["bit"]
    return f"{arch}-{bitness}"


def extract_irsbs(bytes_, arch, opt_level=2, start_addr=0x400000):
    off = 0
    addr = start_addr
    irsbs = []
    while off < len(bytes_):
        irsb = pyvex.lift(
            bytes_[off:], addr, arch_to_pyvex_arch_map[arch], opt_level=opt_level)
        if irsb.size <= 0:
            remaining = len(bytes_) - off
            print(f"Failed at offset {off}. Remaining bytes: {remaining}")
            break
        irsbs.append(irsb)
        addr += irsb.size
        off += irsb.size
    return irsbs


def acfg_disasm2vexir(j_data):
    try:
        for idb_path, idb_data in j_data.items():
            arch = idb_data.pop("arch", convert_filename_to_arch(idb_path))
            for fva, func_data in  tqdm(idb_data.items(), desc=f"Processing {idb_path}"):
                for bva, bb_data in func_data["basic_blocks"].items():
                    bb_bytes = base64.b64decode(bb_data["b64_bytes"])
                    exp_tree = j_data[idb_path][fva]["basic_blocks"][bva].pop("exp_tree", [])
                    if not exp_tree:
                        irsbs = extract_irsbs(bb_bytes, arch)
                        if len(irsbs) == 0:
                            print(f"[M] Warning: failed to lift to IR for {idb_path} {fva} {bva}")
                            for insn in bb_data["bb_disasm"]:
                                print(f"    {insn}")
                        for irsb in irsbs:
                            se = StrandsExtractor(irsb)
                            stmt_idx_to_exp_tree = se.extract_strands()
                            for exp in stmt_idx_to_exp_tree.values():
                                exp_tree.append(exp)
                    j_data[idb_path][fva]["basic_blocks"][bva]["exp_tree"] = exp_tree
            j_data[idb_path]["arch"] = arch
    except Exception as e:
        print(e)
        import traceback
        traceback.print_exc()
        return None
    return j_data


def acfg_disasm2vexir_wrap(in_path: str, out_path: str, pretty: bool = False):
    filters = [
    ]
    info = extract_build_info(in_path)
    if filters:
        for filter in filters:
            if all([ info[k] == v for k, v in filter.items()]):
                print(in_path)
                break
        else:
            print("Skip:", in_path)
            return

    with open(in_path, "r") as fp:
        j_in = json.load(fp)
    j_out = acfg_disasm2vexir(j_in)
    if j_out:
        with open(out_path, "w") as fp:
            if pretty:
                json.dump(j_out, fp, indent=4)
            else:
                json.dump(j_out, fp)

def process(input_dir: str, output_dir: str, num_processes: int, overwrite: bool = False):
    if not os.path.isdir(input_dir):
        print("[M] Error: input dir not exists")
        return
    if not os.path.isdir(output_dir):
        os.makedirs(output_dir)

    workers = set()
    pool = Pool(processes=num_processes)

    try:
        for j_file in tqdm(os.listdir(input_dir)):
            if not j_file.endswith(".json"):
                continue
            j_path = os.path.join(input_dir, j_file)
            out_path = os.path.join(output_dir, j_file.replace("_acfg_disasm.json", "_acfg_vexir.json"))
            if not overwrite and os.path.exists(out_path):
                print(f"[M] Warning: output file already exists, skip {out_path}")
                continue
            if num_processes == 1:
                acfg_disasm2vexir_wrap(j_path, out_path)
            else:
                r = pool.apply_async(acfg_disasm2vexir_wrap, args=(j_path, out_path,))
                workers.add(r)

        # Monitor results using a timeout loop
        while True:
            # Check if all tasks are finished
            if all(r.ready() for r in workers):
                break
            # Short sleep prevents high CPU usage during monitoring
            time.sleep(0.1)

        # Close the pool
        pool.close()
        pool.join()

        # Wait for all the async tasks to finish
        for r in workers:
            r.get()
        print("[M] All processes finished")
    except KeyboardInterrupt:
        print("[M] KeyboardInterrupt received, terminating workers")
        pool.terminate()
        pool.join()
        print("[M] Workers terminated")
        sys.exit(0)

def fix(input_dir: str, num_processes: int):
    process(input_dir, input_dir, num_processes, overwrite=True)

@click.command()
@click.option("-i", "--input-path", required=True, help='IDA_acfg_disasm JSON dir or file.')
@click.option("-o", "--output-path", required=True, help='Output directory.', default=".")
@click.option("-p", "--num-processes", required=True, help='Number of workers.', type=int, default=1)
@click.option("-m", "--mode", required=True, help='Mode of work.', type=click.Choice(["process", "fix"]), default="process")
def main(input_path: str, output_path: str, num_processes: int, mode: str):
    assert os.path.exists and os.path.isdir(output_path)
    if os.path.isfile(input_path):
        filename = os.path.basename(input_path)
        output_file_path = os.path.join(output_path, filename.replace("_acfg_disasm.json", "_acfg_vexir.json"))
        acfg_disasm2vexir_wrap(input_path, output_file_path, pretty=True)
    else:
        for root, _, filename in os.walk(input_path):
            if os.path.basename(root).startswith("acfg_disasm"):
                rel_path = os.path.relpath(root, input_path)
                acfg_input_dir = os.path.join(input_path, rel_path)
                acfg_output_dir = os.path.join(output_path, rel_path)
                os.makedirs(acfg_output_dir, exist_ok=True)
                if mode == "process":
                    process(acfg_input_dir, acfg_output_dir, num_processes)
                elif mode == "fix":
                    fix(acfg_output_dir, num_processes)


if __name__ == "__main__":
    main()
