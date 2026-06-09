import click
from tqdm import tqdm
import os
import json
import base64
from collections import Counter
from multiprocessing import Pool
import time

from strand_extractor import StrandsExtractor, StrandHash
import archinfo
import pyvex
from func_timeout import func_timeout, FunctionTimedOut


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


def extract_irsbs(bytes_, arch, opt_level=2, start_addr=0x400000):
    off = 0
    addr = start_addr
    irsbs = []
    while off < len(bytes_):
        irsb = pyvex.lift(
            bytes_[off:], addr, arch_to_pyvex_arch_map[arch], opt_level=opt_level)
        irsbs.append(irsb)
        addr += irsb.size
        off += irsb.size
    return irsbs


def extract_irsbs_with_timeout(bytes_, arch, opt_level=2, start_addr=0x400000, timeout=20):
    try:
        irsbs = func_timeout(
            timeout,
            extract_irsbs,
            args=(bytes_, arch, opt_level, start_addr)
        )
    except FunctionTimedOut:
        irsbs = []
    return irsbs


def acfg_disasm2vexir(j_data):
    for idb_path, idb_data in j_data.items():
        arch = idb_data.pop("arch")
        for fva, func_data in tqdm(idb_data.items(), desc=f"Processing {idb_path}"):
            func_hash_to_freq = Counter()
            for bva, bb_data in func_data["basic_blocks"].items():
                bb_hash_to_freq = Counter()
                bb_bytes = base64.b64decode(bb_data["b64_bytes"])
                irsbs = extract_irsbs_with_timeout(bb_bytes, arch)
                if len(irsbs) == 0:
                    print(f"[M] Warning: failed to lift to IR for {idb_path} {fva} {bva}")
                    for insn in bb_data["bb_disasm"]:
                        print(f"    {insn}")
                    continue
                j_data[idb_path][fva]["basic_blocks"][bva]["exp_tree"] = list()
                j_data[idb_path][fva]["basic_blocks"][bva]["stmts"] = list()
                for irsb in irsbs:
                    for stmt in irsb.statements:
                        j_data[idb_path][fva]["basic_blocks"][bva]["stmts"].append(str(stmt))
                    se = StrandsExtractor(irsb)
                    stmt_idx_to_exp_tree = se.extract_strands()
                    j_data[idb_path][fva]["basic_blocks"][bva]["exp_tree"].extend([ str(exp_tree) for stmt, exp_tree in sorted(stmt_idx_to_exp_tree.items()) ])
                    stmt_idx_to_exp_tree.update(stmt_idx_to_exp_tree)
                    for stmt, exp_tree in stmt_idx_to_exp_tree.items():
                        h = StrandHash(exp_tree)
                        bb_hash_to_freq.update((h.shash(),))
                j_data[idb_path][fva]["basic_blocks"][bva]["shash"] = ";".join([f"{val}:{freq}" for val, freq in sorted(bb_hash_to_freq.items())])
                func_hash_to_freq.update(bb_hash_to_freq)
            j_data[idb_path][fva]["shash"] = "".join([f"{val}:{freq}" for val, freq in sorted(func_hash_to_freq.items())])
    # sys.exit(0)
    return j_data


def acfg_disasm2vexir_wrap(in_path: str, out_path: str, pretty: bool = False):
    with open(in_path, "r") as fp:
        j_in = json.load(fp)
    j_out = acfg_disasm2vexir(j_in)
    with open(out_path, "w") as fp:
        if pretty:
            json.dump(j_out, fp, indent=4)
        else:
            json.dump(j_out, fp)


def process(input_dir: str, output_dir: str, num_processes: int):
    if not os.path.isdir(input_dir):
        print("[M] Error: input dir not exists")
        return
    if not os.path.isdir(output_dir):
        os.makedirs(output_dir)

    workers = set()
    pool = Pool(processes=num_processes)

    try:
        for j_file in os.listdir(input_dir):
            if not j_file.endswith(".json"):
                continue
            j_path = os.path.join(input_dir, j_file)
            out_path = os.path.join(output_dir, j_file.replace("_acfg_disasm.json", "_acfg_vexir.json"))
            if os.path.exists(out_path):
                print(f"[M] Warning: output file already exists, skip {out_path}")
                continue
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
        return


@click.command()
@click.option("-i", "--input-path", required=True, help='IDA_acfg_disasm JSON dir or file.')
@click.option("-o", "--output-path", required=True, help='Output directory.', default=".")
@click.option("-p", "--num-processes", required=True, help='Number of workers.', type=int, default=1)
def main(input_path: str, output_path: str, num_processes: int):
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
                process(acfg_input_dir, acfg_output_dir, num_processes)


if __name__ == "__main__":
    main()
