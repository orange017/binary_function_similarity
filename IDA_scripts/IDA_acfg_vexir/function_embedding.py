#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import click
import coloredlogs
import json
import logging
import os
import pyvex
import time
import traceback
import keystone

from collections import Counter
from collections import defaultdict
from multiprocessing import Pool
from os.path import abspath
from os.path import basename
from os.path import exists
from os.path import isdir
from os.path import isfile
from os.path import join
from tqdm import tqdm
from func_timeout import func_timeout, FunctionTimedOut

import strand_extractor
from strand_extractor import StrandsExtractor

logger = None
g_start_time = time.time()
g_config = {}

@click.command()
@click.argument('input_path')
@click.argument('output_path')
@click.option('-w', '--workers-num', default=1)
def process(input_path, output_path, workers_num):

    global g_config

    output_path = abspath(output_path)
    logs_dir = join(output_path, 'logs')
    jsons_dir = join(output_path, 'jsons')

    g_config['workers_num'] = workers_num
    g_config['jsons_dir'] = jsons_dir
    g_config['logs_dir'] = logs_dir

    target_dirs = [output_path, jsons_dir, logs_dir]
    for target_dir in target_dirs:
        if not isdir(target_dir):
            if exists(target_dir):
                print(f'ERROR: {target_dir} exists, but it is not a directory')
                return
            else:
                os.makedirs(target_dir)

    set_logger(logs_dir)

    if isfile(input_path):
        j_paths = [input_path]
    elif isdir(input_path):
        j_paths = []
        for fn in sorted(os.listdir(input_path)):
            if fn.endswith('.json'):
                j_path = abspath(join(input_path, fn))
                j_paths.append(j_path)
    else:
        raise Exception('file or dir does not exist')

    logger.info(f'[M] Found {len(j_paths)} file(s) to process')

    worker_results = list()
    logger.info(f'[M] Creating workers_num: {g_config["workers_num"]}')
    pool = Pool(processes=g_config['workers_num'],
                maxtasksperchild=5,
                initializer=init_worker,
                initargs=(g_config, g_start_time))
    try:
        # Iterate over each JSON file (each JSON corresponds to an IDB)
        for j_idx, j_path in enumerate(j_paths):
            r = pool.apply_async(worker_func, args=(
                j_path, j_idx, len(j_paths)))
            worker_results.append(r)

        # Monitor results using a timeout loop
        while True:
            # Check if all tasks are finished
            if all(r.ready() for r in worker_results):
                break
            # Short sleep prevents high CPU usage during monitoring
            time.sleep(0.1)

        logger.info("[M] Waiting processes to finish")

        # Close the pool
        pool.close()
        pool.join()

        # Wait for all the async tasks to finish
        for r in worker_results:
            r.get()
        logger.info("[M] All processes finished")
    except KeyboardInterrupt:
        logger.info("[M] KeyboardInterrupt received, terminating workers")
        pool.terminate()
        pool.join()
        logger.info("[M] Workers terminated")
        return
    output_json_path = join(output_path, 'IronDiff.json')
    save_results(output_json_path)

def save_results(output_json_path):
    global g_config, logger
    logger.info(f"[M] Collecting all results in one single JSON file: {output_json_path}")
    j_paths = []
    jsons_dir = g_config['jsons_dir']
    for fn in sorted(os.listdir(jsons_dir)):
        if fn.endswith('.json'):
            j_path = abspath(join(jsons_dir, fn))
            j_paths.append(j_path)
    logger.info(f'[M] Processing {len(j_paths)} jsons')
    results = {}
    for j_path in tqdm(j_paths):
        with open(j_path) as f:
            j_data = json.load(f)
            for binary_name, info in j_data.items():
                results[binary_name] = {}
                results[binary_name]['elapsed_time'] = info['elapsed_time']
                results[binary_name]['hashes'] = {}
                for func_addr, shash in info['hashes'].items():
                    results[binary_name]['hashes'][func_addr] = {
                        'sh': shash,
                    }
    with open(output_json_path, 'w') as f:
        f.write(json.dumps(results, sort_keys=True,
                           indent=2, separators=(',', ': ')))
    logger.info("[M] Done")


def init_worker(config, start_time):
    """Initialize worker process with config and start_time globals"""
    global g_config, g_start_time, logger
    g_config = config
    g_start_time = start_time
    set_logger(config.get('logs_dir', '.'))


def worker_func(j_path, j_idx, j_num):
    assert j_path.endswith('.json')
    output_j_path = join(g_config['jsons_dir'],
                         basename(j_path)[:-5] + '_IronDiff.json')

    # check if we need to analyze it
    if isfile(output_j_path):
        logger.info(f'Output JSON already exists for {j_path}: {output_j_path}')
        return

    logger.info(f'Processing {j_idx+1}/{j_num} {j_path}')

    with open(j_path) as f:
        j_data = json.load(f)

    results = defaultdict(dict)
    for binary_name, binary_info in j_data.items():
        start_time = time.time()
        arch = binary_info.pop('arch')
        functions = binary_info
        functions_hash_vals = {}
        functions_raw_hashes = {}
        functions_errors = {}
        funcs_num = len(functions)
        for func_idx, (func_addr, func_info) in enumerate(functions.items()):
            blocks = func_info['basic_blocks']
            try:
                func_hash_vals, function_raw_hashes = process_function(blocks, arch)
                func_hash_str = serialize_hash_vals(func_hash_vals)
                functions_hash_vals[func_addr] = func_hash_str
                functions_raw_hashes[func_addr] = function_raw_hashes
            except Exception as exc:
                error_message = f'Error:{j_path}@{binary_name}@{func_addr}@{repr(exc)}'
                functions_errors[func_addr] = error_message
                tb = traceback.format_exc()
                error_record = f'\nException Record\nj_path: {j_path}\nbinary name: {binary_name}\nfunc addr: {func_addr}\nException: {repr(exc)}\nTB: {tb}\n----------------------\n'
                logger.error(error_record)

        results[binary_name]['hashes'] = functions_hash_vals
        results[binary_name]['raw_hashes'] = functions_raw_hashes
        results[binary_name]['errors'] = functions_errors
        elapsed_time = time.time() - start_time
        results[binary_name]['elapsed_time'] = elapsed_time

    tot_elapsed_time = time.time() - g_start_time

    assert output_j_path.find('IronDiff') >= 0
    with open(output_j_path, 'w') as f:
        f.write(json.dumps(results, sort_keys=True,
                           indent=2, separators=(',', ': ')))
    logger.info(f'Done processing {j_idx+1}/{j_num} {j_path} ({elapsed_time:.3f}s / {tot_elapsed_time:.3f}s)')


def serialize_hash_vals(hash_vals):
    return ';'.join(f'{val}:{freq}' for val, freq in sorted(hash_vals.items()))


def set_logger(outputdir):
    """
    Set logger level, syntax, and logfile

    Args
        outputdir: path of the output directory for the logfile
    """
    LOG_NAME = 'IronDiff'

    global logger
    logger = logging.getLogger(LOG_NAME)

    fh = logging.FileHandler(os.path.join(
        outputdir, '{}.log'.format(LOG_NAME)))
    fh.setLevel(logging.DEBUG)

    fmt = '%(asctime)s %(levelname)s %(message)s'
    formatter = coloredlogs.ColoredFormatter(fmt)
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    loglevel = 'INFO'
    coloredlogs.install(fmt=fmt,
                        level=loglevel,
                        logger=logger)


def process_function(blocks, arch):
    func_hash_vals = Counter()
    function_raw_hashes = {}
    for block_idx, (block_addr, block_info) in enumerate(sorted(blocks.items())):
        block_bytes_b64 = block_info['b64_bytes']
        if block_bytes_b64 is not None:
            block_bytes = base64.b64decode(block_bytes_b64)
        else:
            ks_arch, ks_mode = arch_to_keystone_map[arch]
            ks = keystone.Ks(ks_arch, ks_mode)
            assembly_code = '\n'.join(block_info['bb_disasm'])
            encoding, _ = ks.asm(assembly_code)
            block_bytes = bytes(encoding)
        expected_strands_idxs = block_info.get('expected_strands_idxs', None)

        function_raw_hashes[block_addr] = {}
        block_hash_vals, block_raw_hashes = extract_block_hash_vals(
            block_bytes, arch=arch, expected_strands_idxs=expected_strands_idxs)
        func_hash_vals.update(block_hash_vals)
        function_raw_hashes[block_addr] = block_raw_hashes

    return func_hash_vals, function_raw_hashes


def extract_block_hash_vals(block_bytes, arch, expected_strands_idxs=None):
    block_hash_vals = Counter()
    block_raw_hashes = []

    vex_blocks = extract_vex_blocks(block_bytes, arch)
    if expected_strands_idxs is not None:
        assert len(expected_strands_idxs) == len(vex_blocks)
    for vex_block_idx, vex_block in enumerate(vex_blocks):
        se = StrandsExtractor(vex_block, arch)
        block_strands_idxs, vex_block_hashes_vals, raw_hashes = se.extract_strands()

        if expected_strands_idxs is not None:
            assert block_strands_idxs == expected_strands_idxs[vex_block_idx], f'{block_strands_idxs} != {expected_strands_idxs[vex_block_idx]}'

        block_hash_vals.update(vex_block_hashes_vals)
        block_raw_hashes.extend(raw_hashes)

    return block_hash_vals, block_raw_hashes


def extract_vex_blocks(block_bytes, arch, vex_timeout=5):
    try:
        vex_blocks = func_timeout(
            vex_timeout,
            _extract_vex_blocks,
            args=(block_bytes, arch)
        )
    except FunctionTimedOut:
        raise Exception('timeout when extracting VEX block')
    except Exception:
        raise Exception('error while lifting VEX block')
    return vex_blocks


def _extract_vex_blocks(bytes_, arch, opt_level=2, start_addr=0x400000):
    off = 0
    addr = start_addr
    vex_blocks = []

    while off < len(bytes_):
        irsb = pyvex.lift(
            bytes_[off:], addr, strand_extractor.arch_to_pyvex_arch_map[arch], opt_level=opt_level)
        vex_blocks.append(irsb)
        addr += irsb.size
        off += irsb.size

    return vex_blocks

arch_to_keystone_map = {
    'x86': (keystone.KS_ARCH_X86, keystone.KS_MODE_32),
    'x86-32': (keystone.KS_ARCH_X86, keystone.KS_MODE_32),
    'x64': (keystone.KS_ARCH_X86, keystone.KS_MODE_64),
    'x86-64': (keystone.KS_ARCH_X86, keystone.KS_MODE_64),
    'arm32': (keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM),
    'arm-32': (keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM),
    'arm64': (keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN),
    'arm-64': (keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN),
    'mips32': (keystone.KS_ARCH_MIPS, keystone.KS_MODE_MIPS32),
    'mips-32': (keystone.KS_ARCH_MIPS, keystone.KS_MODE_MIPS32),
    'mips64': (keystone.KS_ARCH_MIPS, keystone.KS_MODE_MIPS64),
    'mips-64': (keystone.KS_ARCH_MIPS, keystone.KS_MODE_MIPS64),
}

if __name__ == '__main__':
    process()