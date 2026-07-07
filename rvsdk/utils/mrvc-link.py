#!/usr/bin/env python3

import argparse
import compression.zstd
import hashlib
import pathlib
import shutil
import struct
import subprocess
import sys

parser = argparse.ArgumentParser(
  prog='mrvc-link',
  description='Partially link ELF objects/archives into an MRVC code binary')

parser.add_argument('-b', '--bin', action='store_true',
  help='Produce a `.mrvc` txn data binary blob')

parser.add_argument('-o', '--output', required=True, type=str,
  help='Output object file')

parser.add_argument('--linker', default='ld.lld',
  help='Path to a linker that supports elf64-littleriscv')

parser.add_argument('--objcopy', default='objcopy',
  help='Path to objcopy utility')

parser.add_argument('--nm', default='nm', help='Path to nm utility')

parser.add_argument('-m', '--sym-map-search-dir', action='append',
  default=[], type=pathlib.Path, help='Add symbol map search path directory')

parser.add_argument('-n', '--dry-run', action='store_true',
  help='Print the commands that would run, without running them')

parser.add_argument('-N', '--abi-name', help='Set the ABI name of an MRVC file')

parser.add_argument('-i', '--named-import', action='append',
  default=list(), help='Add a named import to the object')

parser.add_argument('-u', '--uncompressed', action='store_true',
  help='Do not zstd-compress the code payload')

parser.add_argument('-v', '--verbose', action='count', default=0,
  help='Be more verbose; can be repeated')

parser.add_argument('input', nargs='*', help='Input to the partial link')

ELF_NOTE_VENDOR_NAME = b'CategoryLabsMRVC\x00\x00\x00\x00'
ELF_NOTE_ABI_NAME_TYPE = 1
ELF_NOTE_NAMED_IMPORT_TYPE = 2

def emit_mrvc_note_bytes(name: str, note_type: int) -> bytes:
  assert note_type in (ELF_NOTE_ABI_NAME_TYPE, ELF_NOTE_NAMED_IMPORT_TYPE)
  name_hash = hashlib.new('keccak-256', name.encode('utf-8')).digest()
  return struct.pack('<III', len(ELF_NOTE_VENDOR_NAME), len(name_hash),
                     note_type) + ELF_NOTE_VENDOR_NAME + name_hash

def objcopy_mrvc_note(args: argparse.Namespace, name: str, note_type: int):
  contents = emit_mrvc_note_bytes(name, note_type)
  filename = f'/tmp/{name}.note.bin'
  if args.dry_run:
    print(f'writing note file {filename}', file=sys.stdout)
  else:
    with open(filename, 'wb') as note_file:
      note_file.write(contents)

  note_name = f'.note.mrvc_import.{name}' if note_type == ELF_NOTE_NAMED_IMPORT_TYPE else \
      f'.note.mrvc_name.{name}'
  objcopy_args = (args.objcopy, '--add-section', f'{note_name}={filename}',
      f'--set-section-flags', f'{note_name}=alloc,readonly', args.output)

  if args.dry_run:
    print(' '.join(objcopy_args), file=sys.stdout)
  else:
    subprocess.run(objcopy_args, check=True)

def output_mrvc_file(args: argparse.Namespace):
  with open(args.output, 'rb') as in_file:
    code_contents = in_file.read()
    if not args.uncompressed:
      code_contents = compression.zstd.compress(code_contents, level=19)
    code_header = struct.pack('<cccI', b'\xAE', b'\x00', b'\x01', len(code_contents))

    code_blob = code_header + code_contents
    mrvc_path = pathlib.Path(args.output).with_suffix('.mrvc')
    if args.abi_name:
      to_hash = args.abi_name.encode('utf-8')
      name_type = 'ABI_NAME'
    else:
      to_hash = code_blob
      name_type = 'CODE_HASH'

    code_hash = hashlib.new('keccak-256', to_hash).digest()
    print(f'{mrvc_path} => {code_hash.hex()} [{name_type}]', file=sys.stdout)
    if not args.dry_run:
      with open(mrvc_path, 'wb') as out_file:
        out_file.write(code_blob)

def create_abi_name_symbol_map(args: args.Namespace) -> pathlib.Path:
  map_filename = pathlib.Path(args.abi_name + '.map')
  nm_args = (args.nm, '--export-symbols', args.output)

  if args.dry_run:
    print(' '.join(nm_args), file=sys.stdout)
    return map_filename

  nm_proc = subprocess.Popen(nm_args, stdout=subprocess.PIPE, text=True, bufsize=1)
  redefine_pairs = list()
  for line in nm_proc.stdout:
    sym = line.rstrip('\n')
    redefine_pairs.append((sym, f'!{args.abi_name}:{sym}'))

  with open(map_filename, 'wt') as map_file:
    for (sym, mangled) in redefine_pairs:
      print(f'{sym} {mangled}', file=map_file)

  return map_filename

def mangle_versioned_symbols(args: args.Namespace, abi_name: str):
  map_filename = pathlib.Path(abi_name + '.map')
  if args.dry_run:
    # XXX: this is not exactly what runs, because we need to search the
    # directories for the map files
    objcopy_args = (args.objcopy, f'--redefine-syms={map_filename}', args.output)
    print(' '.join(objcopy_args), file=sys.stdout)
  else:
    sym_map_files = list(x / map_filename for x in args.sym_map_search_dir if
                         (x / map_filename).is_file())
    if not sym_map_files:
      raise ValueError(f'object `{args.output}` depends on symbol map file ' +
                       f'`{map_filename}` but it was not found on any path in ' +
                       f'{args.sym_map_search_dir}')
    if len(sym_map_files) > 1:
      print(f'warning: multiple conflicting symbol map files found: {sym_map_files}',
            file=sys.stderr)
    objcopy_args = (args.objcopy, f'--redefine-syms={sym_map_files[0]}', args.output)
    subprocess.run(objcopy_args, check=True)

def main(args: argparse.Namespace) -> int:
  linker = shutil.which(args.linker)
  if not linker:
    raise ValueError(f'value of --linker `{args.linker}` not found on $PATH')
  else:
    args.linker = linker

  objcopy = shutil.which(args.objcopy)
  if not objcopy:
    raise ValueError(f'value of --objcopy `{args.objcopy}` not found on $PATH')
  else:
    args.objcopy = objcopy

  nm = shutil.which(args.nm)
  if not nm:
    return ValueError(f'value of --nm `{args.nm}` not found on $PATH')
  else:
    args.nm = nm

  # The first step is to turn any number of input static libraries and objects
  # into a single relocatable object file containing all symbols, using the -r
  # linker option; this single ET_REL object is what gets processed by the MRV
  # dynamic linker
  linker_args = (args.linker, '-r', '--whole-archive') + tuple(args.input) + \
      ('--no-whole-archive', '-o', f'{args.output}')
  if args.dry_run:
    print(' '.join(linker_args), file=sys.stdout)
  else:
    subprocess.run(linker_args, check=True)

  # Deduplicate the symbol map search directories while preserving the search
  # order
  args.sym_map_search_dir = list(dict.fromkeys(args.sym_map_search_dir))

  if args.abi_name:
    # This library is tagged with an explicit "ABI name", an DT_SONAME-like
    # concept that is used to version shared code; we do two things with a
    # library that has an ABI name:
    #
    #   1. We create an ELF note specifying that name and its keccak-256 hash
    #
    #   2. All the public symbols in the object are extracted we generate
    #      a symbol mapping file that maps <sym> to !<abi-name>:<sym>
    #
    # The symbol mapping file will be used by an
    #
    #    objdump --redefine-syms=<filename> <object>
    #
    # command by any later object that imports the library with that ABI name.

    # Add the ELF note
    objcopy_mrvc_note(args, args.abi_name, ELF_NOTE_ABI_NAME_TYPE)

    # Emit the symbol map file
    create_abi_name_symbol_map(args)

  for i in args.named_import:
    # For each named import we see, we do two things:
    #
    #  1. We create an ELF note specifying that name and its keccak-256 hash
    #
    #  2. We look for the symbol map file and mangle all the symbols in the
    #     object to include the ABI name

    # Add the ELF note
    objcopy_mrvc_note(args, i, ELF_NOTE_NAMED_IMPORT_TYPE)

    # ABI-name-mangle all the import's symbols according to its symbol map file
    mangle_versioned_symbols(args, i)

  if args.bin:
    output_mrvc_file(args)

  return 0

if __name__ == '__main__':
  sys.exit(main(parser.parse_args()))
