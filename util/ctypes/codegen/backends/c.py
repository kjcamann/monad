import argparse
import pathlib
import sys
import textwrap

from c_codegen_common import *
from typing import Mapping, Optional, TextIO
from typeinfo import *

MODULE_HEADER_PROLOGUE = """
/**
 * @file
 *
{file_doc_comment}
 */

#include <stdint.h>
{extra_includes}
// clang-format off
#ifdef __cplusplus
extern "C"
{{
#endif
"""

MODULE_HEADER_EPILOGUE = \
"""#ifdef __cplusplus
} // extern "C"
#endif"""

def emit_module_header_prologue(emit_warning: bool, module: ModuleInfo, out: TextIO):
  file_comment_lines = (f' * {line}' for line in
                        textwrap.wrap(module.doc_comment, break_long_words=False,
                                      break_on_hyphens=False))
  module_include_lines = list(f'#include <{str(get_module_header_path(md))}>'
                              for md in module.dependencies if not md.is_external_only)
  module_include_lines += module.lang_attrs.get('c', {}).get('extra_includes', [])
  if module.is_event_module:
    module_include_lines.insert(0, '#include <stddef.h>') # Need size_t for _EVENT_COUNT
    module_include_lines.append('#include <category/core/event/event_metadata.h>')
  if module_include_lines:
    module_include_lines += ['']
  print(GPL_V3_LICENSE_COMMENT, file=out)
  print(file=out) # Skip a line
  print('#pragma once', file=out)
  if emit_warning:
    print(file=out)
    print(C_CODEGEN_WARNING_FORMAT.format(create_command_comment()), file=out)
  print(MODULE_HEADER_PROLOGUE.format(
      file_doc_comment = '\n'.join(file_comment_lines),
      extra_includes = '\n'.join(module_include_lines)), file=out)

def emit_module_header_epilogue(out: TextIO):
  print(MODULE_HEADER_EPILOGUE, file=out)

def emit_type_comment(comment: str, out: TextIO):
  comment_lines = list()
  for paragraph in comment.split('\n\n'):
    # Wrap the lines in the paragraph, then add an extra blank line to preserve
    # the paragraph nature.
    comment_lines += textwrap.wrap(paragraph, width=80-len('/// '),
                                   break_long_words=False, break_on_hyphens=False) + ['']
  comment_lines.pop(-1)
  print('\n'.join(f'/// {c}'.strip() for c in comment_lines), file=out)

def emit_enum_type(
    module: ModuleInfo,
    enum_info: EnumTypeInfo,
    out: TextIO):
  emit_type_comment(enum_info.doc_comment, out)
  enum_type_name = get_c_type_name(module, enum_info)
  storage_type_name = get_c_type_name(module, enum_info.underlying_type)

  enum_lang_attrs = enum_info.lang_attrs.get('c', dict())
  enum_prefix = enum_lang_attrs.get('prefix', None)
  if not enum_prefix:
    context = f'enum type {enum_info.qual_name}'
    raise ValueError(f'{context} did not define a lang.c.prefix key')

  print(f'''enum {enum_type_name} : {storage_type_name}
{{''', file=out)
  for name, value in enum_info.values:
    print(f'    {enum_prefix.upper()}_{name.upper()} = {value},', file=out)
  print('};\n', file=out)

def emit_alias_type(
    module: ModuleInfo,
    alias_info: AliasTypeInfo,
    out: TextIO):
  emit_type_comment(alias_info.doc_comment, out)
  alias_type_name = get_c_type_name(module, alias_info)
  storage_type_name = get_c_type_name(module, alias_info.underlying_type,
                                      elaborated_type_specifier=True)

  assert not alias_info.strong, 'no lowering strategy for strong typedefs in C yet'
  print(f'typedef {storage_type_name} {alias_type_name};\n', file=out)

def emit_struct_type(
    module: ModuleInfo,
    struct_info: RecordTypeInfo,
    out: TextIO):
  struct_type_name = get_c_type_name(module, struct_info)
  emit_type_comment(struct_info.doc_comment, out)
  print(f'''struct {struct_type_name}
{{''', file=out)

  field_decl_lines: list[list[str]] = []
  max_field_decl_len = 0
  field_indent = 4
  for field_info in struct_info.fields:
    storage_type_name = get_c_type_name(module, field_info.type_info,
                                        elaborated_type_specifier=True)
    field_decl = f'{storage_type_name} {field_info.name};'
    if len(field_decl) + field_indent > 40:
      decl_lines = [storage_type_name, f'{"":>{field_indent}}{field_info.name};']
    else:
      decl_lines = [field_decl]
    max_field_decl_len = max(max_field_decl_len, max(len(c) for c in decl_lines))
    field_decl_lines.append(decl_lines)

  max_field_decl_len = min(max_field_decl_len, 40)
  for field_info, decl_lines in zip(struct_info.fields, field_decl_lines):
    if len(decl_lines) == 1:
      print(f'{"":{field_indent}}{decl_lines[0]:<{max_field_decl_len}}'
            f' ///< {field_info.doc_comment}', file=out)
    else:
      assert len(decl_lines) == 2
      print(f'{"":{field_indent}}{decl_lines[0]}', file=out)
      print(f'{"":{field_indent}}{decl_lines[1]:<{max_field_decl_len}}'
            f' ///< {field_info.doc_comment}', file=out)

  print('};\n', file=out)

def emit_event_enum_type(module: ModuleInfo, out: TextIO):
  event_type_prefix = get_c_type_name_prefix(module)
  print(
f"""/// Each type of event is assigned a unique value in this enumeration
enum {event_type_prefix}_event_type : uint16_t
{{""", file=out)

  for td in module.type_defs.values():
    if td.event_name:
      print(f'    {event_type_prefix.upper()}_{td.event_name.upper()},', file=out)

  print('};\n', file=out)

def emit_module_header_file(
    args: argparse.Namespace,
    module: ModuleInfo,
    out: TextIO):
  emit_module_header_prologue(not args.no_warning, module, out)

  if module.is_event_module:
    emit_event_enum_type(module, out)

  for type_info in module.type_defs.values():
    if isinstance(type_info, EnumTypeInfo):
      emit_enum_type(module, type_info, out)
    elif isinstance(type_info, AliasTypeInfo):
      emit_alias_type(module, type_info, out)
    elif isinstance(type_info, RecordTypeInfo):
      emit_struct_type(module, type_info, out)
    elif isinstance(type_info, (ExternalTypeInfo, EmptyTypeInfo)):
      pass # No code generation for these
    else:
      assert False, 'missing support for this type family'

  print('// clang-format on\n', file=out)
  if module.is_event_module:
    n_types = module.event_count
    event_type_prefix = get_c_type_name_prefix(module)
    event_ring_type = module.event_config.event_ring_type
    event_count_constant = f'{event_type_prefix.upper()}_EVENT_COUNT'
    print(
f"""constexpr size_t {event_count_constant} = {n_types};
extern struct monad_event_metadata const g_{event_type_prefix}_event_metadata[{event_count_constant}];
extern uint8_t const g_{event_type_prefix}_event_schema_hash[32];

constexpr char MONAD_EVENT_DEFAULT_{event_ring_type.upper()}_FILE_NAME[] = \\
    "monad-{event_ring_type}-events";
""", file=out)

  emit_module_header_epilogue(out)

#
# event metadata content and functions
#

METADATA_PROLOGUE = \
"""#include <stdint.h>

#include <category/core/event/event_metadata.h>
#include <{0}>

#ifdef __cplusplus
extern "C"
{{
#endif
"""

METADATA_EPILOGUE = \
"""
#ifdef __cplusplus
} // extern "C"
#endif"""

def emit_metadata_prologue(emit_warning: bool, module: ModuleInfo, out: TextIO):
  print(GPL_V3_LICENSE_COMMENT, file=out)
  print(file=out) # Skip a line
  if emit_warning:
    print(C_CODEGEN_WARNING_FORMAT.format(create_command_comment()), file=out)
    print(file=out)
  print(METADATA_PROLOGUE.format(get_module_header_path(module)), file=out)

def emit_metadata_epilogue(out: TextIO):
  print(METADATA_EPILOGUE, file=out)

def emit_metadata_array(module: ModuleInfo, out: TextIO):
  event_type_prefix = get_c_type_name_prefix(module)
  event_count_constant = f'{event_type_prefix.upper()}_EVENT_COUNT'
  print(
f'''struct monad_event_metadata const g_{event_type_prefix}_event_metadata[{event_count_constant}] = {{''',
    file=out)
  for td in module.type_defs.values():
    if not td.event_name:
      continue
    name_upper = td.event_name.upper()
    short_doc_comment = td.doc_comment.split('\n')[0]
    print(file=out) # Skip a line
    print(f'    [{event_type_prefix.upper()}_{name_upper}] =', file=out)
    print(f'        {{.event_type = {event_type_prefix.upper()}_{name_upper},', file=out)
    print(f'         .c_name = "{name_upper}",', file=out)
    print(f'         .description = "{short_doc_comment}"}},', file=out)
  print('};', file=out)

  print(file=out)
  evt_hash = module.compute_hash()
  print(f'uint8_t const g_{event_type_prefix}_event_schema_hash[32] = {{', file=out)
  for b in range(0, 32, 8):
    hash_initializer = ', '.join(f'0x{b:02x}' for b in evt_hash[b:b+8])
    print(f'    {hash_initializer},', file=out)
  print('};', file=out)

def emit_event_metadata_file(args: argparse.Namespace, module: ModuleInfo,
                             out: TextIO):
  emit_metadata_prologue(not args.no_warning, module, out)
  emit_metadata_array(module, out)
  emit_metadata_epilogue(out)

def c_main(args: argparse.Namespace, module_map: Mapping[str, ModuleInfo]) -> int:
  clang_format_args = check_c_backend_common_args(args)

  for module_name, module in module_map.items():
    if module.is_external_only:
      continue

    if args.module and module_name not in args.module:
      continue

    # Emit module's header file
    header_file_name = f'{module_name}.h'
    if args.stdout:
      print(f'//! {header_file_name} contents:', file=sys.stdout)
      emit_module_header_file(args, module, sys.stdout)
    else:
      header_dir = module.lang_attrs.get('c', {}).get('header_output_dir', None)
      header_dir = pathlib.Path(header_dir) if header_dir else pathlib.Path('.')
      header_full_path = args.path / header_dir / header_file_name
      with open(header_full_path, 'wt') as out:
        emit_module_header_file(args, module, out)
      try_run_clang_format(args.clang_format, clang_format_args,
                           header_full_path)

    # If this is an event module, emit its metadata source file
    if module.is_event_module:
      metadata_file_name = f'{module.name}_metadata.c'
      if args.stdout:
        print(f'//! {metadata_file_name} contents:', file=sys.stdout)
        emit_event_metadata_file(args, module, sys.stdout)
      else:
        metadata_file_path = args.path / header_dir / metadata_file_name
        with open(metadata_file_path, 'wt') as out:
          emit_event_metadata_file(args, module, out)
        try_run_clang_format(args.clang_format, clang_format_args,
                             metadata_file_path)

  return 0

def register_backend(subparsers):
  p = subparsers.add_parser('c',
      help='generate C type bindings for the C language')
  setup_c_backend_common_args(p, 'C')

  p.set_defaults(backend_main=c_main)
