import argparse
import pathlib
import sys

from c_codegen_common import *
from typing import Mapping, Optional, TextIO
from typeinfo import *

FORMATTER_HEADER_PROLOGUE = """
/**
 * @file
 *
 * Defines {format_library} formatters for the C types in `{module_name}.h`
 */

#include <bit>
#include <cstddef>
{format_includes}
#include <iterator>
#include <span>
#include <string_view>
#include <utility>

{extra_includes}"""

def get_formatter_header_path(module: ModuleInfo) -> pathlib.Path:
  header_dir = module.lang_attrs.get('cxx_format', {}).get('header_output_dir', None)
  if not isinstance(header_dir, str):
    raise ValueError(f'module `{module.name}` is missing a header output directory')
  return pathlib.Path(header_dir) / f'{module.name}_fmt.hpp'

def emit_formatter_header_prologue(module: ModuleInfo, emit_warning: bool,
                                   use_fmtlib: bool, out: TextIO):
  if use_fmtlib:
    format_headers = ['<quill/bundled/fmt/format.h>']
  else:
    # std::back_insert_iterator on std::string replaces fmt::memory_buffer
    format_headers = ['<format>', '<string>']
  include_lines = list(f'#include <{get_formatter_header_path(md)}>'
                       for md in module.dependencies if not md.is_external_only)
  include_lines += module.lang_attrs.get('cxx_format', {}).get('extra_includes', [])
  include_lines.insert(0, f'#include <{get_module_header_path(module)}>')
  if include_lines:
    include_lines += ['']
  print('#pragma once', file=out)
  if emit_warning:
    print(file=out)
    print(C_CODEGEN_WARNING_FORMAT.format(create_command_comment()), file=out)
  print(FORMATTER_HEADER_PROLOGUE.format(
      format_library = 'fmtlib' if use_fmtlib else 'C++20',
      module_name = module.name,
      format_includes = '\n'.join(f'#include {h}' for h in format_headers),
      extra_includes = '\n'.join(include_lines)), file=out)

# Enum formatter strategy: the formatter inherits from the underlying type,
# and just prints it reusing the base class formatter.
# TODO(ken): we could easily support a style like `<enum-name> [<enum-value>]`
#   but this is more work...do it later
def emit_enum_formatter(module: ModuleInfo, enum_info: EnumTypeInfo,
                        use_fmtlib: bool, out: TextIO):
  namespace = 'fmt' if use_fmtlib else 'std'
  c_type_name = get_c_type_name(module, enum_info)
  underlying_c_type = get_c_type_name(module, enum_info.underlying_type)
  print(
f"""template <>
struct {namespace}::formatter<{c_type_name}> : {namespace}::formatter<{underlying_c_type}>
{{
    template <typename FormatContext>
    auto format({c_type_name} const &value, FormatContext &ctx) const
    {{
        return {namespace}::formatter<{underlying_c_type}>::format(std::to_underlying(value), ctx);
    }}
}};
""", file=out)

STRUCT_FORMATTER_DECL = \
'''template <>
struct {namespace}::formatter<{c_type_name}> : {namespace}::formatter<std::string_view>
{{
    template <typename FormatContext>
    auto format({c_type_name} const &value, FormatContext &ctx) const
    {{
        {memory_buffer_type} mb;
        std::back_insert_iterator i{{mb}};
        i = {namespace}::format_to(i, "{decl_type_name} {{{{");
{field_lines}
        *i++ = '}}';
{trailing_lines}
        std::string_view const view{{mb.data(), mb.size()}};
        return {namespace}::formatter<std::string_view>::format(view, ctx);
    }}
}};
'''

def emit_struct_formatter(module: ModuleInfo, struct_info: RecordTypeInfo,
                          use_fmtlib: bool, out: TextIO):
  namespace = 'fmt' if use_fmtlib else 'std'
  c_type_name = get_c_type_name(module, struct_info)

  field_lines = list()

  # Pattern: i = std::format_to(i, ", <field_name> = {}", value.<field_name>);
  for field_num, field_info in enumerate(struct_info.fields):
    comma_prefix = ', ' if field_num > 0 else ''
    field_lines.append(
        f'i = {namespace}::format_to(i, "{comma_prefix}{field_info.name} = {{}}", value.{field_info.name});')

  trailing_lines = list()

  for sized_field_no, size_field in enumerate(f for f in struct_info.fields if f.trailing_array_element_type):
    # Pattern:
    #   auto const *p = std::bit_cast<std::byte const *>(&value + 1); // First only
    #   i = std::format_to(i, ", <trailing_name> = {}",
    #       std::span{std::bit_cast< <element_c_type_name> const *>(p),
    #                 static_cast<size_t>(value.<size_field>)});
    #   p += value.<size_field> * sizeof(<element_c_type_name>);
    if sized_field_no == 0:
      trailing_lines.append('auto const *p = std::bit_cast<std::byte const *>(&value + 1);')

    element_c_type_name = get_c_type_name(module, size_field.trailing_array_element_type)
    trailing_label = size_field.name
    if trailing_label.endswith('_count'):
      trailing_label = trailing_label[:-len('_count')] + ' list'
    elif trailing_label.endswith('_length'):
      trailing_label = trailing_label[:-len('_length')]
    trailing_lines.append(f'i = {namespace}::format_to(i, ", {trailing_label} = {{}}", ' +
        f'std::span{{std::bit_cast<{element_c_type_name} const *>(p), ' +
        f'static_cast<size_t>(value.{size_field.name})}});')
    trailing_lines.append(f'p += value.{size_field.name} * sizeof({element_c_type_name});')

  indent = ' ' * 8
  print(STRUCT_FORMATTER_DECL.format(
      namespace = 'fmt' if use_fmtlib else 'std',
      c_type_name = c_type_name,
      memory_buffer_type = 'fmt::memory_buffer' if use_fmtlib else 'std::string',
      decl_type_name = struct_info.type_name,
      field_lines = '\n'.join(f'{indent}{line}' for line in field_lines),
      trailing_lines = '\n'.join(f'{indent}{line}' for line in trailing_lines)
      ), file=out)

def emit_formatter(module: ModuleInfo, type_info: TypeInfo, use_fmtlib: bool,
                   out: TextIO):
  if isinstance(type_info, EnumTypeInfo):
    emit_enum_formatter(module, type_info, use_fmtlib, out)
  elif isinstance(type_info, AliasTypeInfo):
    assert not type_info.strong
    # We don't need to do anything here, since we only support weak typedefs
    # right now, and those don't affect the type deduction
  elif isinstance(type_info, RecordTypeInfo):
    emit_struct_formatter(module, type_info, use_fmtlib, out)
  elif isinstance(type_info, (ExternalTypeInfo, EmptyTypeInfo)):
    pass # No code generation for these
  else:
    assert False, "don't know how to format this type family"

def emit_format_as_function(module: ModuleInfo, use_fmtlib: bool, out: TextIO):
  event_type_prefix = get_c_type_name_prefix(module)
  event_ring_type = module.event_config.event_ring_type
  enum_type = f'{event_type_prefix}_event_type'
  namespace = 'fmt' if use_fmtlib else 'std'
  print(
f'''namespace monad {{

template <std::output_iterator<char> Out>
Out format_as(Out o, void const *payload_buf, {enum_type} event_type)
{{
    switch(event_type) {{''', file=out)

  for td in module.type_defs.values():
    if not td.event_name:
      continue
    event_code = f'{event_type_prefix.upper()}_{td.event_name.upper()}'
    if isinstance(td, (EnumTypeInfo, RecordTypeInfo, AliasTypeInfo)):
      c_type_name = get_c_type_name(module, td)
      print(
f'''        case {event_code}:
            return {namespace}::format_to(o, "{{}}", *static_cast<{c_type_name} const *>(payload_buf));''',
         file=out)
    elif isinstance(td, EmptyTypeInfo):
      print(
f'''       case {event_code}: return o;''', file=out)
    elif isinstance(td, ExternalTypeInfo):
      pass
    else:
      assert False, "don't know how to generate cases for this type family"

  print(
f'''        default:
            return {namespace}::format_to(o, "unknown {event_ring_type} type code {{}}",
                                  std::to_underlying(event_type));
    }}
    std::unreachable();
}}

}} // namespace monad''', file=out)

def emit_formatter_header(args: argparse.Namespace, module: ModuleInfo, out: TextIO):
  emit_formatter_header_prologue(module, not args.no_warning, args.fmtlib, out)

  for td in module.type_defs.values():
    emit_formatter(module, td, args.fmtlib, out)

  if module.is_event_module:
    emit_format_as_function(module, args.fmtlib, out)

def cxx_format_main(args: argparse.Namespace, module_map: Mapping[str, ModuleInfo]) -> int:
  clang_format_args = check_c_backend_common_args(args)

  for module_name, module in module_map.items():
    if module.is_external_only:
      continue

    if args.module and module_name not in args.module:
      continue

    formatter_file_name = f'{module_name}_fmt.hpp'
    if args.stdout:
      print(f'//! {formatter_file_name} contents:', file=sys.stdout)
      emit_formatter_header(args, module, sys.stdout)
    else:
      header_dir = module.lang_attrs.get('cxx_format', {}).get('header_output_dir', None)
      header_dir = pathlib.Path(header_dir) if header_dir else pathlib.Path('.')
      formatter_full_path = args.path / header_dir / formatter_file_name
      with open(formatter_full_path, 'wt') as out:
        emit_formatter_header(args, module, out)
      try_run_clang_format(args.clang_format, clang_format_args,
                           formatter_full_path)

def register_backend(subparsers):
  p = subparsers.add_parser('cxx-format',
      help='generate C++20 std::format (or fmtlib) formatters for C types')
  setup_c_backend_common_args(p, 'C++')

  p.add_argument('--fmtlib', action='store_true',
      help='emit fmtlib formatters instead of C++20 standardized ones')

  p.set_defaults(backend_main=cxx_format_main)
