#!/bin/sh

# Usage: record_link_line.sh <output-file> <linker-arg>...
#
# This linker wrapper script writes the link command to $1, one argument per
# line, then exec(3)'s the linker. We run the linker to ensure that what is
# recorded is a link input that succeeds, otherwise this process exits returning
# non-zero. This script is called using CMake's <LANG>_LINKER_LAUNCHER property.
out=$1
shift
printf '%s\n' "$@" > "$out"
exec "$@"
