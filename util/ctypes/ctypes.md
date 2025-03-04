# C type libraries and code generator

Sometimes the most efficient and convenient way to pass data between threads
or processes on the same host is to place it into a C structure and directly
copy the bits.

Most languages have strong support for interoperating with the C language.
For example, both Rust and the Python ship with language-level and standard
library features for working with data from C.

This directory contains descriptions of various important data types,
defined in TOML files. It also contains a code generator which can
automatically output the generated code for various languages.
