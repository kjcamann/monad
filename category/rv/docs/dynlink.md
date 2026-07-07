# Runtime dynamic linking in the RV64 VM

Code targeting the Monad RISC-V virtual machine is compiled in one of two ways:

  1. Ordinary contracts are compiled into ELF executable files (ELF type
     `ET_EXEC`)

  2. A small number of preordained libraries are built as ELF shared objects
     (ELF type `ET_DYN`); these libraries are part of the platform SDK and the
     canonical binary artifacts used at blockchain runtime are distribured with
     the execution client (these can only be changed at a hard fork boundary)

## Contract code (`ET_EXEC`) ELF files

### Contract address space

For `ET_EXEC` code, the compiler toolchain generates references to in-image
addresses using the "medium low" (`medlow`) RISC-V code model. This means all
loaded program segments must be located within the bottom 2 GiB of RV64
address space.

This implies that contracts must in live in address space 0 (symbolic constant
`RVI_AS_PSABI`), below the stack and heap areas.

The address layout is fixed by the toolchain's linker script: non-writable
program segments are located at a 2 MiB offset from address zero (0x200000)
and writable segments are located at a 4 MiB offset (0x400000).

In the VM, addresses below 4 MiB are known to be image addresses: they do not
go through the VM's general purpose memory access machinery, but directly read
from the VM's view of that contract's loaded executable image.

### Dynamic linking support

A contract file may contain undefined symbols that need to bind to
implementations in shared libraries. If they do, the contract's full list of
dependencies is given via `DT_NEEDED` entries in the dynamic section. Binding
is eager (as if by `RTLD_NOW`) and performed by the dynamic linker before
contract execution begins.

For this reason, the `.dynamic` section and the dynamic link table sections
(`.got`, `.got.plt`, etc.) live in the _read-only_ part of the address space
that contains the executable code and other read-only data. This may look
strange if you examine the file with `readelf`, e.g., the `PT_DYNAMIC` program
segment will appear read-only (`PF_R` without `PF_W`). It is the RISC-V VM that
is loading these, so the flags don't mean anything aside from the meaning we
choose to assign to them. The link tables are filled out once by the dynamic
dynamic linker (before of contract execution) and then never modified again, so
in a runtime sense, they are read-only.

This is very different than the _genuinely_ writable segment (`.data`, `.bss`,
etc.); it must use copy-on-write semantics because the same contract can be
executed by multiple threads in parallel. This is located in a different part
of the address space so that checking one bit of address tells us if we need
to follow the CoW path or the shared read path.

A contract file _can_ be built "free standing": the required functions from the
platform SDK will be statically linked into it, at the cost of a larger binary.
In this case, the contract ELF may not contain a dynamic section, or it may
contain an empty one (just `DT_NULL`).

The symbol `g_mrv_default_param_abi` (which contracts must define) is placed at
exactly 0x400000. This symbol, which represents the contract's default encoding
ABI, is unusual: it's externally referenced by the standard library but isn't
defined there. More will be said about this in the shared library section.

### Variables set at `init_contract` time

In the EVM1 contract creation model, the initial "create" transaction returns
the code to be stored in the database. This allows the initial run of the
contract to "bake in" important values directly into the contract code, so that
they won't need to be placed in storage. This avoids expensive storage loads
of essential contract state that isn't known until initialization time, but is
never changed after that. As an example, the `name` and `symbol` of an ERC-20
contract are set this way.

A similar mechanism is supported for MRV contract executables. If a variable is
placed in an object file's `.data.contract_init` section[^2], the linker script
will relocate it to a special read-only loadable segment in the final
executable.

This segment is similar to the "write-once" dynamic linkage table segment
described above, where "read-only" actually means "read-only during ordinary
contract execution, after an earlier initialization modifies it".

[^2]: This is done in C with the helper macro `MRV_CONTRACT_INIT`, syntactic
sugar for `__attribute__((section(".data.contract_init")))`

### MRV-specific program segment flags

Although the "read-only linkage table" and "contract initialization" schemes are
similar, there is one important difference. The modifications to the linkage
table are not stored as permenant changes to the executable. In other words, the
changes are not part of the ELF image written to the code database. They cannot
be, because the linkage addresses of dynamic libraries can change in the future.

By contrast, the contract initialization writes _are_ saved directly into the
ELF file contents that are stored in the code database. They modify the image
permenantly. That is the point: to get back the most important "code
modification at initialization time" feature that EVM1 has.

Because the VM needs to treat them differently, they are kept in two different
read-only `PT_LOAD` segments, and special segment flags in their program header
(`p_flags` in `Elf64_Phdr`) mark which kind of special segment they are.

ELF permits segment flag bits with the mask `0xff00000` to be used for operating
system extensions. We use bit `0x0100000` (`RVI_ELF_PF_DYN`) to mark the linkage
table segment and bit `0x0200000` (`RVI_ELF_PF_INIT`) to mark the contract
initialization data section.

## Shared library (`ET_DYN`) ELF files

### Sharing code on blockchains

The platform SDK's own libraries can be built as shared libraries and linked to.
At runtime, the content of the code that is actually dynamically linked to is a
canonical binary blob associated with current fork of the Monad blockchain.

This binary must be identical during a particular execution fork because if it
were not, any change in the machine code could induce a change in the gas cost of
execution. This would change the transaction receipt, and destroy the ability
to achieve distributed consensus on the Merklized `receipts_root` value.

In this way, shared libraries are similar to precompiles, except they are not
implemented directly in the VM. Most often, they are simple utility functions
which _can_ be inlined, but which may not be depending on the compiler's
speed/size optimization choice. In the common case (for example, in the Solidty
ABI decoding library) most of the functions are inlinable but a few are not.

ABI stability is maintained using the SONAME scheme of shared libraries. This
implies that 

  - ABI breaking changes need a .so increment

  - The blockchain must keep around all .so versions that have ever existed,
    because an old contract may still be using them [unless, at a hard fork
    boundary, it can be proved that there are no users]

As punishing as the latter requirement sounds, it is no different than a
blockchain's normal state guarantees.

### Dynamic linking model

The dynamic linker is implemented in the VM; there is no external
"interpreter" and thus no `PT_INTERP` program header. All symbols within
a single shared library always bind internally if they can (i.e., the
`-Bsymbolic` behavior). This means techniques like symbol interposition
will not work, similar to loading the library with POSIX's `RTLD_LOCAL`
behavior flag.

As with the contract executables, the shared objects also use eager binding,
as if by the POSIX `RTLD_NOW` (linker extension `-z now`).

In general, shared objects do not reference any symbols in objects which
are loaded later on _except_ for the standard library external symbol
`g_mrv_default_param_abi`. This is treated as a special case, and is known
to be located at absolute address 0x400000. References to that symbol are
directly patched to that VM virtual address.

Shared object code is position independent, but the relative offsets of
the the segments is fixed by the toolchain's linker script. Non-writable
library segments are located at `load_address + 0`. Writable segments are
located at an 8 MiB offset from the load address, `load_address + 0x800000`.

The distinction between the two address ranges is made for the same reason
as for contract executables. For a shared object, the non-writable segment
(containing data from `.text`, `.rodata`, etc.) is _actually_ shared. It
exists once in the memory of the VM.[^1]

[^1]: The non-writable segment is also called the "RX" segment (after its
dual read/execute purpose). The associated relative memory region is called
`SHARED_RX` in the linker script.

The writable section, however, must be copy-on-write, since it is private
to each contract that uses the library. As a concrete example, the global
`errno` variable in libc lives in libc's `.data` section. It has a different
value in every executing contract. Thus the writable data segment is treated
in the following way:

  - It is loaded as described on disk, during VM startup

  - The shared object's `.got` table is populated during the startup of the
    VM's dynamic linker; for example, the standard library
    (`libmrv_stdlib.so.<abi-version>`) contains unresolved references to
    symbols from the RISC-V libc; these are all resolved during VM startup,
    and after this, no further changes to the "writable" segment will occur

  - Contracts may read from the common view of the data segment; if they
    need to write to it, a copy-on-write mechanism is implemented, similar
    to OS virtual memory `MAP_PRIVATE`

The RISC-V interpreter is able to easily decode reads and writes to the
shared object memory segments because of the way the address encoding works.
It uses the following scheme:

  - The lowest 23 bits (0 - 22) give the offset within the writable (W) or
    non-writable (RX) segment

  - If bit 23 is 0, this is an access of the read/execute segment; if 1,
    to the writable segment

  - All shared code is loaded with a base address in an RVI address space
    that holds all the shared code (symbolic constant `RVI_AS_SHARED_LIBRARY`)

  - When the VM starts, the dependency graph of all shared objects is built
    and topologically sorted; each library is numbered in visit order
    (`dso_index`), and its base load address is:


    ```
    dso_base_load_addr = base_addr(RVI_AS_SHARED) + dso_index * 0x1000000
    ```

The runtime address of a shared memory image location is encoded like this:

```
  63              55            39                    23   22                0
 .---------------.-----...-----.-------------------.------.-------------------.
 | RVI_AS_SHARED |   unused    |  shared lib index | RX/W |  segment offset   |
 .---------------.-----...-----.-------------------.------.-------------------.

```

The interpreter, seeing any address, can easily decode it:

```c

switch (addr >> RVI_ADDR_SPACE_OFFSET_BITS) {
  case RVI_AS_PSABI:
    // heap/stack/contract code address, not shown...
    break;

    // ... other special address spaces

  case RVI_AS_SHARED_LIBRARY:
    // Access to shared code:
    //   1. Check that bits 55-40 are zero, BAD_ACCESS otherwise
    //
    //   2. Check that bits 39-24 are the index of a shared library
    //      that is actually loaded, BAD_ACCESS otherwise, i.e., check
    //      dso_index = (addr & RVI_ADDR_SPACE_OFFSET_MASK) >> 24
    //      is a DSO we know about
    //
    //   3. if (write_instruction & ~(addr & (0x1 << 23)))
    //        return BAD_ACCESS; // Can't write to read-only segment
    //      if (write_instruction)
    //        follow_copy_on_write_path(linker->dsos[dso_index], addr) // do segment bounds checking, CoW
    //      else
    //        follow_read_path(linker->dsos[dso_index], addr) // do segment bounds checking and the read
}
```
