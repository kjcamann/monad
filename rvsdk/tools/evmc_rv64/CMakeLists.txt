add_library(rv64_vm SHARED
  # XXX: shim for now
  ../../../category/core/assert.c
  ../../lib/stdlib/host/backtrace.c

  host_exec.c
  vm.c)

set_target_properties(rv64_vm PROPERTIES C_VISIBILITY_PRESET hidden)
target_link_libraries(rv64_vm PRIVATE monad_rv_limited monad_core_limited evmc::evmc)
