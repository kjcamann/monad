add_library(rvcode SHARED
  # XXX: shim for now
  ../../../category/core/assert.c
  ../../lib/stdlib/host/backtrace.c

  ../../../category/rv/rv_code.c
  ../../../category/rv/rv_code_cache.c)

target_link_libraries(rvcode PRIVATE monad_core_limited ${libzstd_file})

if(LIBELF_FOUND)
  target_link_libraries(rvcode PRIVATE PkgConfig::LIBELF)
else()
  target_link_libraries(rvcode PRIVATE -lelf)
endif()
