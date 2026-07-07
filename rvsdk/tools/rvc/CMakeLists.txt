add_library(rvc SHARED
  # XXX: shim for now
  ../../../category/core/assert.c
  ../../lib/stdlib/host/backtrace.c

  lib/config.c
  lib/host_exec.c
  lib/log.c
  lib/rvc.c)

set_target_properties(rvc PROPERTIES C_VISIBILITY_PRESET hidden)
target_include_directories(rvc PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(rvc PRIVATE ../../third_party/musl)
target_link_libraries(rvc PRIVATE monad_rv monad_core_limited evmc::evmc ucl)

add_library(rvc_loader STATIC lib/loader.c lib/log.c)
target_include_directories(rvc_loader PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(rvc_loader PUBLIC c_std_23)
target_compile_options(rvc_loader PRIVATE -Werror)
target_link_libraries(rvc_loader PRIVATE evmc::evmc)
