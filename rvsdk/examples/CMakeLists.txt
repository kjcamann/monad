add_library(hello-erc20 SHARED hello-erc20.c)
set_target_properties(hello-erc20 PROPERTIES C_VISIBILITY_PRESET hidden)
target_link_libraries(hello-erc20 PRIVATE mrv_erc20 mrv_stdlib)

if(APPLE)
  target_link_options(hello-erc20 PRIVATE -Wl,-undefined,dynamic_lookup
      -Wl,-u,_mrv_start -Wl,-u,_mrv_init)
else()
  # Ensure `mrv_start` and `mrv_init` are pulled in from the static mrv_stdlib
  target_link_options(hello-erc20 PRIVATE -Wl,-u,mrv_start -Wl,-u,mrv_init)
endif()

add_library(native-erc20 SHARED native-erc20.c)
set_target_properties(native-erc20 PROPERTIES C_VISIBILITY_PRESET hidden)
target_link_libraries(native-erc20 PRIVATE mrv_erc20 mrv_stdlib)

if(APPLE)
  target_link_options(native-erc20 PRIVATE -Wl,-undefined,dynamic_lookup
     -Wl,-u,_mrv_start, -Wl,-u,_mrv_init)
else()
  # Ensure `mrv_start` is pulled in the static mrv_stdlib
  target_link_options(native-erc20 PRIVATE -Wl,-u,mrv_start -Wl,-u,mrv_init)
endif()
