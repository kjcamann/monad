option(MRV_EXAMPLES_STATIC_RUNTIME "Statically link the platform SDK into the example contracts" OFF)

mrv_add_contract(hello-erc20 hello-erc20.c)
mrv_add_contract(native-erc20 native-erc20.c)

foreach(_target hello-erc20 native-erc20)
  if(MRV_EXAMPLES_STATIC_RUNTIME)
    target_link_options(${_target} PRIVATE ${MRV_DEAD_STRIP_LINK_OPTIONS})
    target_link_libraries(${_target} PRIVATE mrv_erc20_static mrv_stdlib_static)
  else()
    target_link_libraries(${_target} PRIVATE mrv_erc20_shared mrv_stdlib_shared)
  endif()
endforeach()
