add_library(hello-erc20 ${MRV_LIBRARY_TYPE} hello-erc20.c)
mrv_link_contract(hello-erc20 LIB_DEPENDS mrv_erc20)

add_library(native-erc20 ${MRV_LIBRARY_TYPE} native-erc20.c)
mrv_link_contract(native-erc20 LIB_DEPENDS mrv_erc20)
