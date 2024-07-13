add_executable(replay2 options.h driver.c init_trie_db.c replay.c)

target_compile_features(replay2 PRIVATE c_std_23)
target_link_libraries(replay2 PRIVATE monad_execution_c)
#target_compile_options(replay2 PRIVATE -Wall -Wpedantic -Werror)