include_directories(${CMAKE_CURRENT_SOURCE_DIR})

find_package(CLI11 REQUIRED)

add_executable(monad monad.cpp)
monad_compile_options(monad)

target_link_libraries(monad PRIVATE monad_execution monad_statesync
                                    CLI11::CLI11)

if(DEFINED ENV{GIT_COMMIT_HASH})
  set(GIT_COMMIT_HASH $ENV{GIT_COMMIT_HASH})
else()
  execute_process(
    COMMAND git rev-parse HEAD
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_COMMIT_HASH
    OUTPUT_STRIP_TRAILING_WHITESPACE)
endif()

target_compile_definitions(monad PRIVATE GIT_COMMIT_HASH="${GIT_COMMIT_HASH}")
add_executable(monad_cli monad_cli.cpp)
monad_compile_options(monad_cli)
target_link_libraries(monad_cli PUBLIC monad_execution CLI11::CLI11)

add_executable(eventcap eventcap.cpp)
monad_compile_options(eventcap)
target_link_libraries(eventcap PRIVATE monad_event_consumer CLI11::CLI11)

add_executable(monad_edit_trace
        monad_edit_trace/analysis.cpp
        monad_edit_trace/extract_block.cpp
        monad_edit_trace/main.cpp
        monad_edit_trace/merge.cpp
        monad_edit_trace/print.cpp
        monad_edit_trace/show.cpp
        monad_edit_trace/strip.cpp
        monad_edit_trace/trace_file_reader.cpp
        monad_edit_trace/trace_file_writer.cpp)
monad_compile_options(monad_edit_trace)
target_link_libraries(monad_edit_trace monad_core CLI11::CLI11)
