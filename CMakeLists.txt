project(ababuselist)
cmake_minimum_required(VERSION 3.22)
add_compile_options(-g)

add_executable(ababuselist ababuselist.c)
target_link_libraries(ababuselist)
