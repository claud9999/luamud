project(luamud)

cmake_minimum_required(VERSION 3.25)

add_custom_command(
    OUTPUT ${PROJECT_BINARY_DIR}/luamud.sqlite
    DEPENDS ${PROJECT_SOURCE_DIR}/luamud.sql
    COMMAND sqlite3 ${PROJECT_BINARY_DIR}/luamud.sqlite < ${PROJECT_SOURCE_DIR}/luamud.sql
)

add_custom_target(luamud_sqlite ALL DEPENDS ${PROJECT_BINARY_DIR}/luamud.sqlite)

include_directories(/usr/local/include/lua)

link_directories(/usr/local/lib)

add_executable(
    luamud
    luamud.c
)

target_link_libraries(luamud sqlite3 lua)
