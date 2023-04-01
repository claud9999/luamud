project(luamud)
set (CMAKE_C_FLAGS "-g -DDEBUG")

cmake_minimum_required(VERSION 3.1)

add_custom_command(
    OUTPUT ${PROJECT_BINARY_DIR}/luamud.sqlite
    DEPENDS ${PROJECT_SOURCE_DIR}/luamud.sql
    COMMAND sqlite3 ${PROJECT_BINARY_DIR}/luamud.sqlite < ${PROJECT_SOURCE_DIR}/luamud.sql
)

add_custom_target(luamud_sqlite ALL DEPENDS ${PROJECT_BINARY_DIR}/luamud.sqlite)

if (LINUX)
    include_directories(/usr/include/lua5.4)
elseif (APPLE)
    include_directories(/usr/local/include/lua)
    include_directories(/usr/local/Cellar/openssl@3/3.1.0/include)
    link_directories(/usr/local/lib)
    link_directories(/usr/local/Cellar/openssl@3/3.1.0/lib)
endif()

add_executable(
    luamud
    luamud.c
)

target_link_libraries(luamud sqlite3 lua5.4 ssl crypto)
