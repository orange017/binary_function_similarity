cmake_minimum_required(VERSION 3.12)
project(Catalog1 C)

add_library(catalog1 SHARED
    catalog1.c
    catalog1.h
)

set(CMAKE_INSTALL_PREFIX ${CMAKE_SOURCE_DIR}/bin)

install(TARGETS catalog1
    LIBRARY DESTINATION .
    RUNTIME DESTINATION .
    ARCHIVE DESTINATION .
)