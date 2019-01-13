cmake_minimum_required(VERSION 3.9)
project(toxtore VERSION 0.0.1 DESCRIPTION "Storage engine and multi-device synchronization for Tox")
include(GNUInstallDirs)

# Search for dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(TOXCORE REQUIRED toxcore)
pkg_check_modules(SQLCIPHER REQUIRED sqlcipher)

# Build toxtore library
add_library(toxtore SHARED src/toxtore.c src/util.c)
set_target_properties(toxtore PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 0
    PUBLIC_HEADER include/toxtore.h)

target_include_directories(toxtore PRIVATE include)

target_link_libraries(toxtore ${TOXCORE_LIBRARIES} ${SQLCIPHER_LIBRARIES})
target_include_directories(toxtore PUBLIC ${TOXCORE_INCLUDE_DIRS} ${SQLCIPHER_INCLUDE_DIRS})
target_compile_options(toxtore PUBLIC ${TOXCORE_CFLAGS_OTHER} ${SQLCIPHER_CFLAGS_OTHER} -DSQLITE_HAS_CODEC)

configure_file(toxtore.pc.in toxtore.pc @ONLY)

# Build minitox
add_executable(mdmt src/minitox.c)

target_include_directories(mdmt PRIVATE include)

target_link_libraries(mdmt ${TOXCORE_LIBRARIES} ${SQLCIPHER_LIBRARIES} toxtore)
target_include_directories(mdmt PUBLIC ${TOXCORE_INCLUDE_DIRS} ${SQLCIPHER_INCLUDE_DIRS})
target_compile_options(mdmt PUBLIC ${TOXCORE_CFLAGS_OTHER} ${SQLCIPHER_CFLAGS_OTHER})

# Installation 
install(TARGETS toxtore
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES ${CMAKE_BINARY_DIR}/toxtore.pc
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig)

# uncomment to install mdmt
# install(TARGETS mdmt DESTINATION ${CMAKE_INSTALL_BINDIR})
