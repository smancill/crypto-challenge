cmake_minimum_required(VERSION 3.11)
project(crypto_challenge LANGUAGES CXX)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "No build type selected, default to Release")
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Choose the type of build." FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
    Debug Release MinSizeRel RelWithDebInfo)
endif()

if(NOT DEFINED BUILD_SHARED_LIBS)
  set(BUILD_SHARED_LIBS ON)
endif()

include(GNUInstallDirs)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_BINDIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR})


find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
  set(CMAKE_CXX_COMPILER_LAUNCHER "${CCACHE_PROGRAM}" CACHE PATH "")
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_MACOSX_RPATH ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_compile_options(-Wall -Wextra)


include(FetchContent)

find_package(OpenSSL REQUIRED)

add_subdirectory(src/third_party)
add_library(crypto src/crypto.cpp src/util.cpp src/wrappers.cpp)
target_include_directories(crypto PUBLIC
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>)
target_link_libraries(crypto PRIVATE base64 OpenSSL::Crypto)
target_compile_definitions(crypto PUBLIC span_CONFIG_INDEX_TYPE=std::size_t)


macro(add_crypto_exe set ch)
  set(exe_name s${set}ch${ch})
  add_executable(${exe_name} src/set${set}/challenge${ch}.cpp)
  target_link_libraries(${exe_name} PRIVATE crypto)
  unset(exe_name)
endmacro()

add_crypto_exe(01 03)
add_crypto_exe(01 04)
add_crypto_exe(01 06)
add_crypto_exe(01 07)
add_crypto_exe(01 08)

add_crypto_exe(02 10)
add_crypto_exe(02 11)
add_crypto_exe(02 12)
add_crypto_exe(02 13)
add_crypto_exe(02 14)
add_crypto_exe(02 16)


enable_testing()
add_subdirectory(test/third_party)

macro(add_crypto_test set)
  set(test_name test_s${set})
  add_executable(${test_name} test/test_set${set}.cpp)
  add_test(NAME ${test_name} COMMAND ${test_name})
  target_link_libraries(${test_name} PRIVATE crypto gmock_main)
  unset(test_name)
endmacro()

add_crypto_test(01)
add_crypto_test(02)
