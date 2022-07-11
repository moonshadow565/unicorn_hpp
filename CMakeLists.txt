cmake_minimum_required(VERSION 3.20)

project(unicorn_hpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FindDoxygen)
include(FetchContent)

find_package(Doxygen)

set(UNICORN_BUILD_SHARED OFF CACHE INTERNAL "Disable shared unicorn build!")
FetchContent_Declare(
  unicorn
  GIT_REPOSITORY https://github.com/unicorn-engine/unicorn.git
  GIT_TAG        6c1cbef6ac505d355033aef1176b684d02e1eb3a # 2.0
  GIT_SUBMODULES ""
)
FetchContent_MakeAvailable(unicorn)

FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG        153965a655fe62841297ed0532edc161d1b3c4aa
)
FetchContent_MakeAvailable(Catch2)

add_library(unicorn_hpp INTERFACE include/unicorn.hpp)
target_link_libraries(unicorn_hpp INTERFACE unicorn)
target_include_directories(unicorn_hpp INTERFACE include ${unicorn_SOURCE_DIR}/include)

add_executable(tests_hpp
    tests/test_example.cpp
    tests/test_x86.cpp
    )
target_link_libraries(tests_hpp PRIVATE unicorn_hpp Catch2::Catch2WithMain)

list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
include(CTest)
include(Catch)
catch_discover_tests(tests_hpp)

if (DOXYGEN_FOUND)
    set(DOXYGEN_EXTRACT_ALL "YES")
    set(DOXYGEN_INCLUDE_PATH ${unicorn_SOURCE_DIR}/include)
    doxygen_add_docs(unicorn_hpp_docs include/unicorn.hpp)
endif()