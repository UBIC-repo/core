cmake_minimum_required(VERSION 3.7)
project(ubic)

set(CMAKE_CXX_STANDARD 11)

add_definitions(${Boost_LIB_DIAGNOSTIC_DEFINITIONS})
find_package(Boost REQUIRED)
if(NOT Boost_FOUND)
    message(FATAL_ERROR "Could not find boost")
endif()
include_directories(${Boost_INCLUDE_DIRS})
link_libraries(boost_serialization)
link_libraries(boost_system)
link_libraries(boost_filesystem)
link_libraries(pthread)
link_libraries(ssl)
link_libraries(crypto)

set(SOURCE_FILES
        main.cpp
        HttpClient.cpp
        HttpClient.h
        ApiKey.cpp
        ApiKey.h
        FS/FS.h
        FS/FS.cpp
        )

add_executable(ubic ${SOURCE_FILES})