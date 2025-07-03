cmake_minimum_required(VERSION 3.1.0 FATAL_ERROR)
project(mdns)

find_package(Qt5 COMPONENTS Widgets REQUIRED)
add_subdirectory(../../ qtnetworkng)

add_executable(mdns main.cpp)
target_link_libraries(mdns qtnetworkng Qt5::Widgets)
