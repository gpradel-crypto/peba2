cmake_minimum_required(VERSION 3.16)
project(threats-seal VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)

add_executable(threats-seal main.cpp src/math.cpp src/math.h src/utilities.cpp src/utilities.h)

find_package(SEAL 3.7 REQUIRED)
target_link_libraries(threats-seal SEAL::seal)
