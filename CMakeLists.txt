cmake_minimum_required(VERSION 3.16)
project(peba-seal VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)

add_executable(peba-seal main.cpp src/plain_math.cpp src/plain_math.h src/utilities.cpp src/utilities.h src/homomorphic_math.cpp src/homomorphic_math.h)

find_package(SEAL 4.0 REQUIRED)
target_link_libraries(peba-seal SEAL::seal)
find_package(OpenSSL REQUIRED)
target_link_libraries(peba-seal OpenSSL::SSL)
