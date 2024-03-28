cmake_minimum_required(VERSION 3.16)
project(peba2 VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)

add_executable(peba2 main.cpp src/plain_math.cpp src/plain_math.h src/utilities.cpp src/utilities.h src/homomorphic_math.cpp src/homomorphic_math.h
        src/protocol_bfv.cpp
        src/protocol_bfv.h
        src/protocol_ckks.cpp
        src/protocol_ckks.h
        src/accuracy.cpp
        src/accuracy.h)

find_package(SEAL 4.1.1 REQUIRED)
target_link_libraries(peba2 SEAL::seal)
find_package(OpenSSL REQUIRED)
target_link_libraries(peba2 OpenSSL::SSL)
