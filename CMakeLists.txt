cmake_minimum_required(VERSION 3.20)

project(2025_System_and_Network_Security C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

add_executable(2025_System_and_Network_Security
        src/main.c
        src/ecdsa_sig.c
        src/dilithium_sig.c
        src/sphincs_sig.c
        src/rsa_pss_sig.c
        src/falcon_sig.c
        include/scheme.h
)

target_include_directories(2025_System_and_Network_Security
        PRIVATE include
)

target_link_libraries(2025_System_and_Network_Security
        oqs
        OpenSSL::Crypto
)
