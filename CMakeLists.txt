cmake_minimum_required(VERSION 3.20)

project(2025_System_and_Network_Security C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_library(OQS_LIB oqs REQUIRED)

# Hybrid image signing
add_executable(hybrid_app
        src/main.c
        src/image_buffer.c
        src/hybrid_signature.c
        src/hash.c
        src/signatures/ecdsa_sig.c
        src/signatures/rsa_pss_sig.c
        src/pq-signatures/dilithium_sig.c
        src/pq-signatures/falcon_sig.c
        src/pq-signatures/sphincs_sig.c
        src/image_uploader.c
)

target_include_directories(hybrid_app
        PRIVATE
        ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(hybrid_app
        OpenSSL::Crypto
        ${OQS_LIB}
        curl
)

# Upload server
add_executable(server
        src/server.c
)

target_include_directories(server
        PRIVATE
        ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(server
        pthread
)

# Verify executable
add_executable(verify
        src/verify.c
        src/hybrid_signature.c
        src/hash.c
        src/signatures/ecdsa_sig.c
        src/signatures/rsa_pss_sig.c
        src/pq-signatures/dilithium_sig.c
        src/pq-signatures/falcon_sig.c
        src/pq-signatures/sphincs_sig.c
)

target_include_directories(verify
        PRIVATE
        ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(verify
        OpenSSL::Crypto
        ${OQS_LIB}
)

# Benchmark executable
add_executable(benchmark
        src/benchmark.c
        src/hash.c
        src/signatures/ecdsa_sig.c
        src/signatures/rsa_pss_sig.c
        src/pq-signatures/dilithium_sig.c
        src/pq-signatures/falcon_sig.c
        src/pq-signatures/sphincs_sig.c
        include/image_uploader.h
)

target_include_directories(benchmark
        PRIVATE
        ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(benchmark
        OpenSSL::Crypto
        ${OQS_LIB}
)
