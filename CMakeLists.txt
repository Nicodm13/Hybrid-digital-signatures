cmake_minimum_required(VERSION 3.20)

project(2025_System_and_Network_Security LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Server (Windows only)
add_executable(server
        src/server.c
)

target_include_directories(server
        PRIVATE
        ${PROJECT_SOURCE_DIR}/include
)

if(WIN32)
    target_link_libraries(server ws2_32)
elseif(UNIX)
    target_link_libraries(server pthread)
endif()

# Client (Linux only)
if(UNIX)

    find_package(OpenSSL REQUIRED)
    find_library(OQS_LIB oqs REQUIRED)

    # Hybrid image signing app
    add_executable(hybrid_app
            src/main.c
            src/hybrid_signature.c
            src/hash.c
            src/signatures/ecdsa_sig.c
            src/signatures/rsa_pss_sig.c
            src/pq-signatures/dilithium_sig.c
            src/pq-signatures/falcon_sig.c
            src/pq-signatures/sphincs_sig.c
            src/image_uploader.c
            src/image_buffer.c
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
            src/hash.c
            src/signatures/ecdsa_sig.c
            src/signatures/rsa_pss_sig.c
            src/pq-signatures/dilithium_sig.c
            src/pq-signatures/falcon_sig.c
            src/pq-signatures/sphincs_sig.c
    )

    target_include_directories(benchmark
            PRIVATE
            ${PROJECT_SOURCE_DIR}/include
    )

    target_link_libraries(benchmark
            OpenSSL::Crypto
            ${OQS_LIB}
    )

    # File tamper utility (no crypto)
    add_executable(file_tamper
            src/file_tamper.c
    )

    target_include_directories(file_tamper
            PRIVATE
            ${PROJECT_SOURCE_DIR}/include
    )

endif()
