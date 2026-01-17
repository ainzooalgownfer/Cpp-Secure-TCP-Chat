cmake_minimum_required(VERSION 3.16)
project(crypto_ CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ------------------ vcpkg toolchain ------------------
set(CMAKE_TOOLCHAIN_FILE "C:/dev/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "")

# ------------------ Find OpenSSL ------------------
find_package(OpenSSL REQUIRED)

# ------------------ Client executable ------------------
add_executable(crypto_
        src/client.cpp
        src/CryptoUtils.cpp
)
target_link_libraries(crypto_ PRIVATE ws2_32 OpenSSL::SSL OpenSSL::Crypto)

# ------------------ Server executable ------------------
add_executable(Server_
        src/server.cpp
        src/CryptoUtils.cpp
)
target_link_libraries(Server_ PRIVATE ws2_32 OpenSSL::SSL OpenSSL::Crypto)

# ------------------ Crypto test executable ------------------
add_executable(cryptotest_
        src/TestCrypto.cpp
        src/CryptoUtils.cpp
)
target_link_libraries(cryptotest_ PRIVATE ws2_32 OpenSSL::SSL OpenSSL::Crypto)

