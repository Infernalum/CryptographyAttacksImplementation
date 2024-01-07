
set (CMAKE_CXX_STANDARD 17)

add_library(BlockCipherModsImpl blockcipher.cpp)

target_include_directories(BlockCipherModsImpl PUBLIC include)

set(OPENSSL_ROOT_DIR "C:/msys64/mingw64")

find_package(OpenSSL REQUIRED)
target_link_libraries(BlockCipherModsImpl OpenSSL::SSL)

add_definitions(-Dlcrypto)