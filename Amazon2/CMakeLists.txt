cmake_minimum_required(VERSION 3.10)
project(Amazon2)
set(CMAKE_CXX_STANDARD 17)

# Ensure you're using the correct case for the package name
find_package(xlnt CONFIG REQUIRED)
find_package(cpprestsdk CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
add_executable(Amazon2 main.cpp)
target_link_libraries(Amazon2 PRIVATE xlnt::xlnt)
target_link_libraries(Amazon2 PRIVATE cpprestsdk::cpprest cpprestsdk::cpprestsdk_zlib_internal cpprestsdk::cpprestsdk_brotli_internal)
target_link_libraries(Amazon2 PRIVATE OpenSSL::SSL OpenSSL::Crypto)

