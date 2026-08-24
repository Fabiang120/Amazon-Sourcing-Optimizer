cmake_minimum_required(VERSION 3.10)
project(Amazon2)
set(CMAKE_CXX_STANDARD 17)

# Ensure you're using the correct case for the package name
find_package(xlnt CONFIG REQUIRED)
find_package(cpprestsdk CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
add_executable(Amazon2 main.cpp)
target_link_libraries(Amazon2 PRIVATE
    xlnt::xlnt
    cpprestsdk::cpprest
    OpenSSL::SSL
    OpenSSL::Crypto
)

