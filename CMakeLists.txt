cmake_minimum_required(VERSION 3.16)
project(MyProject)
add_executable(test ckkss_example.cpp)
find_package(SEAL 4.1 REQUIRED)
target_link_libraries(test SEAL::seal)

