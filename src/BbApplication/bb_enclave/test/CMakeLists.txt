cmake_minimum_required(VERSION 2.6)

#Locate GTest
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS} ../../../ ../../../common_enclave/)

set (CMAKE_CXX_STANDARD 11)

#Link runTests with what we want to test and the pthread library
add_executable(runTests tests.cpp ../Graph.cpp ../Edge.cpp ../PartyId.cpp ../BlackBoxExecuter.cpp)
target_link_libraries(runTests ${GTEST_LIBRARIES} pthread)
