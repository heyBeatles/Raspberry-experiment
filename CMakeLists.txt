cmake_minimum_required(VERSION 2.8)
project(testSocket)

set(CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")


add_executable(server server.cpp)

add_executable(client client.cpp
        agent.cpp
        agent.h
        )

add_executable(client_2 client_2.cpp
        agent.cpp
        agent.h
        )

add_executable(client_3 client_3.cpp
        agent.cpp
        agent.h
        )

add_executable(client_4 client_4.cpp
        agent.cpp
        agent.h
        )

add_executable(server_lcb server_lcb.cpp)

add_executable(helloWorldTest helloWorldTest.cpp)

add_executable(client_lcb client_lcb.cpp
        agent.cpp
        agent.h
        )

add_executable(testPaillier testPaillier.cpp
        agent.cpp
        agent.h
        )

INCLUDE_DIRECTORIES(/
        "/usr/local/include"
        "/usr/local/lib")

aux_source_directory(. SRC_LIST) # 搜索当前目录下的所有.cpp文件

target_link_libraries(server
        gmp
        pthread
        paillier)

target_link_libraries(client
        gmp
        pthread
#        wiringPi
        paillier)

target_link_libraries(client_2
        gmp
        pthread
#        wiringPi
        paillier)

target_link_libraries(client_3
        gmp
        pthread
#        wiringPi
        paillier)

target_link_libraries(client_4
        gmp
        pthread
#        wiringPi
        paillier)

target_link_libraries(helloWorldTest
        gmp
        pthread
#        wiringPi
        paillier)

target_link_libraries(testPaillier
        gmp
        pthread
#        wiringPi
        paillier)

target_link_libraries(server_lcb
        gmp
        pthread
#        wiringPi
        paillier)

target_link_libraries(client_lcb
        gmp
        pthread
#        wiringPi
        paillier)
