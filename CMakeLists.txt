cmake_minimum_required(VERSION 3.10)
project(winhorse LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

file(GLOB HEADERS
    ${CMAKE_CURRENT_SOURCE_DIR}/*.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/*.h
)

set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/syscalls.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/windows.cpp
)

message(STATUS "Found sources: ${SOURCES}")

add_subdirectory(deps/KUBERA)
add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/deps/KUBERA
    ${CMAKE_CURRENT_SOURCE_DIR}/deps/KUBERA/deps/linux-pe
    ${CMAKE_CURRENT_SOURCE_DIR}/deps/KUBERA/deps/boost_multiprecision/include
    ${CMAKE_CURRENT_SOURCE_DIR}/deps/KUBERA/deps/boost_config/include
)

target_link_libraries(${PROJECT_NAME} PRIVATE Kubera)
target_compile_definitions(${PROJECT_NAME} PUBLIC BOOST_MP_STANDALONE)
