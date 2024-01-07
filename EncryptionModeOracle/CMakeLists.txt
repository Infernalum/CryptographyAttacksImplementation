cmake_minimum_required(VERSION 3.5.0)
project(EncryprionModeOracle VERSION 0.1.0 LANGUAGES CXX)
set (CMAKE_CXX_STANDARD 17)

## На случай, если зависимостей по типу curl'а в системе нет, 
## иначе компилятор на отсуствие библиотек будет ругаться
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(${CMAKE_PROJECT_NAME} encryprionmodeoracle.cpp) 
target_include_directories(${CMAKE_PROJECT_NAME} PUBLIC include)

include(FetchContent)

FetchContent_Declare(json GIT_REPOSITORY https://github.com/nlohmann/json.git
                          GIT_TAG v3.11.3)
FetchContent_MakeAvailable(json)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE nlohmann_json::nlohmann_json)

FetchContent_Declare(cpr GIT_REPOSITORY https://github.com/libcpr/cpr.git
                         GIT_TAG 1.10.5)
FetchContent_MakeAvailable(cpr)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE cpr::cpr)


