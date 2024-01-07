cmake_minimum_required(VERSION 3.5.0)
project(OTP LANGUAGES CXX)

add_executable(${CMAKE_PROJECT_NAME} otp.cpp)

include(FetchContent)

FetchContent_Declare(json GIT_REPOSITORY https://github.com/nlohmann/json.git
                          GIT_TAG v3.11.3)
FetchContent_MakeAvailable(json)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE nlohmann_json::nlohmann_json)


