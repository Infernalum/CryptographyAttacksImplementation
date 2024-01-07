include(FetchContent)

# Remove unnecessary build files
# and steps from GTest's CMake
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG        v1.14.0
)
FetchContent_MakeAvailable(googletest)
add_library(GTest::GTest INTERFACE IMPORTED)
target_link_libraries(GTest::GTest INTERFACE gtest_main)

add_executable(utests validate.cpp unit-modes.cpp)

target_link_libraries(utests
 PRIVATE
  GTest::GTest
  BlockCipherModsImpl)

add_test(utests_gtests utests)