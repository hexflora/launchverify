cmake_minimum_required(VERSION 3.16)
project(launchverify VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(BUILD_TESTS "Build unit tests" ON)

add_library(launchverify_core STATIC
    src/core/hash.cpp
    src/core/signature.cpp
    src/core/report.cpp
)
target_include_directories(launchverify_core PUBLIC include)
target_link_libraries(launchverify_core PUBLIC bcrypt wintrust crypt32)
target_compile_options(launchverify_core PRIVATE -Wall -Wextra -Wpedantic -Werror)

add_executable(launchverify src/app/main.cpp)
target_include_directories(launchverify PRIVATE include)
target_link_libraries(launchverify PRIVATE launchverify_core)
target_compile_options(launchverify PRIVATE -Wall -Wextra -Wpedantic -Werror)

if(BUILD_TESTS)
    include(FetchContent)
    FetchContent_Declare(Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG v3.5.0
    )
    FetchContent_MakeAvailable(Catch2)

    enable_testing()

    add_executable(launchverify_tests
        tests/hash_tests.cpp
        tests/signature_tests.cpp
        tests/report_tests.cpp
    )
    target_include_directories(launchverify_tests PRIVATE include)
    target_link_libraries(launchverify_tests PRIVATE launchverify_core Catch2::Catch2WithMain)
    target_compile_options(launchverify_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)

    include(Catch)
    catch_discover_tests(launchverify_tests)
endif()