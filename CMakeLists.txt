cmake_minimum_required(VERSION 3.28)
project(polymarket-cpp LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

include(FetchContent)
set(FETCHCONTENT_QUIET OFF)

# The cryptographic floor: keccak/EIP-712, secp256k1 and libsodium all
# arrive through izan-crypto, pinned by commit.
FetchContent_Declare(izan_crypto
    GIT_REPOSITORY https://github.com/izandotai/izan-crypto.git
    GIT_TAG 83899cb
    EXCLUDE_FROM_ALL
)
FetchContent_Declare(doctest
    URL https://github.com/doctest/doctest/archive/refs/tags/v2.4.11.tar.gz
    DOWNLOAD_EXTRACT_TIMESTAMP ON
    EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(izan_crypto doctest)

# pm_core: signing, credentials and codecs — everything needed to
# build and authenticate requests, nothing that talks to a network.
add_library(pm_core STATIC
    pm/auth.cpp
    pm/codec.cpp
    pm/keys.cpp
    pm/signing.cpp
)
add_library(pm::core ALIAS pm_core)
target_include_directories(pm_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(pm_core PUBLIC izan::crypto izan::units sodium)

if(PROJECT_IS_TOP_LEVEL)
    enable_testing()
    add_executable(pm_tests tests/pm_test.cpp)
    target_link_libraries(pm_tests PRIVATE pm::core doctest::doctest)
    add_test(NAME pm_tests COMMAND pm_tests)
endif()
