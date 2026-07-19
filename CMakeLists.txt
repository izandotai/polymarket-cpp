cmake_minimum_required(VERSION 3.28)
project(polymarket-cpp LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

include(FetchContent)
set(FETCHCONTENT_QUIET OFF)
include(cmake/openssl.cmake)

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
# Boost beast/asio for the HTTPS transport, from the official CMake
# release tarball.
set(BOOST_INCLUDE_LIBRARIES beast asio)
set(BOOST_ENABLE_CMAKE ON)
set(BOOST_SKIP_INSTALL_RULES ON)
FetchContent_Declare(Boost
    URL https://github.com/boostorg/boost/releases/download/boost-1.87.0/boost-1.87.0-cmake.tar.xz
    DOWNLOAD_EXTRACT_TIMESTAMP ON
    EXCLUDE_FROM_ALL
)
# Reflection-based JSON for request bodies and venue answers.
FetchContent_Declare(glaze
    URL https://github.com/stephenberry/glaze/archive/refs/tags/v7.8.4.tar.gz
    DOWNLOAD_EXTRACT_TIMESTAMP ON
    EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(izan_crypto doctest Boost glaze)

# pm_core: signing, credentials, codecs and amount arithmetic —
# everything needed to build and authenticate requests, nothing that
# talks to a network.
add_library(pm_core STATIC
    pm/amounts.cpp
    pm/auth.cpp
    pm/codec.cpp
    pm/keys.cpp
    pm/signing.cpp
)
add_library(pm::core ALIAS pm_core)
target_include_directories(pm_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(pm_core PUBLIC izan::crypto izan::units sodium)

# pm_net: the synchronous HTTPS transport (Beast, OS trust anchors).
add_library(pm_net STATIC
    net/ws_client.cpp
    net/http_client.cpp
    net/tls.cpp
)
add_library(pm::net ALIAS pm_net)
target_include_directories(pm_net PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(pm_net PUBLIC Boost::beast Boost::asio pm_openssl)
if(WIN32)
    target_link_libraries(pm_net PUBLIC ws2_32 mswsock crypt32)
endif()

# pm_clob: the venue client — market data, credentials and orders.
add_library(pm_clob STATIC
    pm/clob.cpp
)
add_library(pm::clob ALIAS pm_clob)
target_include_directories(pm_clob PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(pm_clob PUBLIC pm_core pm_net PRIVATE glaze::glaze)

# pm_feeds: the three live sockets — CLOB market books, the
# authenticated user channel, and the real-time data socket.
add_library(pm_feeds STATIC
    pm/market_ws.cpp
    pm/rtds.cpp
    pm/user_ws.cpp
)
add_library(pm::feeds ALIAS pm_feeds)
target_include_directories(pm_feeds PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(pm_feeds PUBLIC pm_core pm_net PRIVATE glaze::glaze)

if(PROJECT_IS_TOP_LEVEL)
    enable_testing()
    add_executable(pm_tests tests/pm_test.cpp)
    target_link_libraries(pm_tests PRIVATE pm::clob pm::feeds doctest::doctest)
    add_test(NAME pm_tests COMMAND pm_tests)
endif()
