# OpenSSL 3.5 LTS, built as static libraries from the pinned release
# tarball (msys perl + make on Windows). No system OpenSSL is searched
# or trusted; the import table stays free of third-party DLLs.
include(ExternalProject)

set(IZAN_OPENSSL_VERSION 3.5.0)
set(IZAN_OPENSSL_PREFIX ${CMAKE_BINARY_DIR}/deps/openssl)
set(IZAN_OPENSSL_INSTALL ${IZAN_OPENSSL_PREFIX}/install)

# The external make runs concurrently with ninja's own compile jobs;
# uncapped this doubles up to 2×NCORES compilers and can exhaust the
# Windows commit limit (observed: cc1 "out of memory" at -j16 + ninja).
cmake_host_system_information(RESULT IZAN_NCORES QUERY NUMBER_OF_LOGICAL_CORES)
if(IZAN_NCORES GREATER 8)
    set(IZAN_OPENSSL_JOBS 8)
else()
    set(IZAN_OPENSSL_JOBS ${IZAN_NCORES})
endif()

if(WIN32)
    set(IZAN_OPENSSL_TARGET mingw64)
    set(IZAN_OPENSSL_SYSLIBS "ws2_32;crypt32;bcrypt")
else()
    set(IZAN_OPENSSL_TARGET linux-x86_64)
    set(IZAN_OPENSSL_SYSLIBS "dl;pthread")
endif()

ExternalProject_Add(openssl_ep
    URL https://github.com/openssl/openssl/releases/download/openssl-${IZAN_OPENSSL_VERSION}/openssl-${IZAN_OPENSSL_VERSION}.tar.gz
    PREFIX ${IZAN_OPENSSL_PREFIX}
    DOWNLOAD_EXTRACT_TIMESTAMP ON
    BUILD_IN_SOURCE ON
    # no-autoload-config: never read openssl.cnf — a wallet must not
    # take engine/provider directives from a file on disk. The fixed
    # --openssldir keeps the builder's home directory out of the binary
    # (the path is embedded verbatim) and points nowhere by design.
    CONFIGURE_COMMAND perl <SOURCE_DIR>/Configure ${IZAN_OPENSSL_TARGET}
        no-shared no-tests no-apps no-docs no-legacy no-autoload-config
        --prefix=${IZAN_OPENSSL_INSTALL} --libdir=lib
        # Drive-letter literal: msys perl rewrites POSIX-style paths to
        # its own root, which would leak the builder's home again.
        --openssldir=C:/pm/no-openssl-dir
    BUILD_COMMAND make -j${IZAN_OPENSSL_JOBS}
    INSTALL_COMMAND make install_sw
    BUILD_BYPRODUCTS
        ${IZAN_OPENSSL_INSTALL}/lib/libssl.a
        ${IZAN_OPENSSL_INSTALL}/lib/libcrypto.a
    LOG_CONFIGURE ON
    LOG_BUILD ON
    LOG_INSTALL ON
)

# Imported targets need their include directory to exist at configure
# time.
file(MAKE_DIRECTORY ${IZAN_OPENSSL_INSTALL}/include)

add_library(OpenSSL::Crypto STATIC IMPORTED GLOBAL)
set_target_properties(OpenSSL::Crypto PROPERTIES
    IMPORTED_LOCATION ${IZAN_OPENSSL_INSTALL}/lib/libcrypto.a
    INTERFACE_INCLUDE_DIRECTORIES ${IZAN_OPENSSL_INSTALL}/include
    INTERFACE_LINK_LIBRARIES "${IZAN_OPENSSL_SYSLIBS}")

add_library(OpenSSL::SSL STATIC IMPORTED GLOBAL)
set_target_properties(OpenSSL::SSL PROPERTIES
    IMPORTED_LOCATION ${IZAN_OPENSSL_INSTALL}/lib/libssl.a
    INTERFACE_INCLUDE_DIRECTORIES ${IZAN_OPENSSL_INSTALL}/include
    INTERFACE_LINK_LIBRARIES OpenSSL::Crypto)

# Imported targets cannot carry build dependencies; consumers link the
# interface target instead.
add_library(pm_openssl INTERFACE)
target_link_libraries(pm_openssl INTERFACE OpenSSL::SSL OpenSSL::Crypto)
add_dependencies(pm_openssl openssl_ep)
