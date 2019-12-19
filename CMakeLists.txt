cmake_minimum_required(VERSION 3.1)

project(crypto_benchmark)

include(CheckIncludeFile)

find_package(OpenSSL
	COMPONENTS Crypto
	REQUIRED
)

find_package(PkgConfig
	REQUIRED
)

pkg_search_module(libsodium
	REQUIRED
	libsodium
)

pkg_search_module(wolfssl
	REQUIRED
	wolfssl
)

add_executable(crypto_benchmark
	"main.c"
	"openssl.c"
	"openssl.h"
	"sodium.c"
	"sodium.h"
	"utils.c"
	"utils.h"
	"wolfcrypt.c"
	"wolfcrypt.h"
)

target_compile_definitions(crypto_benchmark PRIVATE "HAS_WOLFSSL_OPTIONS")

# The official Ubuntu Bionic package doesn't provide the header.
check_include_file(
	"wolfssl/options.h"
	HAS_WOLFSSL_OPTIONS
	CMAKE_REQUIRED_INCLUDES wolfssl_INCLUDE_DIRS
)

if(NOT HAS_WOLFSSL_OPTIONS)
	target_include_directories(crypto_benchmark PRIVATE "${CMAKE_SOURCE_DIR}/include")
endif()

target_include_directories(crypto_benchmark PRIVATE
	${libsodium_INCLUDE_DIRS}
	${wolfssl_INCLUDE_DIRS}
)

target_link_libraries(crypto_benchmark
	OpenSSL::Crypto
	${libsodium_LIBRARIES}
	${wolfssl_LIBRARIES}
)
