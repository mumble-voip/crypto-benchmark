cmake_minimum_required(VERSION 3.0)

project(crypto_benchmark)

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

add_executable(crypto_benchmark
	"main.c"
	"openssl.c"
	"openssl.h"
	"sodium.c"
	"sodium.h"
	"utils.c"
	"utils.h"
)

target_include_directories(crypto_benchmark PRIVATE ${libsodium_INCLUDE_DIRS})

target_link_libraries(crypto_benchmark
	OpenSSL::Crypto
	${libsodium_LIBRARIES}
)
