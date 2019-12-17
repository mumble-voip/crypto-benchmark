cmake_minimum_required(VERSION 3.0)

project(crypto_benchmark)

find_package(OpenSSL
	COMPONENTS Crypto
	REQUIRED
)

add_executable(crypto_benchmark
	"main.c"
	"openssl.c"
	"openssl.h"
	"utils.c"
	"utils.h"
)

target_link_libraries(crypto_benchmark OpenSSL::Crypto)
