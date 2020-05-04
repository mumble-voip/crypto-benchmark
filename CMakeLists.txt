cmake_minimum_required(VERSION 3.1)

project(crypto_benchmark)

option(hydrogen "Build libhydrogen benchmark" ON)
option(nss "Build NSS benchmark" ON)
option(openssl "Build OpenSSL benchmark" ON)
option(sodium "Build libsodium benchmark" ON)
option(wolfcrypt "Build wolfCrypt benchmark" ON)

if(nss OR sodium OR wolfcrypt)
	find_package(PkgConfig
		REQUIRED
	)
endif()

if(wolfcrypt)
	include(CheckIncludeFile)
endif()

add_executable(crypto_benchmark
	"main.c"
	"utils.c"
	"utils.h"
)

if(hydrogen)
	add_subdirectory(libhydrogen)

	target_compile_definitions(crypto_benchmark
		PRIVATE
			"BENCHMARK_HYDROGEN"
	)

	target_sources(crypto_benchmark
		PRIVATE
			"hydrogen.c"
			"hydrogen.h"
	)

	target_link_libraries(crypto_benchmark
		PRIVATE
			hydrogen::hydrogen
	)
endif()

if(nss)
	pkg_search_module(nss
		REQUIRED
		nss
	)

	target_compile_definitions(crypto_benchmark
		PRIVATE
			"BENCHMARK_NSS"
	)

	target_include_directories(crypto_benchmark
		PRIVATE
			${nss_INCLUDE_DIRS}
	)

	target_sources(crypto_benchmark
		PRIVATE
			"nss.c"
			"nss.h"
	)

	target_link_libraries(crypto_benchmark
		PRIVATE
			${nss_LIBRARIES}
	)
endif()

if(openssl)
	find_package(OpenSSL
		COMPONENTS Crypto
		REQUIRED
	)

	target_compile_definitions(crypto_benchmark
		PRIVATE
			"BENCHMARK_OPENSSL"
	)

	target_sources(crypto_benchmark
		PRIVATE
			"openssl.c"
			"openssl.h"
	)

	target_link_libraries(crypto_benchmark
		PRIVATE
			OpenSSL::Crypto
	)
endif()

if(sodium)
	pkg_search_module(libsodium
		REQUIRED
		libsodium
	)

	target_compile_definitions(crypto_benchmark
		PRIVATE
			"BENCHMARK_SODIUM"
	)

	target_include_directories(crypto_benchmark
		PRIVATE
			${libsodium_INCLUDE_DIRS}
	)

	target_sources(crypto_benchmark
		PRIVATE
			"sodium.c"
			"sodium.h"
	)

	target_link_libraries(crypto_benchmark
		PRIVATE
			${libsodium_LIBRARIES}
	)
endif()

if(wolfcrypt)
	pkg_search_module(wolfssl
		REQUIRED
		wolfssl
	)

	# The official Ubuntu Bionic package doesn't provide the header.
	check_include_file(
		"wolfssl/options.h"
		HAS_WOLFSSL_OPTIONS
		CMAKE_REQUIRED_INCLUDES wolfssl_INCLUDE_DIRS
	)

	target_compile_definitions(crypto_benchmark
		PRIVATE
			"BENCHMARK_WOLFCRYPT"
			"HAS_WOLFSSL_OPTIONS"
	)

	if(NOT HAS_WOLFSSL_OPTIONS)
		target_include_directories(crypto_benchmark
			PRIVATE
				"${CMAKE_SOURCE_DIR}/include"
		)
	endif()

	target_include_directories(crypto_benchmark
		PRIVATE
			${wolfssl_INCLUDE_DIRS}
	)

	target_sources(crypto_benchmark
		PRIVATE
			"wolfcrypt.c"
			"wolfcrypt.h"
	)

	target_link_libraries(crypto_benchmark
		PRIVATE
			${wolfssl_LIBRARIES}
	)
endif()
