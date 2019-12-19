/* wolfssl options.h
 * generated from configure options
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
 *
 */

#ifndef WOLFSSL_OPTIONS_H
#define WOLFSSL_OPTIONS_H


#ifdef __cplusplus
extern "C" {
#endif

#ifndef WOLFSSL_OPTIONS_IGNORE_SYS
#undef  _FORTIFY_SOURCE
#define _FORTIFY_SOURCE 2
#endif

#undef  WOLFSSL_PUBLIC_MP
#define WOLFSSL_PUBLIC_MP

#undef  HAVE_FFDHE_2048
#define HAVE_FFDHE_2048

#undef  WOLFSSL_SEP
#define WOLFSSL_SEP

#undef  KEEP_PEER_CERT
#define KEEP_PEER_CERT

#undef  WOLFSSL_VERIFY_CB_ALL_CERTS
#define WOLFSSL_VERIFY_CB_ALL_CERTS

#undef  OPENSSL_EXTRA
#define OPENSSL_EXTRA

#undef  WOLFSSL_ALWAYS_VERIFY_CB
#define WOLFSSL_ALWAYS_VERIFY_CB

#undef  OPENSSL_ALL
#define OPENSSL_ALL

#undef  WOLFSSL_TLS13
#define WOLFSSL_TLS13

#undef  HAVE_TLS_EXTENSIONS
#define HAVE_TLS_EXTENSIONS

#undef  HAVE_SUPPORTED_CURVES
#define HAVE_SUPPORTED_CURVES

#undef  WOLFSSL_DTLS
#define WOLFSSL_DTLS

#ifndef WOLFSSL_OPTIONS_IGNORE_SYS
#undef  _POSIX_THREADS
#define _POSIX_THREADS
#endif

#undef  HAVE_THREAD_LS
#define HAVE_THREAD_LS

#undef  HAVE_AES_DECRYPT
#define HAVE_AES_DECRYPT

#undef  HAVE_AES_ECB
#define HAVE_AES_ECB

#undef  WOLFSSL_ALT_NAMES
#define WOLFSSL_ALT_NAMES

#undef  WOLFSSL_DER_LOAD
#define WOLFSSL_DER_LOAD

#undef  KEEP_OUR_CERT
#define KEEP_OUR_CERT

#undef  KEEP_PEER_CERT
#define KEEP_PEER_CERT

#undef  HAVE_CRL_IO
#define HAVE_CRL_IO

#undef  HAVE_IO_TIMEOUT
#define HAVE_IO_TIMEOUT

#undef  HAVE_FFDHE_2048
#define HAVE_FFDHE_2048

#undef  HAVE_FFDHE_3072
#define HAVE_FFDHE_3072

#undef  HAVE_FFDHE_4096
#define HAVE_FFDHE_4096

#undef  HAVE_FFDHE_6144
#define HAVE_FFDHE_6144

#undef  HAVE_FFDHE_8192
#define HAVE_FFDHE_8192

#undef  TFM_TIMING_RESISTANT
#define TFM_TIMING_RESISTANT

#undef  ECC_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT

#undef  WC_RSA_BLINDING
#define WC_RSA_BLINDING

#undef  FORTRESS
#define FORTRESS

#undef  WOLFSSL_ALWAYS_VERIFY_CB
#define WOLFSSL_ALWAYS_VERIFY_CB

#undef  WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_COUNTER

#undef  WOLFSSL_AES_DIRECT
#define WOLFSSL_AES_DIRECT

#undef  WOLFSSL_DER_LOAD
#define WOLFSSL_DER_LOAD

#undef  WOLFSSL_KEY_GEN
#define WOLFSSL_KEY_GEN

#undef  PERSIST_SESSION_CACHE
#define PERSIST_SESSION_CACHE

#undef  PERSIST_CERT_CACHE
#define PERSIST_CERT_CACHE

#undef  ATOMIC_USER
#define ATOMIC_USER

#undef  HAVE_PK_CALLBACKS
#define HAVE_PK_CALLBACKS

#undef  HAVE_AESGCM
#define HAVE_AESGCM

#undef  HAVE_AESCCM
#define HAVE_AESCCM

#undef  WOLFSSL_AES_CFB
#define WOLFSSL_AES_CFB

#undef  HAVE_CAMELLIA
#define HAVE_CAMELLIA

#undef  HAVE_NULL_CIPHER
#define HAVE_NULL_CIPHER

#undef  WOLFSSL_RIPEMD
#define WOLFSSL_RIPEMD

#undef  WOLFSSL_SHA512
#define WOLFSSL_SHA512

#undef  WOLFSSL_SHA384
#define WOLFSSL_SHA384

#undef  SESSION_CERTS
#define SESSION_CERTS

#undef  WOLFSSL_KEY_GEN
#define WOLFSSL_KEY_GEN

#undef  WOLFSSL_CERT_GEN
#define WOLFSSL_CERT_GEN

#undef  WOLFSSL_CERT_REQ
#define WOLFSSL_CERT_REQ

#undef  WOLFSSL_CERT_EXT
#define WOLFSSL_CERT_EXT

#undef  HAVE_HKDF
#define HAVE_HKDF

#undef  HAVE_X963_KDF
#define HAVE_X963_KDF

#undef  HAVE_ECC
#define HAVE_ECC

#undef  TFM_ECC256
#define TFM_ECC256

#undef  ECC_SHAMIR
#define ECC_SHAMIR

#undef  WOLFSSL_CUSTOM_CURVES
#define WOLFSSL_CUSTOM_CURVES

#undef  HAVE_ECC_SECPR2
#define HAVE_ECC_SECPR2

#undef  HAVE_ECC_SECPR3
#define HAVE_ECC_SECPR3

#undef  HAVE_ECC_BRAINPOOL
#define HAVE_ECC_BRAINPOOL

#undef  HAVE_ECC_KOBLITZ
#define HAVE_ECC_KOBLITZ

#undef  HAVE_COMP_KEY
#define HAVE_COMP_KEY

#undef  HAVE_CURVE25519
#define HAVE_CURVE25519

#undef  HAVE_ED25519
#define HAVE_ED25519

#undef  FP_ECC
#define FP_ECC

#undef  HAVE_ECC_ENCRYPT
#define HAVE_ECC_ENCRYPT

#undef  WC_RSA_PSS
#define WC_RSA_PSS

#undef  WOLFSSL_BASE64_ENCODE
#define WOLFSSL_BASE64_ENCODE

#undef  HAVE_IDEA
#define HAVE_IDEA

#undef  WOLFSSL_CMAC
#define WOLFSSL_CMAC

#undef  WOLFSSL_AES_DIRECT
#define WOLFSSL_AES_DIRECT

#undef  WOLFSSL_AES_XTS
#define WOLFSSL_AES_XTS

#undef  WOLFSSL_AES_DIRECT
#define WOLFSSL_AES_DIRECT

#undef  HAVE_WEBSERVER
#define HAVE_WEBSERVER

#undef  HAVE_HC128
#define HAVE_HC128

#undef  HAVE_RABBIT
#define HAVE_RABBIT

#undef  WOLFSSL_DES_ECB
#define WOLFSSL_DES_ECB

#undef  WOLFSSL_SHA224
#define WOLFSSL_SHA224

#undef  WOLFSSL_SHA3
#define WOLFSSL_SHA3

#undef  HAVE_POLY1305
#define HAVE_POLY1305

#undef  HAVE_ONE_TIME_AUTH
#define HAVE_ONE_TIME_AUTH

#undef  HAVE_CHACHA
#define HAVE_CHACHA

#undef  HAVE_HASHDRBG
#define HAVE_HASHDRBG

#undef  HAVE_OCSP
#define HAVE_OCSP

#undef  HAVE_OPENSSL_CMD
#define HAVE_OPENSSL_CMD

#undef  HAVE_TLS_EXTENSIONS
#define HAVE_TLS_EXTENSIONS

#undef  HAVE_CERTIFICATE_STATUS_REQUEST
#define HAVE_CERTIFICATE_STATUS_REQUEST

#undef  HAVE_TLS_EXTENSIONS
#define HAVE_TLS_EXTENSIONS

#undef  HAVE_CERTIFICATE_STATUS_REQUEST_V2
#define HAVE_CERTIFICATE_STATUS_REQUEST_V2

#undef  HAVE_CRL
#define HAVE_CRL

#undef  HAVE_TLS_EXTENSIONS
#define HAVE_TLS_EXTENSIONS

#undef  HAVE_SNI
#define HAVE_SNI

#undef  HAVE_TLS_EXTENSIONS
#define HAVE_TLS_EXTENSIONS

#undef  HAVE_ALPN
#define HAVE_ALPN

#undef  HAVE_TLS_EXTENSIONS
#define HAVE_TLS_EXTENSIONS

#undef  HAVE_MAX_FRAGMENT
#define HAVE_MAX_FRAGMENT

#undef  HAVE_TLS_EXTENSIONS
#define HAVE_TLS_EXTENSIONS

#undef  HAVE_TRUNCATED_HMAC
#define HAVE_TRUNCATED_HMAC

#undef  HAVE_TLS_EXTENSIONS
#define HAVE_TLS_EXTENSIONS

#undef  HAVE_SUPPORTED_CURVES
#define HAVE_SUPPORTED_CURVES

#undef  HAVE_TLS_EXTENSIONS
#define HAVE_TLS_EXTENSIONS

#undef  HAVE_SESSION_TICKET
#define HAVE_SESSION_TICKET

#undef  HAVE_EXTENDED_MASTER
#define HAVE_EXTENDED_MASTER

#undef  HAVE_TLS_EXTENSIONS
#define HAVE_TLS_EXTENSIONS

#undef  HAVE_SNI
#define HAVE_SNI

#undef  HAVE_MAX_FRAGMENT
#define HAVE_MAX_FRAGMENT

#undef  HAVE_TRUNCATED_HMAC
#define HAVE_TRUNCATED_HMAC

#undef  HAVE_ALPN
#define HAVE_ALPN

#undef  HAVE_SUPPORTED_CURVES
#define HAVE_SUPPORTED_CURVES

#undef  WOLFCRYPT_HAVE_SRP
#define WOLFCRYPT_HAVE_SRP

#undef  ASN_BER_TO_DER
#define ASN_BER_TO_DER

#undef  WOLFSSL_HAVE_CERT_SERVICE
#define WOLFSSL_HAVE_CERT_SERVICE

#undef  WOLFSSL_JNI
#define WOLFSSL_JNI

#undef  HAVE_LIGHTY
#define HAVE_LIGHTY

#undef  HAVE_WOLFSSL_SSL_H
#define HAVE_WOLFSSL_SSL_H 1

#undef  WOLFSSL_NGINX
#define WOLFSSL_NGINX

#undef  WOLFSSL_HAPROXY
#define WOLFSSL_HAPROXY

#undef  WOLFSSL_ALWAYS_VERIFY_CB
#define WOLFSSL_ALWAYS_VERIFY_CB

#undef  WOLFSSL_ALWAYS_KEEP_SNI
#define WOLFSSL_ALWAYS_KEEP_SNI

#undef  KEEP_OUR_CERT
#define KEEP_OUR_CERT

#undef  KEEP_PEER_CERT
#define KEEP_PEER_CERT

#undef  HAVE_EXT_CACHE
#define HAVE_EXT_CACHE

#undef  HAVE_EX_DATA
#define HAVE_EX_DATA

#undef  HAVE_STUNNEL
#define HAVE_STUNNEL

#undef  WOLFSSL_ALWAYS_VERIFY_CB
#define WOLFSSL_ALWAYS_VERIFY_CB

#undef  WOLFSSL_ALWAYS_KEEP_SNI
#define WOLFSSL_ALWAYS_KEEP_SNI

#undef  HAVE_EX_DATA
#define HAVE_EX_DATA

#undef  WOLFSSL_ENCRYPTED_KEYS
#define WOLFSSL_ENCRYPTED_KEYS

#undef  HAVE_SCRYPT
#define HAVE_SCRYPT

#undef  WC_NO_ASYNC_THREADING
#define WC_NO_ASYNC_THREADING

#undef  HAVE_AES_KEYWRAP
#define HAVE_AES_KEYWRAP

#undef  WOLFSSL_AES_DIRECT
#define WOLFSSL_AES_DIRECT

#undef  WOLFSSL_HAVE_WOLFSCEP
#define WOLFSSL_HAVE_WOLFSCEP

#undef  HAVE_PKCS7
#define HAVE_PKCS7

#undef  HAVE___UINT128_T
#define HAVE___UINT128_T


#ifdef __cplusplus
}
#endif


#endif /* WOLFSSL_OPTIONS_H */

