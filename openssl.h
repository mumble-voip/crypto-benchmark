#pragma once

#include <stdbool.h>
#include <stddef.h>

typedef struct evp_cipher_st EVP_CIPHER;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;

bool openssl_main(const size_t message_size, const size_t iterations);

int openssl_process(EVP_CIPHER_CTX *ctx, const bool enc, const unsigned char *iv, const int tag_size, unsigned char *tag, unsigned char *dst, const int src_size, const unsigned char *src);

double openssl_aead(const EVP_CIPHER *cipher, const size_t iterations, unsigned char *dst, const int size, const unsigned char *src);
