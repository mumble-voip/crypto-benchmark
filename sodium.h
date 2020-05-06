#pragma once

#include "utils.h"

#undef IV_SIZE
#define IV_SIZE 32

const Crypto *sodium_get();
