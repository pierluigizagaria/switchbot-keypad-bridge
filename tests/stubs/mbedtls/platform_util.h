#pragma once
#include <cstring>
inline void mbedtls_platform_zeroize(void *p, size_t n) { std::memset(p, 0, n); }
