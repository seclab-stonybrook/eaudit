#ifndef COMPUTEHASH_H
#define COMPUTEHASH_H
#include <stdint.h>
#include <stddef.h>
uint64_t compute_umac3_mac(const uint8_t *in, size_t inlen, const uint8_t *k);
#endif
