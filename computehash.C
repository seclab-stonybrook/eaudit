#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define P1 ((1UL << 32) - 5)
#define P2 ((1UL << 32) - 17)

static inline uint32_t
load_u32_le(const uint8_t *src, size_t available) {
   uint32_t word = 0;
   if (available > 0) word |= (uint32_t)src[0];
   if (available > 1) word |= ((uint32_t)src[1]) << 8;
   if (available > 2) word |= ((uint32_t)src[2]) << 16;
   if (available > 3) word |= ((uint32_t)src[3]) << 24;
   return word;
}

// UMAC3: polynomial universal hash with one-time pad.
// Two 32-bit fingerprints (mod p1, mod p2) concatenated into a 64-bit MAC.
static uint64_t
compute_umac3_words(const uint8_t *in, size_t inlen, size_t word_count,
                    uint64_t poly_key, uint64_t pad_key) {
   if (word_count == 0) return pad_key;

   const uint64_t k11 = poly_key & 0xffffffffULL;
   const uint64_t k12 = poly_key >> 32;
   uint32_t rv1 = load_u32_le(in, inlen >= 4 ? 4 : inlen);
   uint32_t rv2 = rv1;

   if (rv1 >= P1) rv1 -= P1;
   if (rv2 >= P2) rv2 -= P2;

   for (size_t word = 1; word < word_count; ++word) {
      size_t byte_offset = word * 4;
      size_t remaining = inlen - byte_offset;
      uint32_t msg_word = load_u32_le(in + byte_offset, remaining >= 4 ? 4 : remaining);
      uint64_t x = (uint64_t)rv1 * k11 + msg_word;
      uint64_t y = (uint64_t)rv2 * k12 + msg_word;
      rv1 = x % P1;
      rv2 = y % P2;
   }

   return (pad_key ^ rv1) ^ (((uint64_t)rv2) << 32);
}

uint64_t compute_umac3_mac(const uint8_t *in, size_t inlen, const uint8_t *k) {
   uint64_t poly_key = 0;
   uint64_t pad_key = 0;
   memcpy(&poly_key, k, sizeof(poly_key));
   memcpy(&pad_key, k + sizeof(poly_key), sizeof(pad_key));

   size_t word_count = (inlen + 3) / 4;
   return compute_umac3_words(in, inlen, word_count, poly_key, pad_key);
}
