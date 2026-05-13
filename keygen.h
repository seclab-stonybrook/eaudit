#ifndef KEYGEN_H
#define KEYGEN_H

#include <stdint.h>
#include "eauditk.h"

#ifdef __cplusplus
extern "C" {
#endif

struct signing_key_batch {
    uint64_t keys[SIGNING_KEY_BATCH_SIZE][2] __attribute__((aligned(16)));
};

struct signing_key_seed {
    uint64_t k[2];
};

void generate_signing_keys(const unsigned char *batch_seed, unsigned char *signing_key_batch_out);
int generate_signing_keys_and_load(const unsigned char *batch_seed, int map_fd);
int load_signing_key_seed(const unsigned char *batch_seed, int map_fd);
#ifdef __cplusplus
}
#endif
#endif
