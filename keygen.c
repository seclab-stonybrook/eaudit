/*
 * keygen.c — AES-NI accelerated signing-key generation for eaudit
 *
 * This module implements the forward-secure key derivation scheme described
 * in QuickLog2 (see §4–5 of the QuickLog paper for the security proof).
 * A batch of SIGNING_KEY_BATCH_SIZE (131072) per-record signing keys is
 * expanded from a single 128-bit seed using an Even-Mansour construction
 * built on AES with a fixed all-zero key.
 *
 * Key schedule (Even-Mansour with domain-separating tweaks):
 *
 *   K_i   = AES_0(S_i xor 0x01) xor S_i      (signing key for record i)
 *   S_i+1 = AES_0(S_i xor 0x00) xor S_i      (chain state for next key)
 *
 * where AES_0 denotes AES-128 under the fixed all-zero key.  The XOR tweaks
 * (0x01 vs 0x00) provide domain separation so that K_i and S_i+1 are
 * cryptographically independent outputs of the same state.
 *
 * Forward secrecy: knowing K_i reveals nothing about any K_j for j < i,
 * provided that S_j (j <= i) and all prior keys are securely erased after
 * use.  The batch buffer is wiped with explicit_bzero after each BPF map
 * update.
 *
 * Performance: the inner loop interleaves the two independent AES
 * encryptions per iteration so the CPU can execute them at throughput
 * (~1 cycle/round) rather than latency (~4 cycles/round).  Non-temporal
 * stores avoid polluting the cache with the 2 MiB output buffer.
 *
 * Usage:
 *   - eauditd.py calls generate_signing_keys_and_load() from a dedicated
 *     refill thread whenever the BPF kernel probe signals that the current
 *     half of the key ring is nearly exhausted.
 *   - eParser (the verifier) calls generate_signing_keys() to regenerate
 *     the same key sequence from the recorded seed for MAC verification.
 */

#include "keygen.h"
#include <errno.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <wmmintrin.h> /* AES-NI intrinsics: _mm_aesenc_si128, etc. */

/* Locked key batch buffer.  The constructor maps it with MAP_LOCKED and
 * also calls mlock() as a fallback for kernels that may defer population.
 * It is allocated once at library load time. */
static struct signing_key_batch *generated_key_batch = NULL;

/* Precomputed AES-128 round keys for the fixed all-zero key.  Expanded
 * once at library load time by init_fixed_aes_key(). */
static __m128i fixed_zero_key_schedule[11];

/*
 * init_key_storage — allocate the locked key batch buffer.
 *
 * Called automatically at library load time (__attribute__((constructor))).
 * The buffer is MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED so that:
 *   1. It is never backed by a file (no disk leakage).
 *   2. It is pinned in physical memory (no swap leakage).
 */
__attribute__((constructor)) static void init_key_storage() {
  generated_key_batch = (struct signing_key_batch *)mmap(
      NULL, sizeof(struct signing_key_batch), PROT_READ | PROT_WRITE,
      MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
  if (generated_key_batch == MAP_FAILED) {
    perror("mmap for key storage failed");
    abort();
  }
  mlock(generated_key_batch, sizeof(struct signing_key_batch));
}

/*
 * AES_128_ASSIST — Intel-style helper for AES-128 key expansion.
 *
 * Adapted from Intel's AES-NI reference implementation in:
 * https://www.intel.com/content/dam/develop/external/us/en/documents/aes-wp-2012-09-22-v01-165683.pdf
 *
 * This mirrors the reference structure in Intel's AES-NI whitepaper:
 *   1. shift the current key material left by 4 bytes three times,
 *   2. xor each shifted version back into the working register,
 *   3. xor the shuffled AESKEYGENASSIST output into the result.
 */
static inline __m128i AES_128_ASSIST(__m128i temp1, __m128i temp2) {
  __m128i temp3;

  temp2 = _mm_shuffle_epi32(temp2, 0xff);
  temp3 = _mm_slli_si128(temp1, 0x4);
  temp1 = _mm_xor_si128(temp1, temp3);
  temp3 = _mm_slli_si128(temp3, 0x4);
  temp1 = _mm_xor_si128(temp1, temp3);
  temp3 = _mm_slli_si128(temp3, 0x4);
  temp1 = _mm_xor_si128(temp1, temp3);
  temp1 = _mm_xor_si128(temp1, temp2);

  return temp1;
}

/*
 * expand_aes128_key — AES-128 key expansion using AES-NI.
 *
 * Expands a 128-bit cipher key into the 11 round keys (key_schedule[0..10])
 * required by AES-128.  This is adapted from Intel's documented AES-NI
 * example in (Figure 2) of the whitepaper.
 */
static void expand_aes128_key(const unsigned char *key, __m128i *key_schedule) {
  __m128i temp1, temp2;

  temp1 = _mm_loadu_si128((const __m128i *)key);
  key_schedule[0] = temp1;

  temp2 = _mm_aeskeygenassist_si128(temp1, 0x01);
  temp1 = AES_128_ASSIST(temp1, temp2);
  key_schedule[1] = temp1;

  temp2 = _mm_aeskeygenassist_si128(temp1, 0x02);
  temp1 = AES_128_ASSIST(temp1, temp2);
  key_schedule[2] = temp1;

  temp2 = _mm_aeskeygenassist_si128(temp1, 0x04);
  temp1 = AES_128_ASSIST(temp1, temp2);
  key_schedule[3] = temp1;

  temp2 = _mm_aeskeygenassist_si128(temp1, 0x08);
  temp1 = AES_128_ASSIST(temp1, temp2);
  key_schedule[4] = temp1;

  temp2 = _mm_aeskeygenassist_si128(temp1, 0x10);
  temp1 = AES_128_ASSIST(temp1, temp2);
  key_schedule[5] = temp1;

  temp2 = _mm_aeskeygenassist_si128(temp1, 0x20);
  temp1 = AES_128_ASSIST(temp1, temp2);
  key_schedule[6] = temp1;

  temp2 = _mm_aeskeygenassist_si128(temp1, 0x40);
  temp1 = AES_128_ASSIST(temp1, temp2);
  key_schedule[7] = temp1;

  temp2 = _mm_aeskeygenassist_si128(temp1, 0x80);
  temp1 = AES_128_ASSIST(temp1, temp2);
  key_schedule[8] = temp1;

  temp2 = _mm_aeskeygenassist_si128(temp1, 0x1b);
  temp1 = AES_128_ASSIST(temp1, temp2);
  key_schedule[9] = temp1;

  temp2 = _mm_aeskeygenassist_si128(temp1, 0x36);
  temp1 = AES_128_ASSIST(temp1, temp2);
  key_schedule[10] = temp1;
}

/*
 * init_fixed_aes_key — precompute round keys for the all-zero AES key.
 * The fixed key F = 0 makes AES behave as a public random permutation over
 * 128-bit blocks, which is the role it plays in the Even-Mansour construction.
 */
__attribute__((constructor)) static void init_fixed_aes_key() {
  static const unsigned char zero_key[SIGNING_KEY_SIZE] = {0};
  expand_aes128_key(zero_key, fixed_zero_key_schedule);
}

/*
 * generate_signing_key_batch — expand a seed into SIGNING_KEY_BATCH_SIZE keys.
 *
 * This is the performance-critical inner loop.  Two AES-128 encryptions are
 * needed per iteration: one derives the signing key K_i (tweak = 0x01) and
 * one advances the chain state S_i+1 (tweak = 0x00).  Because both operate
 * on the same input state, their AES rounds are fully independent and can
 * be interleaved instruction-by-instruction.
 *
 * The output uses non-temporal (streaming) stores (_mm_stream_si128) because
 * the batch buffer is 2 MiB — writing it through the cache would evict
 * useful working data.  A trailing _mm_sfence ensures all stores are
 * globally visible before the caller reads the buffer or passes it to the
 * kernel via bpf_map_update_elem.
 *
 * dest->keys must be 16-byte aligned (guaranteed by the struct definition
 * and by calloc/mmap alignment on x86-64).
 */
  /*
  * Intel Intrinsics Guide:
  * https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.htm
  *
  * __m128i _mm_aesenc_si128(__m128i a, __m128i RoundKey)  
  *
  * Performs one round of an AES encryption flow on data (state) in a
  * using the round key in RoundKey, and stores the result in dst.
  *
  * Operation:
  *   a[127:0] := ShiftRows(a[127:0])
  *   a[127:0] := SubBytes(a[127:0])
  *   a[127:0] := MixColumns(a[127:0])
  *   dst[127:0] := a[127:0] XOR RoundKey[127:0]
  */
 
static inline void generate_signing_key_batch(const unsigned char *batch_seed,
                                              struct signing_key_batch *dest) {
  __m128i state = _mm_loadu_si128((const __m128i *)batch_seed);
  const __m128i one = _mm_set_epi32(0, 0, 0, 1);
  const __m128i *ks = fixed_zero_key_schedule;

  for (int i = 0; i < SIGNING_KEY_BATCH_SIZE; i++) {
    /* k = AES_0(state xor 0x01)  — will become signing key K_i
     * s = AES_0(state xor 0x00)  — will become next chain state S_i+1
     * Rounds are interleaved (k, s, k, s, ...) */
    __m128i k = _mm_xor_si128(_mm_xor_si128(state, one), ks[0]);
    __m128i s = _mm_xor_si128(state, ks[0]);

    k = _mm_aesenc_si128(k, ks[1]);
    s = _mm_aesenc_si128(s, ks[1]);
    k = _mm_aesenc_si128(k, ks[2]);
    s = _mm_aesenc_si128(s, ks[2]);
    k = _mm_aesenc_si128(k, ks[3]);
    s = _mm_aesenc_si128(s, ks[3]);
    k = _mm_aesenc_si128(k, ks[4]);
    s = _mm_aesenc_si128(s, ks[4]);
    k = _mm_aesenc_si128(k, ks[5]);
    s = _mm_aesenc_si128(s, ks[5]);
    k = _mm_aesenc_si128(k, ks[6]);
    s = _mm_aesenc_si128(s, ks[6]);
    k = _mm_aesenc_si128(k, ks[7]);
    s = _mm_aesenc_si128(s, ks[7]);
    k = _mm_aesenc_si128(k, ks[8]);
    s = _mm_aesenc_si128(s, ks[8]);
    k = _mm_aesenc_si128(k, ks[9]);
    s = _mm_aesenc_si128(s, ks[9]);
    k = _mm_aesenclast_si128(k, ks[10]);
    s = _mm_aesenclast_si128(s, ks[10]);

    /* Even-Mansour whitening: XOR the AES output with the pre-permutation
     * state.  K_i is written to the output; S_i+1 becomes the loop carry. */
    _mm_stream_si128((__m128i *)&dest->keys[i], _mm_xor_si128(k, state));
    state = _mm_xor_si128(s, state);
  }
  _mm_sfence();
}

/*
 * generate_signing_keys — public entry point for the verifier (eParser).
 *
 * Expands batch_seed into a full batch of signing keys written to
 * signing_key_batch_out.  The caller is responsible for allocating a buffer
 * of at least sizeof(struct signing_key_batch) bytes, 16-byte aligned.
 */
void generate_signing_keys(const unsigned char *batch_seed,
                           unsigned char *signing_key_batch_out) {
  generate_signing_key_batch(batch_seed,
                             (struct signing_key_batch *)signing_key_batch_out);
}

/* init_bpf_attr — fill a bpf_attr for a single-element map update.
 *
 * All keygen BPF maps are single-element (key = 0) per-CPU arrays.
 * This helper zeroes the attr struct and sets the common fields. */
static void init_bpf_attr(union bpf_attr *attr, int map_fd, void *value) {
  static __u32 zero = 0;
  memset(attr, 0, sizeof(*attr));
  attr->map_fd = (__u32)map_fd;
  attr->key = (__u64)(unsigned long)&zero;
  attr->value = (__u64)(unsigned long)value;
  attr->flags = BPF_ANY;
}

/*
 * generate_signing_keys_and_load — expand a batch and publish it to a BPF map.
 *
 * Called by the daemon's key-refill thread (eauditd.py) to fill one half
 * of the kernel-side signing key ring.  The sequence is:
 *   1. Expand the seed into the locked batch buffer.
 *   2. Copy the batch into the BPF per-CPU array via bpf_map_update_elem.
 *   3. Wipe the userspace buffer with explicit_bzero (forward secrecy).
 *
 * Returns 0 on success, -errno on failure.
 */
__attribute__((visibility("default"))) int
generate_signing_keys_and_load(const unsigned char *batch_seed, int map_fd) {
  generate_signing_key_batch(batch_seed, generated_key_batch);

  union bpf_attr attr;
  init_bpf_attr(&attr, map_fd, generated_key_batch);

  int ret = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
  explicit_bzero(generated_key_batch, sizeof(struct signing_key_batch));

  if (ret < 0) {
    perror("bpf_map_update_elem failed");
    return -errno;
  }
  return ret;
}

/*
 * load_signing_key_seed — store a batch seed in a BPF map for the verifier.
 *
 * The seed is written to a single-element BPF map so that:
 *   - The kernel probe can embed it into the record stream at the sync point,
 *     allowing the verifier to regenerate the same key sequence.
 *   - The seed is wiped from userspace immediately after the map update.
 *
 * Returns 0 on success, -errno on failure.
 */
__attribute__((visibility("default"))) int
load_signing_key_seed(const unsigned char *batch_seed, int map_fd) {
  struct signing_key_seed seed = {0};
  memcpy(&seed.k, batch_seed, SIGNING_KEY_SIZE);

  union bpf_attr attr;
  init_bpf_attr(&attr, map_fd, &seed);

  int ret = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
  explicit_bzero(&seed, sizeof(seed));

  if (ret < 0) {
    perror("Failed to update signing key seed");
    return -errno;
  }
  return 0;
}
