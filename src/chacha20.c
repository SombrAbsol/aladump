/*
 * ChaCha20 variant specific to DeNA's Aladin asset system.
 * Based on the ChaCha20 stream cipher designed by Daniel J. Bernstein:
 * https://cr.yp.to/chacha.html
 *
 * SPDX-FileCopyrightText: 2026 SombrAbsol
 *
 * SPDX-License-Identifier: MIT
 */

#include "chacha20.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * Sigma constant used in state initialization.
 */
static const uint8_t SIGMA[16] = { 'A',
    '3',
    'A',
    'x',
    'w',
    't',
    'f',
    'W',
    'D',
    '<',
    'P',
    'b',
    'x',
    'M',
    'x',
    '$' };

/*
 * Turn table controlling number of double rounds.
 */
static const int TURN_TABLE[16]
    = { 6, 5, 6, 5, 5, 6, 5, 6, 6, 6, 5, 5, 5, 6, 6, 5 };

/*
 * Rotate left 32-bit value.
 */
#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

/*
 * Load little-endian u32.
 */
static inline uint32_t load32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16)
        | ((uint32_t)p[3] << 24);
}

/*
 * Apply ChaCha quarter-round.
 */
#define QR(x, a, b, c, d)                                                      \
    do {                                                                       \
        (x)[a] += (x)[b];                                                      \
        (x)[d] = ROTL32((x)[d] ^ (x)[a], 16);                                  \
        (x)[c] += (x)[d];                                                      \
        (x)[b] = ROTL32((x)[b] ^ (x)[c], 12);                                  \
        (x)[a] += (x)[b];                                                      \
        (x)[d] = ROTL32((x)[d] ^ (x)[a], 8);                                   \
        (x)[c] += (x)[d];                                                      \
        (x)[b] = ROTL32((x)[b] ^ (x)[c], 7);                                   \
    } while (0)

/*
 * Generate a ChaCha20 block into output from state.
 */
static void chacha20_block(const uint32_t *state, int turns, uint8_t *output)
{
    uint32_t x[16];
    memcpy(x, state, 64);

    for (int i = 0; i < turns; i++) {
        // column rounds
        QR(x, 0, 4, 8, 12);
        QR(x, 1, 5, 9, 13);
        QR(x, 2, 6, 10, 14);
        QR(x, 3, 7, 11, 15);

        // diagonal rounds
        QR(x, 0, 5, 10, 15);
        QR(x, 1, 6, 11, 12);
        QR(x, 2, 7, 8, 13);
        QR(x, 3, 4, 9, 14);
    }

    // final addition of the initial state
    for (int i = 0; i < 16; i++) {
        x[i] += state[i];
    }

    // serialise the 16 words into the output byte buffer
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    memcpy(output, x, 64);
#else
    for (int i = 0; i < 16; i++) {
        output[i * 4 + 0] = (uint8_t)(x[i]);
        output[i * 4 + 1] = (uint8_t)(x[i] >> 8);
        output[i * 4 + 2] = (uint8_t)(x[i] >> 16);
        output[i * 4 + 3] = (uint8_t)(x[i] >> 24);
    }
#endif
}

/*
 * Derive the double-round count from the initial state.
 */
static int compute_turns(const uint32_t *s)
{
    uint32_t step = ((s[9] + s[4]) ^ s[11]) + (s[15] ^ (s[14] + s[13]));

    /*
     * Extract a 4-bit index from three non-overlapping bit fields of step.
     * Bit 1   : (step >> 7)  & 2
     * Bit 0   : (step >> 2)  & 1 (XORed with bit 1 to add non-linearity)
     * Bits 3-2: (step >> 13) & 4 and (step >> 2) & 8
     * The resulting index (0-15) selects the double-round count from
     * TURN_TABLE. This derivation is specific to the Aladin variant.
     */
    int idx = (((step >> 7) & 2) ^ ((step >> 2) & 1)) | ((step >> 13) & 4)
        | ((step >> 2) & 8);
    return TURN_TABLE[idx];
}

/*
 * Initialize ChaCha20 context from IV and key.
 */
void chacha20_keysetup(
    chacha20_ctx_t *ctx, uint64_t content_hash, const uint8_t *key)
{
    // words 0–3: sigma constant
    ctx->state[0] = load32le(SIGMA + 0);
    ctx->state[1] = load32le(SIGMA + 4);
    ctx->state[2] = load32le(SIGMA + 8);
    ctx->state[3] = load32le(SIGMA + 12);

    // words 4-11: 256-bit key
    for (int i = 0; i < 8; i++) {
        ctx->state[4 + i] = load32le(key + i * 4);
    }

    // counter initialized to 0, will be incremented before the first block
    ctx->state[12] = 0;

    // words 13–14: IV, content_hash encoded as little-endian 64-bit
    ctx->state[13] = (uint32_t)(content_hash);
    ctx->state[14] = (uint32_t)(content_hash >> 32);

    // word 15: Aladin-specific magic marker 'chch'
    ctx->state[15] = 0x63686368u;

    ctx->turns = compute_turns(ctx->state);
}

/*
 * Encrypt/decrypt buffer using ChaCha20.
 */
void chacha20_crypt(chacha20_ctx_t *__restrict__ ctx,
    const uint8_t *src,
    uint8_t *dst,
    size_t len)
{
    uint8_t block[64] __attribute__((aligned(16)));

    // process full 64-byte blocks using word-sized XOR
    while (len >= 64) {

        // counter is incremented before block generation (non-standard)
        ctx->state[12]++;
        chacha20_block(ctx->state, ctx->turns, block);

        // XOR 64 bytes as 8 * uint64_t
        for (int i = 0; i < 8; i++) {
            uint64_t s_word, d_word, k_word;
            memcpy(&k_word, block + i * 8, 8);
            memcpy(&s_word, src + i * 8, 8);
            d_word = s_word ^ k_word;
            memcpy(dst + i * 8, &d_word, 8);
        }

        src += 64;
        dst += 64;
        len -= 64;
    }

    // tail path, handle the final partial block (0–63 bytes)
    if (len > 0) {
        ctx->state[12]++;
        chacha20_block(ctx->state, ctx->turns, block);

        for (size_t i = 0; i < len; i++) {
            dst[i] = src[i] ^ block[i];
        }
    }
}
