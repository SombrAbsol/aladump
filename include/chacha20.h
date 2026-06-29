/*
 * ChaCha20 variant specific to DeNA's Aladin asset system.
 * Based on the ChaCha20 stream cipher designed by Daniel J. Bernstein:
 * https://cr.yp.to/chacha.html
 *
 * SPDX-FileCopyrightText: 2026 SombrAbsol
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef CHACHA20
#define CHACHA20

#include <stddef.h>
#include <stdint.h>

/*
 * Full ChaCha20 cipher state, 16 32-bit words + double-round count.
 */
typedef struct {
    uint32_t state[16];
    int turns; // double-round count (5 or 6), constant per (key, IV) pair
} chacha20_ctx_t;

/*
 * Initialize ChaCha20 context from IV and key.
 */
void chacha20_keysetup(
    chacha20_ctx_t *ctx, uint64_t content_hash, const uint8_t *key);

/*
 * Encrypt/decrypt buffer.
 */
void chacha20_crypt(
    chacha20_ctx_t *ctx, const uint8_t *src, uint8_t *dst, size_t len);

#endif /* CHACHA20 */
