/*
 * xxHash64 implementation.
 * Derived from the xxHash project by Yann Collet:
 * https://github.com/Cyan4973/xxHash
 *
 * SPDX-FileCopyrightText: 2012-2023 Yann Collet
 * SPDX-FileCopyrightText: 2026 SombrAbsol
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef XXHASH
#define XXHASH

#include <stdint.h>
#include <string.h>

/*
 * Multiplicative constants for the xxHash-64 mixing scheme.
 */
#define XXH_P1 UINT64_C(0x9E3779B185EBCA87)
#define XXH_P2 UINT64_C(0xC2B2AE3D27D4EB4F)
#define XXH_P3 UINT64_C(0x165667B19E3779F9)
#define XXH_P4 UINT64_C(0x85EBCA77C2B2AE63)
#define XXH_P5 UINT64_C(0x27D4EB2F165667C5)

/*
 * Rotate left 64-bit.
 */
static inline uint64_t xxh_rotl64(uint64_t x, int r)
{
    return (x << r) | (x >> (64 - r));
}

/*
 * Read a u64 little-endian.
 */
static inline uint64_t xxh_r64(const void *p)
{
    uint64_t v;
    memcpy(&v, p, 8);
    return v;
}

/*
 * Read a u32 little-endian.
 */
static inline uint32_t xxh_r32(const void *p)
{
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}

/*
 * Accumulate an 8-byte block into a stripe-phase accumulator.
 */
static inline uint64_t xxh_round(uint64_t acc, uint64_t in)
{
    return xxh_rotl64(acc + in * XXH_P2, 31) * XXH_P1;
}

/*
 * Merge an accumulator into the final hash after the stripe phase.
 */
static inline uint64_t xxh_merge(uint64_t h, uint64_t v)
{
    return (h ^ xxh_round(0, v)) * XXH_P1 + XXH_P4;
}

/*
 * Final avalanche to eliminate bias in the output bits.
 */
static inline uint64_t xxh_avalanche(uint64_t h)
{
    h ^= h >> 33;
    h *= XXH_P2;
    h ^= h >> 29;
    h *= XXH_P3;
    h ^= h >> 32;
    return h;
}

/*
 * Compute the xxHash-64 digest of data with the given seed.
 */
static inline uint64_t xxh64(const void *data, size_t len, uint64_t seed)
{
    const uint8_t *p = (const uint8_t *)data;
    const uint8_t *end = p + len;
    uint64_t h;

    if (len >= 32) {

        // stripe phase, process 32-byte blocks with 4 accumulators
        uint64_t v1 = seed + XXH_P1 + XXH_P2;
        uint64_t v2 = seed + XXH_P2;
        uint64_t v3 = seed;
        uint64_t v4 = seed - XXH_P1;
        do {
            v1 = xxh_round(v1, xxh_r64(p));
            p += 8;
            v2 = xxh_round(v2, xxh_r64(p));
            p += 8;
            v3 = xxh_round(v3, xxh_r64(p));
            p += 8;
            v4 = xxh_round(v4, xxh_r64(p));
            p += 8;
        } while (p <= end - 32);
        h = xxh_rotl64(v1, 1) + xxh_rotl64(v2, 7) + xxh_rotl64(v3, 12)
            + xxh_rotl64(v4, 18);
        h = xxh_merge(h, v1);
        h = xxh_merge(h, v2);
        h = xxh_merge(h, v3);
        h = xxh_merge(h, v4);
    } else {
        h = seed + XXH_P5;
    }
    h += (uint64_t)len;

    // remaining bytes in blocks of 8, 4, then 1
    while (p + 8 <= end) {
        h ^= xxh_round(0, xxh_r64(p));
        h = xxh_rotl64(h, 27) * XXH_P1 + XXH_P4;
        p += 8;
    }
    if (p + 4 <= end) {
        h ^= (uint64_t)xxh_r32(p) * XXH_P1;
        h = xxh_rotl64(h, 23) * XXH_P2 + XXH_P3;
        p += 4;
    }
    while (p < end) {
        h ^= (uint64_t)*p * XXH_P5;
        h = xxh_rotl64(h, 11) * XXH_P1;
        p++;
    }

    return xxh_avalanche(h);
}

#endif /* XXHASH */
