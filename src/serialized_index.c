/*
 * FlatBuffers serialized index parser implementation.
 *
 * SPDX-FileCopyrightText: 2026 SombrAbsol
 *
 * SPDX-License-Identifier: MIT
 */

#include "serialized_index.h"

#include "flatbuffers.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/*
 * vtable slot indices for the three vector fields in the FlatBuffers schema.
 */
#define SI_SLOT_BLOBS  4
#define SI_SLOT_HASHES 6
#define SI_SLOT_VALUES 8

/*
 * Byte stride between consecutive blob entries in the blobs vector.
 */
#define BLOB_STRIDE 48

/*
 * Read a little-endian u64 from a blob entry.
 */
static inline uint64_t blob_u64(blob_ref_t b, int off)
{
    uint64_t v;
    __builtin_memcpy(&v, b + off, 8);
    return v;
}

/*
 * Get the content hash.
 */
uint64_t blob_content_hash(blob_ref_t b)
{
    return blob_u64(b, 0);
}

/*
 * Get the content size.
 */
int64_t blob_content_size(blob_ref_t b)
{
    return (int64_t)blob_u64(b, 8);
}

/*
 * Get the blob hash.
 */
uint64_t blob_blob_hash(blob_ref_t b)
{
    return blob_u64(b, 16);
}

/*
 * Get the blob size.
 */
int64_t blob_blob_size(blob_ref_t b)
{
    return (int64_t)blob_u64(b, 24);
}

/*
 * Get the encryption key id.
 */
uint64_t blob_crypt_key_id(blob_ref_t b)
{
    return blob_u64(b, 32);
}

/*
 * Check the blob's encryption flag.
 */
bool blob_is_crypted(blob_ref_t b)
{
    return b[40] != 0;
}

/*
 * Initialize the serialized index parser.
 */
bool si_init(serialized_index_t *idx, const uint8_t *buf, size_t len)
{
    if (len < 8) {
        fprintf(stderr, "si_init: buffer too small\n");
        return false;
    }

    idx->buf = buf;
    idx->table_pos = fb_root(buf);

    // retrieve vtable offsets for each required field
    idx->blobs_off = fb_field(buf, idx->table_pos, SI_SLOT_BLOBS);
    idx->hashes_off = fb_field(buf, idx->table_pos, SI_SLOT_HASHES);
    idx->values_off = fb_field(buf, idx->table_pos, SI_SLOT_VALUES);

    // entry count is read from the address-values vector
    idx->count = (idx->values_off != 0)
        ? fb_vec_len(buf, idx->table_pos, idx->values_off)
        : 0;
    return true;
}

/*
 * Get the entry count.
 */
uint32_t si_count(const serialized_index_t *idx)
{
    return idx->count;
}

/*
 * Get the blob reference.
 */
blob_ref_t si_blob(const serialized_index_t *idx, uint32_t i)
{
    if (idx->blobs_off == 0 || i >= idx->count) {
        return NULL;
    }
    uint32_t start = fb_vec_data(idx->buf, idx->table_pos, idx->blobs_off);
    return idx->buf + start + (uint32_t)i * BLOB_STRIDE;
}

/*
 * Get the address hash.
 */
uint64_t si_address_hash(const serialized_index_t *idx, uint32_t i)
{
    if (idx->hashes_off == 0 || i >= idx->count) {
        return 0;
    }
    uint32_t start = fb_vec_data(idx->buf, idx->table_pos, idx->hashes_off);
    return fb_u64(idx->buf, start + (uint32_t)i * 8);
}

/*
 * Get the address string.
 */
const char *si_address_value(const serialized_index_t *idx, uint32_t i)
{
    if (idx->values_off == 0 || i >= idx->count) {
        return NULL;
    }
    uint32_t start = fb_vec_data(idx->buf, idx->table_pos, idx->values_off);

    // each element of the string vector is a 4-byte uoffset
    return fb_string(idx->buf, start + (uint32_t)i * 4);
}
