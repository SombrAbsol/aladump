/*
 * FlatBuffers serialized index parser implementation.
 *
 * SPDX-FileCopyrightText: 2026 SombrAbsol
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef SERIALIZED_INDEX
#define SERIALIZED_INDEX

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/*
 * Memory layout (little-endian):
 *   [0 .. 7]  content_hash   uint64   xxh64 of the decrypted content
 *   [8 ..15]  content_size   int64    size of the decrypted content
 *   [16..23]  blob_hash      uint64   xxh64 of the .aladin file
 *   [24..31]  blob_size      int64    size of the .aladin file
 *   [32..39]  crypt_key_id   uint64   opaque key identifier
 *   [40]      is_crypted     uint8    1 if encrypted, 0 otherwise
 *   [41..47]  padding        7 bytes
 */

/*
 * Pointer to the raw 48 bytes of an entry in the buffer.
 */
typedef const uint8_t *blob_ref_t;

/*
 * Get the content hash.
 */
uint64_t blob_content_hash(blob_ref_t b);

/*
 * Get the content size.
 */
int64_t blob_content_size(blob_ref_t b);

/*
 * Get the blob hash.
 */
uint64_t blob_blob_hash(blob_ref_t b);

/*
 * Get the blob size.
 */
int64_t blob_blob_size(blob_ref_t b);

/*
 * Get the encryption key id.
 */
uint64_t blob_crypt_key_id(blob_ref_t b);

/*
 * Check the blob's encryption flag.
 */
bool blob_is_crypted(blob_ref_t b);

typedef struct {
    const uint8_t *buf;
    uint32_t table_pos; // absolute position of the root table
    uint32_t blobs_off; // vtable field offsets for blobs vector
    uint32_t hashes_off; // vtable field offsets for adress-hashes vector
    uint32_t values_off; // vtable field offsets for adress-values vector
    uint32_t count; // number of entries in the index
} serialized_index_t;

/*
 * Initialize the serialized index parser.
 */
bool si_init(serialized_index_t *idx, const uint8_t *buf, size_t len);

/*
 * Get the entry count.
 */
uint32_t si_count(const serialized_index_t *idx);

/*
 * Get the blob reference.
 */
blob_ref_t si_blob(const serialized_index_t *idx, uint32_t i);

/*
 * Get the address hash.
 */
uint64_t si_address_hash(const serialized_index_t *idx, uint32_t i);

/*
 * Get the address string.
 */
const char *si_address_value(const serialized_index_t *idx, uint32_t i);

#endif /* SERIALIZED_INDEX */
