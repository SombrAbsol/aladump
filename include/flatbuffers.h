/*
 * FlatBuffers utilities.
 *
 * SPDX-FileCopyrightText: 2026 SombrAbsol
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef FLATBUFFERS
#define FLATBUFFERS

#include <stdint.h>
#include <string.h>

/*
 * Read a u16 little-endian.
 */
static inline uint16_t fb_u16(const uint8_t *b, uint32_t pos)
{
    uint16_t v;
    memcpy(&v, b + pos, 2);
    return v;
}

/*
 * Read a u32 little-endian.
 */
static inline uint32_t fb_u32(const uint8_t *b, uint32_t pos)
{
    uint32_t v;
    memcpy(&v, b + pos, 4);
    return v;
}

/*
 * Read a u64 little-endian.
 */
static inline uint64_t fb_u64(const uint8_t *b, uint32_t pos)
{
    uint64_t v;
    memcpy(&v, b + pos, 8);
    return v;
}

/*
 * Read a s32 little-endian.
 */
static inline int32_t fb_s32(const uint8_t *b, uint32_t pos)
{
    int32_t v;
    memcpy(&v, b + pos, 4);
    return v;
}

/*
 * Get the absolute position of the root table in the buffer.
 */
static inline uint32_t fb_root(const uint8_t *buf)
{
    return fb_u32(buf, 0);
}

/*
 * Get the field offset for the given vtable slot.
 */
static inline uint32_t fb_field(
    const uint8_t *buf, uint32_t table_pos, uint16_t vtable_slot)
{
    // the vtable is at table_pos - soffset
    uint32_t vtab = (uint32_t)((int32_t)table_pos - fb_s32(buf, table_pos));
    if (vtable_slot >= fb_u16(buf, vtab)) {
        return 0;
    }
    return fb_u16(buf, vtab + vtable_slot);
}

/*
 * Get the vector data start.
 */
static inline uint32_t fb_vec_data(
    const uint8_t *buf, uint32_t table_pos, uint32_t field_off)
{
    uint32_t ref = table_pos + field_off;

    // the field holds a relative uoffset pointing to the vector header
    return ref + fb_u32(buf, ref) + 4; // +4 to skip the count word
}

/*
 * Get the vector length.
 */
static inline uint32_t fb_vec_len(
    const uint8_t *buf, uint32_t table_pos, uint32_t field_off)
{
    uint32_t ref = table_pos + field_off;
    return fb_u32(buf, ref + fb_u32(buf, ref));
}

/*
 * Get the string pointer.
 */
static inline const char *fb_string(const uint8_t *buf, uint32_t elem_pos)
{
    // +4 to skip the length prefix
    return (const char *)(buf + elem_pos + fb_u32(buf, elem_pos) + 4);
}

#endif /* FLATBUFFERS */
