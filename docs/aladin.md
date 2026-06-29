<!--
SPDX-FileCopyrightText: 2026 SombrAbsol

SPDX-License-Identifier: MIT
-->

# Aladin Asset System
Used in *Pokémon Trading Card Game Pocket* to store, index, and optionally encrypt game assets. The system consists of three interacting components: a directory of encrypted blob files (`.aladin`), a set of FlatBuffers index files mapping asset paths to blobs, and a two-key encryption scheme based on a modified ChaCha20 cipher.

Please note that this documentation was written based on the code that served as the basis for aladump and may therefore be inaccurate or incomplete.

## Table of contents
* [Directory layout](#directory-layout)
* [Built-in sub-key container](#built-in-sub-key-container)
* [Blob file](#blob-file)
  * [File naming](#file-naming)
  * [Decryption](#decryption)
* [FlatBuffers index file](#flatbuffers-index-file)
  * [FlatBuffers layout](#flatbuffers-layout)
  * [FlatBuffers pointer resolution](#flatbuffers-pointer-resolution)
  * [Blob entry](#blob-entry)
  * [Address hash](#address-hash)
* [Encryption](#encryption)
  * [Key schedule](#key-schedule)
  * [Variable round count](#variable-round-count)
  * [Block function](#block-function)
  * [Stream cipher](#stream-cipher)
* [Key bootstrapping](#key-bootstrapping)
  * [KEY_ID_BUILTIN_SUB](#key_id_builtin_sub)
  * [KEY_ID_MAIN](#key_id_main)
* [xxHash-64](#xxhash-64)
  * [Constants](#constants)
  * [Stripe phase](#stripe-phase)
  * [Tail phase](#tail-phase)
  * [Avalanche](#avalanche)

## Directory layout
```
<base>/
  src_cph_1001          built-in sub-key container
  index/
    <xx>/
      <hex16>.aladin    FlatBuffers serialized index files
  blob/
    <xx>/
      <hex16>.aladin    encrypted or plaintext blob files
```

* Blob files are sharded into 256 subdirectories named by the first two hex digits of their hash (e.g. `blob/3f/3fabc...aladin`).
* Index files are similarly sharded under `index/`.

## Built-in sub-key container
`src_cph_1001` is a small binary file included with the base game that contains the first decryption key (`KEY_ID_BUILTIN_SUB = 0xBCBD3EF1AD9527D8`). The key itself is 32 bytes long.

Header:
```rust
{
  u32 offset // big-endian, byte offset to the key data from the start of the file
  u32 length // big-endian, length of the key data in bytes (must be >= 32)
}
```

Immediately followed by arbitrary padding, then `length` bytes of key material starting at `offset`.

## Blob file
A blob file is a raw byte payload, either plain text or ChaCha20-encrypted. The file has no header of its own. All metadata (size, hashes, encryption flag, key id) is contained in the index that references it.

### File naming
The filename is the lowercase hexadecimal representation of the blob's xxHash-64 digest (`blob_hash`), zero-padded to 16 characters, with the `.aladin` extension appended:
```
blob/<blob_hash[0:2]>/<blob_hash>.aladin
```

### Decryption
If the associated index entry has `is_crypted = 1`:
1. Read the full file into a buffer.
2. Initialise a ChaCha20 context with `content_hash` as the IV and the key identified by `crypt_key_id`.
3. Decrypt the buffer in-place.
4. Verify the xxHash-64 digest of the decrypted buffer equals `content_hash`.

If `is_crypted = 0`, the file is stored as-is; only the hash check applies.

## FlatBuffers index file
Each index file is a FlatBuffers table that maps the addresses of virtual assets to the blob metadata. All integer values are little-endian.

### FlatBuffers layout
```rust
[0..3] u32 root_offset // offset from byte 0 to the root table
```

The root table contains three parallel vectors, all of the same length `N`:
| FlatBuffers vtable slot | Field | Type | Description |
|---|---|---|---|
| 4 | `blobs` | vector of struct | `N` blob entries, 48 bytes each |
| 6 | `address_hashes` | vector of u64 | `N` xxHash-64 digests of the address strings |
| 8 | `address_values` | vector of string | `N` virtual asset path strings |

The entry count `N` is read from the `address_values` vector length. All three vectors are indexed identically: entry `i` in `blobs`, `address_hashes[i]`, and `address_values[i]` all describe the same asset.

### FlatBuffers pointer resolution
```
vtable_pos    = table_pos - soffset32(buf, table_pos)
field_offset  = u16(buf, vtable_pos + slot) // 0 if field absent
vector_header = table_pos + field_offset + u32(buf, table_pos + field_offset)
vector_count  = u32(buf, vector_header)
vector_data   = vector_header + 4
```

`address_values` are FlatBuffers strings composed of a 4-byte prefix, followed by UTF-8 bytes and a null terminator. Each slot in the string vector holds a 4-byte uoffset to its string.

### Blob entry
```rust
{
  u64   content_hash // [0..7]   xxHash-64 of the decrypted content; used as ChaCha20 IV
  i64   content_size // [8..15]  size of the decrypted content in bytes
  u64   blob_hash    // [16..23] xxHash-64 of the .aladin file; used to build the file path
  i64   blob_size    // [24..31] size of the .aladin file in bytes
  u64   crypt_key_id // [32..39] opaque identifier of the decryption key
  u8    is_crypted   // [40]     1 if encrypted, 0 if plaintext
  u8[7] padding      // [41..47] reserved, zero
}
```

### Address hash
`address_hashes[i]` is the xxHash-64 digest of the corresponding address string computed with seed `0`. It is used to locate a specific asset (notably the main key blob) without iterating over all string values:
```
address_hash = xxh64(address_string, strlen(address_string), seed=0)
```

## Encryption
The cipher is a structural variant of [ChaCha20](https://cr.yp.to/chacha.html) (by Daniel J. Bernstein, 2008). It differs from the standard in three ways: a custom sigma constant, a key-derived variable round count, and a counter that is pre-incremented before each block is generated.

### Key schedule
The 16-word (512-bit) initial state is laid out as follows:
| Words | Source | Value |
|---|---|---|
| 0–3 | sigma constant | `"A3AxwtfWD<PbxMx$"` (ASCII, little-endian u32 per word) |
| 4–11 | 256-bit key | 8 * little-endian u32 from the 32-byte key |
| 12 | counter | `0` (pre-incremented before the first block) |
| 13–14 | IV | `content_hash` split as two little-endian u32 (low word first) |
| 15 | marker | `0x63686368` (`chch` in ASCII) |

### Variable round count
The number of double rounds per block is not fixed. It is derived once from the initial state after it is fully populated:
```
step = ((state[9] + state[4]) XOR state[11])
     + (state[15] XOR (state[14] + state[13]))

idx  = ( ((step >> 7) & 2) XOR ((step >> 2) & 1) )
     | ( (step >> 13) & 4 )
     | ( (step >> 2)  & 8 )

turns = TURN_TABLE[idx]
```

`TURN_TABLE` is a fixed 16-entry lookup table indexed by the 4-bit value `idx`:
| idx | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| turns | 6 | 5 | 6 | 5 | 5 | 6 | 5 | 6 | 6 | 6 | 5 | 5 | 5 | 6 | 6 | 5 |

Each entry is a double-round count (one double round = one column round + one diagonal round). The standard ChaCha20 uses 10 fixed double rounds; this variant uses either 5 or 6.

### Block function
Each 64-byte keystream block is generated as follows:
1. Pre-increment the counter: `state[12]++`
2. Copy the 16-word state into a working array `x`.
3. Apply `turns` double rounds to `x`:
   * **Column round:** QR(x, 0,4,8,12), QR(x, 1,5,9,13), QR(x, 2,6,10,14), QR(x, 3,7,11,15)
   * **Diagonal round:** QR(x, 0,5,10,15), QR(x, 1,6,11,12), QR(x, 2,7,8,13), QR(x, 3,4,9,14)
4. Add the original state word-by-word: `x[i] += state[i]`
5. Serialise `x` as 64 bytes, little-endian u32 per word.

The quarter-round function QR(x, a, b, c, d) is the standard ChaCha20 quarter-round:
```
x[a] += x[b];  x[d] = ROTL32(x[d] ^ x[a], 16)
x[c] += x[d];  x[b] = ROTL32(x[b] ^ x[c], 12)
x[a] += x[b];  x[d] = ROTL32(x[d] ^ x[a],  8)
x[c] += x[d];  x[b] = ROTL32(x[b] ^ x[c],  7)
```

### Stream cipher
The keystream is XOR-ed with the plaintext sequentially, one block at a time:
```
for each 64-byte block (or partial final block):
    generate block (counter pre-incremented as above)
    dst[i] = src[i] XOR block[i]  for i in [0, min(64, remaining))
```

Encryption and decryption are the same operation.

## Key bootstrapping
Two keys are used. They are loaded in order at startup; all blobs that reference `KEY_ID_MAIN` cannot be decrypted until the main key has been found and loaded.

### KEY_ID_BUILTIN_SUB
`0xBCBD3EF1AD9527D8`. Loaded unconditionally from `src_cph_1001` at startup. This key decrypts the main key blob.

### KEY_ID_MAIN
`0xCF461AF74368F659`. The main key is itself stored as an asset blob in the index. Its location is found by scanning `address_hashes` for the xxHash-64 of the filename `src_cph_2337e44f-c267-44e7-9af9-ec332df6e7ae.bytes` (seed `0`). The blob is decrypted with `KEY_ID_BUILTIN_SUB` if `is_crypted = 1`, and the resulting 32-byte payload is registered as `KEY_ID_MAIN`.

## xxHash-64
All hashes in the system (content verification, blob file naming, address lookup) use the [xxHash-64](https://github.com/Cyan4973/xxHash) algorithm (by Yann Collet, 2012) with seed `0` unless noted otherwise. The implementation follows the reference exactly:

### Constants
```
P1 = 0x9E3779B185EBCA87
P2 = 0xC2B2AE3D27D4EB4F
P3 = 0x165667B19E3779F9
P4 = 0x85EBCA77C2B2AE63
P5 = 0x27D4EB2F165667C5
```

### Stripe phase
Input is at least 32 bytes. Four 64-bit accumulators are initialised from the seed:
```
v1 = seed + P1 + P2
v2 = seed + P2
v3 = seed
v4 = seed - P1
```

Each 32-byte stripe feeds 8 bytes into each accumulator in turn via the round function:
```
round(acc, in) = ROTL64(acc + in * P2, 31) * P1
```

After all stripes are consumed the accumulators are folded into a single value:
```
h = ROTL64(v1,  1) + ROTL64(v2,  7)
  + ROTL64(v3, 12) + ROTL64(v4, 18)

merge(h, v) = (h XOR round(0, v)) * P1 + P4

h = merge(merge(merge(merge(h, v1), v2), v3), v4)
```

For inputs shorter than 32 bytes the stripe phase is skipped and `h = seed + P5`.

### Tail phase
`h += len` is added unconditionally after the stripe phase. Remaining bytes are consumed in blocks of 8, then 4, then 1:
```
// 8-byte blocks
h ^= round(0, u64le(p));  h = ROTL64(h, 27) * P1 + P4

// 4-byte block
h ^= u32le(p) * P1;  h = ROTL64(h, 23) * P2 + P3

// single bytes
h ^= byte * P5;  h = ROTL64(h, 11) * P1
```

### Avalanche
A final mixing step is applied to eliminate output bias:
```
h ^= h >> 33;  h *= P2
h ^= h >> 29;  h *= P3
h ^= h >> 32
```
