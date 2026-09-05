/*
 * Extraction and decryption tool for Pokémon TCG Pocket assets.
 *
 * SPDX-FileCopyrightText: 2026 SombrAbsol
 *
 * SPDX-License-Identifier: MIT
 */

#include "chacha20.h"
#include "serialized_index.h"
#include "xxhash.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <direct.h>
#include <io.h>
#include <share.h>
#include <windows.h>
#else
#include <dirent.h>
#include <sys/mman.h>
#include <unistd.h>
#endif

/*
 * Wrappers for MSVC-deprecated CRT functions.
 */
#ifdef _WIN32
#define open(path, flags)     xopen((path), (flags))
#define close                 _close
#define xstrncpy(dst, src, n) strncpy_s((dst), (n) + 1, (src), (n))

static const char *xstrerror(int err)
{
    static char buf[256];
    strerror_s(buf, sizeof(buf), err);
    return buf;
}

static int xopen(const char *path, int flags)
{
    int fd = -1;
    _sopen_s(&fd, path, flags | _O_BINARY, _SH_DENYNO, _S_IREAD);
    return fd;
}

static FILE *xfopen(const char *path, const char *mode)
{
    FILE *f = NULL;
    fopen_s(&f, path, mode);
    return f;
}
#else
#define xstrncpy(dst, src, n) strncpy((dst), (src), (n))
#define xstrerror(e)          strerror(e)
#define xfopen(path, mode)    fopen((path), (mode))
#endif

/*
 * Identifiers for the encryption keys, defined by the game's build system.
 */
#define KEY_ID_BUILTIN_SUB UINT64_C(0xBCBD3EF1AD9527D8) // 13600095657449039832
#define KEY_ID_MAIN        UINT64_C(0xCF461AF74368F659) // 14935654863511025241

/*
 * Filename of the main key in the index, its xxh64 is used to locate its blob.
 */
#define MAIN_KEY_FILENAME "src_cph_2337e44f-c267-44e7-9af9-ec332df6e7ae.bytes"

/*
 * Size of a ChaCha20 key in bytes.
 */
#define KEY_SIZE 32

/*
 * Maximum number of simultaneous keys: builtin_sub + main key = 2 in practice.
 */
#define MAX_KEYS 8

/*
 * Maximum file path length.
 */
#define PATH_BUF 8192

/*
 * Blobs larger than this threshold are memory-mapped instead of malloc+fread.
 */
#define MMAP_THRESHOLD (1024 * 1024)

/*
 * Number of recently-created directory paths to cache.
 */
#define MKDIR_CACHE_SIZE 16

/*
 * Cross-platform mkdir wrapper.
 */
#ifdef _WIN32
#define MKDIR(path) _mkdir(path)
#else
#define MKDIR(path) mkdir(path, 0755)
#endif

/*
 * Stored decryption key entry.
 */
typedef struct {
    uint64_t id;
    uint8_t data[KEY_SIZE];
    bool valid;
} key_entry_t;

/*
 * Global key table, indexed by opaque identifier.
 */
static key_entry_t g_keys[MAX_KEYS];

/*
 * Store or overwrite a key in the global table.
 */
static bool key_store(uint64_t id, const uint8_t *data, size_t len)
{
    if (len < KEY_SIZE) {
        fprintf(stderr,
            "key_store: warning, key 0x%016llx is only %zu bytes (need %d)\n",
            (unsigned long long)id,
            len,
            KEY_SIZE);
        return false;
    }
    for (int i = 0; i < MAX_KEYS; i++) {
        if (!g_keys[i].valid || g_keys[i].id == id) {
            g_keys[i].id = id;
            g_keys[i].valid = true;
            memcpy(g_keys[i].data, data, KEY_SIZE);
            return true;
        }
    }
    fprintf(stderr, "key_store: key table full\n");
    return false;
}

/*
 * Return a pointer to the KEY_SIZE bytes of a key.
 */
static const uint8_t *key_find(uint64_t id)
{
    for (int i = 0; i < MAX_KEYS; i++) {
        if (g_keys[i].valid && g_keys[i].id == id) {
            return g_keys[i].data;
        }
    }
    return NULL;
}

/*
 * Track whether the buffer came from mmap or malloc
 * so the caller can release it correctly.
 */
typedef struct {
    uint8_t *data;
    size_t len;
    bool mapped; // true: munmap, false: free
} file_buf_t;

/*
 * Open a file and return its contents.
 */
static bool file_open(const char *path, file_buf_t *fb)
{
    fb->data = NULL;
    fb->len = 0;
    fb->mapped = false;

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr,
            "\nfile_open: cannot open '%s': %s\n",
            path,
            xstrerror(errno));
        return false;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        int err = errno;
        close(fd);
        fprintf(stderr,
            "\nfile_open: cannot stat '%s': %s\n",
            path,
            xstrerror(err));
        return false;
    }
    if (st.st_size <= 0) {
        fprintf(stderr, "\nfile_open: '%s' is empty\n", path);
        close(fd);
        return false;
    }
    size_t sz = (size_t)st.st_size;

#ifndef _WIN32
    // use mmap for large files on POSIX platforms
    if (sz >= MMAP_THRESHOLD) {
        void *p = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
        close(fd);
        if (p == MAP_FAILED) {
            fprintf(stderr,
                "\nfile_open: mmap failed for '%s': %s\n",
                path,
                xstrerror(errno));
            return false;
        }
        fb->data = (uint8_t *)p;
        fb->len = sz;
        fb->mapped = true;
        return true;
    }
#endif
    // fallback to buffered I/O
    close(fd);

    FILE *f = xfopen(path, "rb");
    if (!f) {
        fprintf(stderr,
            "\nfile_open: cannot open '%s': %s\n",
            path,
            xstrerror(errno));
        return false;
    }

    uint8_t *buf = malloc(sz);
    if (!buf) {
        fprintf(
            stderr, "\nfile_open: out of memory allocating %zu bytes\n", sz);
        fclose(f);
        return false;
    }

    if (fread(buf, 1, sz, f) != sz) {
        fprintf(stderr, "\nfile_open: short read on '%s'\n", path);
        free(buf);
        fclose(f);
        return false;
    }

    fclose(f);

    fb->data = buf;
    fb->len = sz;
    fb->mapped = false;

    return true;
}

/*
 * Release a buffer.
 */
static void file_close(file_buf_t *fb)
{
    if (!fb->data) {
        return;
    }

#ifndef _WIN32
    // release a memory-mapped buffer
    if (fb->mapped) {
        munmap(fb->data, fb->len);
    } else

#endif
    {
        free(fb->data);
    }

    fb->data = NULL;
}

/*
 * Write len bytes of data to the file at path.
 */
static bool file_write(const char *path, const uint8_t *data, size_t len)
{
    FILE *f = xfopen(path, "wb");
    if (!f) {
        fprintf(stderr,
            "file_write: cannot create '%s': %s\n",
            path,
            xstrerror(errno));
        return false;
    }

    bool ok = fwrite(data, 1, len, f) == len;
    if (!ok) {
        fprintf(stderr, "file_write: short write to '%s'\n", path);
    }

    fclose(f);
    return ok;
}

/*
 * Recursively create all directories in path.
 */
static bool mkdir_p(char *path)
{
    for (char *p = path + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (MKDIR(path) != 0 && errno != EEXIST) {
                fprintf(stderr,
                    "mkdir_p: cannot create '%s': %s\n",
                    path,
                    xstrerror(errno));
                *p = '/';
                return false;
            }
            *p = '/';
        }
    }
    if (MKDIR(path) != 0 && errno != EEXIST) {
        fprintf(stderr,
            "mkdir_p: cannot create '%s': %s\n",
            path,
            xstrerror(errno));
        return false;
    }
    return true;
}

/*
 * Ring-buffer cache of recently mkdir_p-ed directory paths.
 */
static char g_mkdir_cache[MKDIR_CACHE_SIZE][PATH_BUF];
static int g_mkdir_cache_head = 0;

/*
 * Call mkdir_p(dir) only if dir is not already in the recent-path cache.
 */
static bool mkdir_cached(char *dir)
{
    for (int i = 0; i < MKDIR_CACHE_SIZE; i++) {
        if (strcmp(g_mkdir_cache[i], dir) == 0) {
            return true; // already created
        }
    }
    if (!mkdir_p(dir)) {
        return false;
    }
    xstrncpy(g_mkdir_cache[g_mkdir_cache_head], dir, PATH_BUF - 1);
    g_mkdir_cache[g_mkdir_cache_head][PATH_BUF - 1] = '\0';
    g_mkdir_cache_head = (g_mkdir_cache_head + 1) % MKDIR_CACHE_SIZE;
    return true;
}

/*
 * Callback invoked for each file during directory traversal.
 */
typedef void (*file_cb_t)(const char *path, void *ud);

/*
 * Recursively walk a directory and call callback for each file.
 */
#ifdef _WIN32
static void walk_dir(const char *dir, file_cb_t cb, void *ud)
{
    char pattern[PATH_BUF];
    snprintf(pattern, sizeof(pattern), "%s\\*", dir);

    WIN32_FIND_DATAA ffd;
    HANDLE hFind = FindFirstFileA(pattern, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "walk_dir: cannot open directory '%s'\n", dir);
        return;
    }

    do {
        if (ffd.cFileName[0] == '.') {
            continue;
        }

        char path[PATH_BUF];
        snprintf(path, sizeof(path), "%s/%s", dir, ffd.cFileName);

        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            walk_dir(path, cb, ud);
        } else {
            cb(path, ud);
        }
    } while (FindNextFileA(hFind, &ffd));

    FindClose(hFind);
}
#else
static void walk_dir(const char *dir, file_cb_t cb, void *ud)
{
    DIR *d = opendir(dir);
    if (!d) {
        fprintf(stderr, "walk_dir: cannot open directory '%s'\n", dir);
        return;
    }

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') {
            continue;
        }

        char path[PATH_BUF];
        snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);

#if defined(_DIRENT_HAVE_D_TYPE)
        unsigned char dt = ent->d_type;
        if (dt == DT_UNKNOWN) {
            // fallback for filesystems that do not populate d_type
            struct stat st;
            if (stat(path, &st) != 0) {
                fprintf(stderr, "walk_dir: cannot stat '%s'\n", path);
                continue;
            }
            dt = S_ISREG(st.st_mode)  ? DT_REG
                : S_ISDIR(st.st_mode) ? DT_DIR
                                      : DT_UNKNOWN;
        }
        if (dt == DT_REG) {
            cb(path, ud);
        } else if (dt == DT_DIR) {
            walk_dir(path, cb, ud);
        }
#else
        // portable fallback when d_type is unavailable
        struct stat st;
        if (stat(path, &st) != 0) {
            fprintf(stderr, "walk_dir: cannot stat '%s'\n", path);
            continue;
        }
        if (S_ISREG(st.st_mode)) {
            cb(path, ud);
        } else if (S_ISDIR(st.st_mode)) {
            walk_dir(path, cb, ud);
        }
#endif
    }

    closedir(d);
}
#endif

/*
 * Progress tracking structure.
 */
typedef struct {
    uint32_t total;
    uint32_t current;
} progress_t;

/*
 * Update progress with the description of the current item.
 */
static void progress_update(progress_t *p, const char *desc)
{
    p->current++;
    /*
     * '\r': overwrite the same line.
     * '\033[K': clear the rest of the line.
     */
    if (p->total > 0) {
        fprintf(stderr, "\r[%u/%u] %.80s\033[K", p->current, p->total, desc);
    } else {
        fprintf(stderr, "\r[%u] %.80s\033[K", p->current, desc);
    }
    fflush(stderr);
}

/*
 * Finalize the progress bar and move to the next line.
 */
static void progress_done(const progress_t *p)
{
    fprintf(stderr, "\r[%u/%u] done.\033[K\n", p->current, p->total);
}

/*
 * Decrypt a buffer in-place using ChaCha20.
 */
static bool decrypt_blob(
    uint8_t *data, size_t len, uint64_t content_hash, uint64_t key_id)
{
    const uint8_t *key = key_find(key_id);
    if (!key) {
        fprintf(stderr,
            "\ndecrypt_blob: warning, unknown key id 0x%016llx\n",
            (unsigned long long)key_id);
        return false;
    }
    chacha20_ctx_t ctx;
    chacha20_keysetup(&ctx, content_hash, key);
    chacha20_crypt(&ctx, data, data, len);
    return true;
}

/*
 * Read 'src_cph_1001', extract the big-endian-encoded key
 * from the first 8 bytes, then register it in the key table.
 */
static bool load_builtin_sub_key(const char *base_path)
{
    char path[PATH_BUF];
    snprintf(path, sizeof(path), "%s/src_cph_1001", base_path);

    file_buf_t fb;
    if (!file_open(path, &fb)) {
        return false;
    }
    if (fb.len < 8) {
        file_close(&fb);
        fprintf(stderr, "load_builtin_sub_key: '%s' too small\n", path);
        return false;
    }

    // big-endian header: uint32 offset, uint32 length
    uint32_t offset = ((uint32_t)fb.data[0] << 24)
        | ((uint32_t)fb.data[1] << 16) | ((uint32_t)fb.data[2] << 8)
        | (uint32_t)fb.data[3];
    uint32_t klen = ((uint32_t)fb.data[4] << 24) | ((uint32_t)fb.data[5] << 16)
        | ((uint32_t)fb.data[6] << 8) | (uint32_t)fb.data[7];

    if ((size_t)offset + klen > fb.len) {
        file_close(&fb);
        fprintf(stderr,
            "load_builtin_sub_key: src_cph_1001 header out of bounds\n");
        return false;
    }

    if (!key_store(KEY_ID_BUILTIN_SUB, fb.data + offset, klen)) {
        file_close(&fb);
        return false;
    }
    file_close(&fb);
    printf("Builtin sub key loaded (%u bytes)\n", klen);
    return true;
}

/*
 * Main key address hash, computed once at startup.
 */
static uint64_t g_main_key_addr_hash = 0;

/*
 * Absolute path to the 'blob/' subdirectory.
 */
static char g_blob_dir[PATH_BUF];

/*
 * Absolute path to the 'output/' subdirectory.
 */
static char g_output_dir[PATH_BUF];

/*
 * True once the main key has been loaded.
 */
static bool g_main_key_loaded = false;

/*
 * Build the path of a .aladin file from its hash.
 */
static void make_blob_path(char *out, size_t out_size, uint64_t blob_hash)
{
    char hex[17];
    snprintf(hex, sizeof(hex), "%016llx", (unsigned long long)blob_hash);
    snprintf(out, out_size, "%s/%.2s/%s.aladin", g_blob_dir, hex, hex);
}

/*
 * Process a FlatBuffers index buffer.
 */
static void process_index_buf(
    const uint8_t *idx_buf, size_t idx_len, progress_t *progress)
{
    serialized_index_t idx;
    if (!si_init(&idx, idx_buf, idx_len)) {
        fprintf(stderr, "process_index_buf: warning, invalid index buffer\n\n");
        return;
    }

    uint32_t n = si_count(&idx);

    // pass 1: load the main key if it is in this index
    if (!g_main_key_loaded) {
        for (uint32_t i = 0; i < n; i++) {
            if (si_address_hash(&idx, i) != g_main_key_addr_hash) {
                continue;
            }

            blob_ref_t b = si_blob(&idx, i);
            char blob_path[PATH_BUF];
            make_blob_path(blob_path, sizeof(blob_path), blob_blob_hash(b));

            file_buf_t fb;
            if (!file_open(blob_path, &fb)) {
                break; // blob missing, key may be in another index
            }

            if (blob_is_crypted(b)) {
                decrypt_blob(fb.data,
                    fb.len,
                    blob_content_hash(b),
                    blob_crypt_key_id(b));
            }

            if (!key_store(KEY_ID_MAIN, fb.data, fb.len)) {
                fprintf(
                    stderr, "process_index_buf: failed to store main key\n\n");
                file_close(&fb);
                break;
            }
            file_close(&fb);
            g_main_key_loaded = true;
            printf("Main key loaded from blob %016llx\n",
                (unsigned long long)blob_blob_hash(b));
            break;
        }
    }

    // pass 2: export all assets
    for (uint32_t i = 0; i < n; i++) {
        blob_ref_t b = si_blob(&idx, i);
        const char *addr = si_address_value(&idx, i);

        if (progress) {
            progress_update(progress, addr ? addr : "?");
        }

        char blob_path[PATH_BUF];
        make_blob_path(blob_path, sizeof(blob_path), blob_blob_hash(b));

        file_buf_t fb;
        if (!file_open(blob_path, &fb)) {
            fprintf(stderr,
                "process_index_buf: skipping (not found) '%s'\n\n",
                blob_path);
            continue;
        }

        if (blob_is_crypted(b)) {
            if (!decrypt_blob(fb.data,
                    fb.len,
                    blob_content_hash(b),
                    blob_crypt_key_id(b))) {
                file_close(&fb);
                continue;
            }
        }

        // xxh64 of the decrypted content must match
        uint64_t actual = xxh64(fb.data, fb.len, 0);
        if (actual != blob_content_hash(b)) {
            fprintf(stderr,
                "process_index_buf: hash mismatch for '%s' (got %016llx "
                "expected %016llx)\n\n",
                addr ? addr : "?",
                (unsigned long long)actual,
                (unsigned long long)blob_content_hash(b));
            file_close(&fb);
            continue;
        }

        // create the destination directory and write the decrypted file
        if (addr) {
            char out_path[PATH_BUF];
            snprintf(out_path, sizeof(out_path), "%s/%s", g_output_dir, addr);

            // extract the parent directory and create it
            char dir_buf[PATH_BUF];
            snprintf(dir_buf, sizeof(dir_buf), "%s", out_path);
            char *sep = strrchr(dir_buf, '/');
            if (sep) {
                *sep = '\0';
                mkdir_cached(dir_buf);
            }

            file_write(out_path, fb.data, fb.len);
        }

        file_close(&fb);
    }
}

/*
 * Shared data between the counting and processing callbacks.
 */
typedef struct {
    uint32_t total; // total entry count
    progress_t prog; // progress bar
} walk_state_t;

/*
 * Count the number of entries in each index file.
 */
static void count_cb(const char *path, void *ud)
{
    walk_state_t *ws = (walk_state_t *)ud;

    file_buf_t fb;
    if (!file_open(path, &fb)) {
        fprintf(stderr, "count_cb: cannot read %s\n", path);
        return;
    }
    serialized_index_t tmp;
    if (!si_init(&tmp, fb.data, fb.len)) {
        fprintf(stderr, "count_cb: invalid index '%s'\n", path);
    } else {
        ws->total += si_count(&tmp);
    }
    file_close(&fb);
}

/*
 * Process an index file and update the progress bar.
 */
static void process_cb(const char *path, void *ud)
{
    walk_state_t *ws = (walk_state_t *)ud;

    file_buf_t fb;
    if (!file_open(path, &fb)) {
        fprintf(stderr, "\nwarning: cannot read '%s'\n", path);
        return;
    }
    process_index_buf(fb.data, fb.len, &ws->prog);
    file_close(&fb);
}

/*
 * Initialize paths and keys, and walk the index directory twice.
 */
static bool process_path(const char *base)
{
    char index_dir[PATH_BUF];

    snprintf(index_dir, sizeof(index_dir), "%s/index", base);
    snprintf(g_blob_dir, sizeof(g_blob_dir), "%s/blob", base);
    snprintf(g_output_dir, sizeof(g_output_dir), "%s/output", base);

    mkdir_p(g_output_dir);

    g_main_key_addr_hash
        = xxh64(MAIN_KEY_FILENAME, strlen(MAIN_KEY_FILENAME), 0);

    printf("Main key address hash: 0x%016llx\n",
        (unsigned long long)g_main_key_addr_hash);

    if (!load_builtin_sub_key(base)) {
        return false;
    }

    walk_state_t ws = { 0 };

    walk_dir(index_dir, count_cb, &ws);
    printf("Total index entries: %u\n", ws.total);

    ws.prog.total = ws.total;

    walk_dir(index_dir, process_cb, &ws);

    if (!g_main_key_loaded) {
        fprintf(stderr, "process_path: main key was not found in any index\n");
        return false;
    }

    progress_done(&ws.prog);

    printf("Extraction complete: '%s'\n", g_output_dir);

    return true;
}

/*
 * Command-line interface.
 */
int main(int argc, char **argv)
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8); // ensure UTF-8 output on Windows
#endif

    if (argc >= 2 && (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h"))) {
        printf(
            "aladump - Asset extractor for Pokémon Trading Card Game Pocket\n");
        printf("Copyright (c) 2026 SombrAbsol\n\n");
        printf("Usage:\n");
        printf(
            "  %s <indir>    must contain 'src_cph_1001', 'index/', 'blob/'\n",
            argv[0]);
        printf("  %s -h|--help  show this help\n", argv[0]);
        return EXIT_SUCCESS;
    }

    const char *base = NULL;

    if (argc == 2) {
        base = argv[1];
    } else {
        fprintf(stderr, "Invalid arguments\n");
        fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (!process_path(base)) {
        fprintf(stderr, "Extraction failed.\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
