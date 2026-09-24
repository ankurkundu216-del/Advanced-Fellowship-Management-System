/*
 * ADVANCED FELLOWSHIP MANAGEMENT SYSTEM
 *
 * Architecture:
 *   - Primary storage: sorted doubly linked list by member name.
 *   - Secondary index: separate-chaining hash table mapping name -> DLL node.
 *   - Recycled node pool: AVAIL stack avoids immediate free() on delete.
 *   - Secure wiping: deleted/history/persistence buffers are zeroed.
 *   - Undo: last 3 Add/Remove commands are retained and can be reversed.
 *   - Persistence: binary file with magic/version/count/CRC32.
 *
 * Compile:
 *   gcc -Wall -Wextra -O3 -fsanitize=address -g -o fellowship fellowship.c
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>

/******************************************************************************
 * Constants
 ******************************************************************************/

#define MAX_NAME_LEN        128u
#define MAX_RACE_LEN        64u
#define INPUT_LEN           512u

#define HISTORY_LIMIT       3u

#define DEFAULT_BUCKET_COUNT 1024u   /* Must be power of two. */

#define MIN_AGE             0
#define MAX_AGE             100000

#define FELLOWSHIP_FILE     "fellowship.dat"

/*
 * Binary file format:
 *   16-byte header:
 *     [0..3]   magic       little-endian
 *     [4..7]   version     little-endian
 *     [8..11]  count       little-endian
 *     [12..15] crc32       little-endian, CRC32 over payload only
 *
 *   Payload record:
 *     name[MAX_NAME_LEN]
 *     race[MAX_RACE_LEN]
 *     age[4] little-endian
 */
#define FILE_MAGIC          0x464C5731u  /* "FLW1" */
#define FILE_VERSION        1u
#define HEADER_BYTES        16u
#define AGE_BYTES           sizeof(uint32_t)
#define RECORD_BYTES        (MAX_NAME_LEN + MAX_RACE_LEN + AGE_BYTES)

/* Defensive load-time cap. Tune as needed. */
#define MAX_LOAD_COUNT      1000000u

/******************************************************************************
 * Types
 ******************************************************************************/

typedef enum {
    ACTION_NONE = 0,
    ACTION_ADD,
    ACTION_REMOVE
} ActionType;

/*
 * Lightweight Command Pattern record.
 * It stores enough inverse state to undo an Add or Remove.
 */
typedef struct UndoCommand {
    ActionType type;
    char       name[MAX_NAME_LEN];
    char       race[MAX_RACE_LEN];
    int        age;
} UndoCommand;

/*
 * Member node.
 *
 * next/prev: active DLL links.
 * hash_next: hash bucket chain link.
 *
 * When a node is in the AVAIL pool, next is reused as the pool stack link.
 */
typedef struct MemberNode {
    char               name[MAX_NAME_LEN];
    char               race[MAX_RACE_LEN];
    int                age;
    struct MemberNode *prev;
    struct MemberNode *next;
    struct MemberNode *hash_next;
} MemberNode;

typedef struct FellowshipSystem {
    MemberNode   *head;
    MemberNode   *tail;

    MemberNode  **buckets;
    size_t        bucket_count;     /* always power of two */
    size_t        active_count;

    MemberNode   *avail_head;       /* stack pool */
    size_t        avail_count;

    UndoCommand   history[HISTORY_LIMIT];
    size_t        history_count;
} FellowshipSystem;

/******************************************************************************
 * Secure wiping helpers
 ******************************************************************************/

/*
 * Best-effort secure zeroing.
 *
 * A volatile pointer is used to make it harder for an optimizing compiler
 * to elide the writes. For formally certified environments, use memset_s(),
 * explicit_bzero(), or platform-specific secure memory APIs.
 */
static void secure_wipe(void *ptr, size_t len)
{
    if (ptr == NULL || len == 0u) {
        return;
    }

    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len-- > 0u) {
        *p++ = 0x00u;
    }
}

static void wipe_undo_command(UndoCommand *cmd)
{
    if (cmd == NULL) {
        return;
    }

    secure_wipe(cmd, sizeof(*cmd));
    cmd->type = ACTION_NONE;
    cmd->age  = 0;
}

/*
 * Wipe only member payload data, not linkage pointers.
 * This is mandatory before pushing a deleted node into AVAIL.
 */
static void wipe_node_payload(MemberNode *node)
{
    if (node == NULL) {
        return;
    }

    secure_wipe(node->name, sizeof(node->name));
    secure_wipe(node->race, sizeof(node->race));
    node->age = 0;

    node->name[0] = '\0';
    node->race[0] = '\0';
}

/******************************************************************************
 * Small string/validation helpers
 ******************************************************************************/

static bool has_visible_text(const char *s, size_t max_len)
{
    if (s == NULL) {
        return false;
    }

    for (size_t i = 0u; i < max_len && s[i] != '\0'; ++i) {
        if (!isspace((unsigned char)s[i])) {
            return true;
        }
    }

    return false;
}

static bool copy_string(char *dst, size_t dst_size, const char *src)
{
    if (dst == NULL || dst_size == 0u || src == NULL) {
        return false;
    }

    size_t len = strnlen(src, dst_size);
    if (len == dst_size) {
        return false; /* no room for NUL terminator */
    }

    memcpy(dst, src, len);
    dst[len] = '\0';
    return true;
}

static bool valid_member_fields(const char *name, const char *race, int age)
{
    if (name == NULL || race == NULL) {
        return false;
    }

    size_t name_len = strnlen(name, MAX_NAME_LEN + 1u);
    if (name_len == 0u || name_len >= MAX_NAME_LEN) {
        return false;
    }

    size_t race_len = strnlen(race, MAX_RACE_LEN + 1u);
    if (race_len == 0u || race_len >= MAX_RACE_LEN) {
        return false;
    }

    if (!has_visible_text(name, MAX_NAME_LEN)) {
        return false;
    }

    if (!has_visible_text(race, MAX_RACE_LEN)) {
        return false;
    }

    if (age < MIN_AGE || age > MAX_AGE) {
        return false;
    }

    return true;
}

/******************************************************************************
 * Hash table
 *
 * Hash function:
 *   FNV-1a 64-bit.
 *   - Offset basis: 14695981039346656037
 *   - Prime:        1099511628211
 *
 * Bucket indexing:
 *   bucket_count is maintained as a power of two, so:
 *       index = fnv1a64(name) & (bucket_count - 1)
 *   avoids modulo division and remains fast.
 ******************************************************************************/

static uint64_t fnv1a64(const char *s)
{
    uint64_t hash = 14695981039346656037ULL;

    if (s == NULL) {
        return hash;
    }

    const unsigned char *p = (const unsigned char *)s;

    while (*p != '\0') {
        hash ^= (uint64_t)*p++;
        hash *= 1099511628211ULL;
    }

    return hash;
}

static size_t hash_index_count(size_t bucket_count, const char *name)
{
    if (bucket_count == 0u) {
        return 0u;
    }

    return (size_t)(fnv1a64(name) & (uint64_t)(bucket_count - 1u));
}

static size_t hash_index(const FellowshipSystem *sys, const char *name)
{
    if (sys == NULL || name == NULL || sys->bucket_count == 0u) {
        return 0u;
    }

    return hash_index_count(sys->bucket_count, name);
}

static MemberNode *hash_find(FellowshipSystem *sys, const char *name)
{
    if (sys == NULL || sys->buckets == NULL || name == NULL ||
        sys->bucket_count == 0u || name[0] == '\0') {
        return NULL;
    }

    size_t       idx = hash_index(sys, name);
    MemberNode  *cur = sys->buckets[idx];

    while (cur != NULL) {
        if (cur->name[0] != '\0' && strcmp(cur->name, name) == 0) {
            return cur;
        }
        cur = cur->hash_next;
    }

    return NULL;
}

static void hash_link(MemberNode **bucket_head, MemberNode *node)
{
    if (bucket_head == NULL || node == NULL) {
        return;
    }

    node->hash_next = *bucket_head;
    *bucket_head    = node;
}

static bool hash_resize(FellowshipSystem *sys, size_t new_count)
{
    if (sys == NULL) {
        return false;
    }

    if (new_count < DEFAULT_BUCKET_COUNT) {
        new_count = DEFAULT_BUCKET_COUNT;
    }

    /* Round up to next power of two. */
    size_t power = DEFAULT_BUCKET_COUNT;
    while (power < new_count) {
        if (power > SIZE_MAX / 2u) {
            return false;
        }
        power <<= 1u;
    }
    new_count = power;

    if (new_count == sys->bucket_count) {
        return true;
    }

    MemberNode **new_buckets = calloc(new_count, sizeof(*new_buckets));
    if (new_buckets == NULL) {
        return false;
    }

    /* Rehash only active DLL nodes. AVAIL nodes are not indexed. */
    MemberNode *cur = sys->head;
    while (cur != NULL) {
        MemberNode *next_dll = cur->next;

        cur->hash_next = NULL;
        size_t idx = hash_index_count(new_count, cur->name);
        hash_link(&new_buckets[idx], cur);

        cur = next_dll;
    }

    if (sys->buckets != NULL) {
        secure_wipe(sys->buckets,
                    sys->bucket_count * sizeof(*sys->buckets));
        free(sys->buckets);
    }

    sys->buckets      = new_buckets;
    sys->bucket_count = new_count;

    return true;
}

static bool hash_prepare_for_insert(FellowshipSystem *sys,
                                    size_t prospective_count)
{
    if (sys == NULL || sys->bucket_count == 0u) {
        return false;
    }

    /* Grow when load factor would exceed 0.75. */
    size_t threshold = (sys->bucket_count / 4u) * 3u;

    if (prospective_count > threshold) {
        if (sys->bucket_count > SIZE_MAX / 2u) {
            return false;
        }
        return hash_resize(sys, sys->bucket_count * 2u);
    }

    return true;
}

/*
 * Removes a node from hash chain only.
 * Uses a strictly typed double pointer to splice the chain safely.
 */
static bool hash_remove(FellowshipSystem *sys, const char *name)
{
    if (sys == NULL || sys->buckets == NULL || name == NULL ||
        sys->bucket_count == 0u || name[0] == '\0') {
        return false;
    }

    size_t        idx = hash_index(sys, name);
    MemberNode  **cur = &sys->buckets[idx];

    while (cur != NULL && *cur != NULL) {
        MemberNode *candidate = *cur;

        if (candidate->name[0] != '\0' &&
            strcmp(candidate->name, name) == 0) {
            *cur = candidate->hash_next;
            candidate->hash_next = NULL;
            return true;
        }

        cur = &candidate->hash_next;
    }

    return false;
}

/******************************************************************************
 * AVAIL stack pool
 ******************************************************************************/

static MemberNode *pop_avail(FellowshipSystem *sys)
{
    if (sys == NULL || sys->avail_head == NULL) {
        return NULL;
    }

    MemberNode *node = sys->avail_head;
    sys->avail_head  = node->next;

    if (sys->avail_count > 0u) {
        sys->avail_count--;
    }

    node->prev       = NULL;
    node->next       = NULL;
    node->hash_next  = NULL;
    node->name[0]    = '\0';
    node->race[0]    = '\0';
    node->age        = 0;

    return node;
}

/*
 * Push deleted node into AVAIL pool.
 * The payload must be securely wiped before the node is recycled.
 */
static void push_avail(FellowshipSystem *sys, MemberNode *node)
{
    if (sys == NULL || node == NULL) {
        return;
    }

    wipe_node_payload(node);

    node->prev      = NULL;
    node->hash_next = NULL;
    node->next      = sys->avail_head;

    sys->avail_head = node;
    sys->avail_count++;
}

static MemberNode *allocate_node(FellowshipSystem *sys)
{
    if (sys == NULL) {
        return NULL;
    }

    MemberNode *node = pop_avail(sys);
    if (node != NULL) {
        return node;
    }

    node = calloc(1, sizeof(*node));
    return node;
}

/******************************************************************************
 * Doubly linked list: ordered by name
 ******************************************************************************/

/*
 * Inserts into DLL using a typed double pointer to the "next" link.
 * This avoids special-casing head insertion.
 */
static bool list_insert_sorted(FellowshipSystem *sys, MemberNode *node)
{
    if (sys == NULL || node == NULL || node->name[0] == '\0') {
        return false;
    }

    MemberNode **link = &sys->head;
    MemberNode  *prev = NULL;

    while (*link != NULL && strcmp(node->name, (*link)->name) > 0) {
        prev = *link;
        link = &(*link)->next;
    }

    node->prev = prev;
    node->next = *link;

    if (*link != NULL) {
        (*link)->prev = node;
    } else {
        sys->tail = node;
    }

    *link = node;
    sys->active_count++;

    return true;
}

static void list_unlink(FellowshipSystem *sys, MemberNode *node)
{
    if (sys == NULL || node == NULL) {
        return;
    }

    if (node->prev != NULL) {
        node->prev->next = node->next;
    } else {
        sys->head = node->next;
    }

    if (node->next != NULL) {
        node->next->prev = node->prev;
    } else {
        sys->tail = node->prev;
    }

    node->prev = NULL;
    node->next = NULL;

    if (sys->active_count > 0u) {
        sys->active_count--;
    }
}

/******************************************************************************
 * Undo history stack
 ******************************************************************************/

static void history_make_room(FellowshipSystem *sys)
{
    if (sys == NULL) {
        return;
    }

    if (sys->history_count < HISTORY_LIMIT) {
        return;
    }

    /* Discard oldest command securely. */
    wipe_undo_command(&sys->history[0]);

    for (size_t i = 0u; i + 1u < HISTORY_LIMIT; ++i) {
        sys->history[i] = sys->history[i + 1u];
    }

    sys->history_count = HISTORY_LIMIT - 1u;

    /* The last slot now contains duplicate/moved data; wipe it. */
    wipe_undo_command(&sys->history[HISTORY_LIMIT - 1u]);
}

static void push_history_add(FellowshipSystem *sys, const char *name)
{
    if (sys == NULL || name == NULL) {
        return;
    }

    history_make_room(sys);

    UndoCommand *cmd = &sys->history[sys->history_count];

    cmd->type = ACTION_ADD;

    if (!copy_string(cmd->name, sizeof(cmd->name), name)) {
        cmd->name[0] = '\0';
    }

    cmd->race[0] = '\0';
    cmd->age     = 0;

    sys->history_count++;
}

static void push_history_remove(FellowshipSystem *sys, const MemberNode *node)
{
    if (sys == NULL || node == NULL) {
        return;
    }

    history_make_room(sys);

    UndoCommand *cmd = &sys->history[sys->history_count];

    cmd->type = ACTION_REMOVE;

    if (!copy_string(cmd->name, sizeof(cmd->name), node->name)) {
        cmd->name[0] = '\0';
    }

    if (!copy_string(cmd->race, sizeof(cmd->race), node->race)) {
        cmd->race[0] = '\0';
    }

    cmd->age = node->age;

    sys->history_count++;
}

static void clear_history(FellowshipSystem *sys)
{
    if (sys == NULL) {
        return;
    }

    for (size_t i = 0u; i < HISTORY_LIMIT; ++i) {
        wipe_undo_command(&sys->history[i]);
    }

    sys->history_count = 0u;
}

/******************************************************************************
 * Core member operations
 ******************************************************************************/

static bool add_member(FellowshipSystem *sys,
                       const char *name,
                       const char *race,
                       int age,
                       bool record_undo)
{
    if (sys == NULL || !valid_member_fields(name, race, age)) {
        return false;
    }

    if (sys->active_count >= SIZE_MAX) {
        return false;
    }

    /* O(1) duplicate check. */
    if (hash_find(sys, name) != NULL) {
        return false;
    }

    /* Grow hash table before insertion if needed. */
    if (!hash_prepare_for_insert(sys, sys->active_count + 1u)) {
        return false;
    }

    MemberNode *node = allocate_node(sys);
    if (node == NULL) {
        return false;
    }

    if (!copy_string(node->name, sizeof(node->name), name) ||
        !copy_string(node->race, sizeof(node->race), race)) {
        push_avail(sys, node);
        return false;
    }

    node->age = age;

    /* DLL insertion is O(N) because order must be maintained. */
    if (!list_insert_sorted(sys, node)) {
        push_avail(sys, node);
        return false;
    }

    size_t idx = hash_index(sys, node->name);
    hash_link(&sys->buckets[idx], node);

    if (record_undo) {
        push_history_add(sys, node->name);
    }

    return true;
}

static bool remove_member(FellowshipSystem *sys,
                          const char *name,
                          bool record_undo)
{
    if (sys == NULL || name == NULL || name[0] == '\0') {
        return false;
    }

    /* O(1) existence lookup. */
    MemberNode *node = hash_find(sys, name);
    if (node == NULL) {
        return false;
    }

    /*
     * Remove from hash first. If this fails, the system is inconsistent,
     * and we do not proceed.
     */
    if (!hash_remove(sys, name)) {
        return false;
    }

    if (record_undo) {
        push_history_remove(sys, node);
    }

    list_unlink(sys, node);

    /* Node is wiped and recycled, not freed. */
    push_avail(sys, node);

    return true;
}

static bool undo_last(FellowshipSystem *sys)
{
    if (sys == NULL || sys->history_count == 0u) {
        return false;
    }

    sys->history_count--;

    UndoCommand *cmd = &sys->history[sys->history_count];
    bool ok = false;

    if (cmd->type == ACTION_ADD) {
        /*
         * Undo Add => Remove that member.
         * If the member is already gone, treat undo as completed.
         */
        MemberNode *existing = hash_find(sys, cmd->name);
        if (existing != NULL) {
            ok = remove_member(sys, cmd->name, false);
        } else {
            ok = true;
        }
    } else if (cmd->type == ACTION_REMOVE) {
        /*
         * Undo Remove => re-insert member.
         *
         * Because the original node was securely wiped in AVAIL,
         * restoration uses the command's protected copy and recycles
         * an AVAIL node when available.
         */
        MemberNode *existing = hash_find(sys, cmd->name);
        if (existing != NULL) {
            /*
             * A member with the same name already exists.
             * Do not overwrite current data silently.
             */
            ok = true;
        } else {
            ok = add_member(sys, cmd->name, cmd->race, cmd->age, false);
        }
    } else {
        ok = false;
    }

    wipe_undo_command(cmd);
    return ok;
}

/******************************************************************************
 * System lifecycle / teardown
 ******************************************************************************/

static bool init_system(FellowshipSystem *sys, size_t bucket_count)
{
    if (sys == NULL) {
        return false;
    }

    memset(sys, 0, sizeof(*sys));

    size_t power = DEFAULT_BUCKET_COUNT;

    if (bucket_count < power) {
        bucket_count = power;
    }

    while (power < bucket_count) {
        if (power > SIZE_MAX / 2u) {
            return false;
        }
        power <<= 1u;
    }

    sys->bucket_count = power;
    sys->buckets = calloc(power, sizeof(*sys->buckets));

    if (sys->buckets == NULL) {
        sys->bucket_count = 0u;
        return false;
    }

    return true;
}

/*
 * Move all active nodes to AVAIL and clear hash buckets.
 * This does not free memory; it recycles nodes.
 */
static void clear_active_to_avail(FellowshipSystem *sys)
{
    if (sys == NULL) {
        return;
    }

    if (sys->buckets != NULL && sys->bucket_count > 0u) {
        memset(sys->buckets, 0,
               sys->bucket_count * sizeof(*sys->buckets));
    }

    MemberNode *cur = sys->head;

    while (cur != NULL) {
        MemberNode *next_dll = cur->next;

        cur->hash_next = NULL;
        push_avail(sys, cur);

        cur = next_dll;
    }

    sys->head         = NULL;
    sys->tail         = NULL;
    sys->active_count = 0u;
}

static void clear_state(FellowshipSystem *sys)
{
    if (sys == NULL) {
        return;
    }

    clear_history(sys);
    clear_active_to_avail(sys);
}

/*
 * Full teardown.
 * Frees active DLL nodes, AVAIL pool nodes, and hash buckets.
 * Intended to leave no leaks under Valgrind/ASan.
 */
static void destroy_system(FellowshipSystem *sys)
{
    if (sys == NULL) {
        return;
    }

    clear_history(sys);

    /* Free active nodes directly. */
    MemberNode *cur = sys->head;
    while (cur != NULL) {
        MemberNode *next_dll = cur->next;

        secure_wipe(cur, sizeof(*cur));
        free(cur);

        cur = next_dll;
    }

    sys->head         = NULL;
    sys->tail         = NULL;
    sys->active_count = 0u;

    /* Free AVAIL pool nodes. */
    cur = sys->avail_head;
    while (cur != NULL) {
        MemberNode *next_avail = cur->next;

        secure_wipe(cur, sizeof(*cur));
        free(cur);

        cur = next_avail;
    }

    sys->avail_head  = NULL;
    sys->avail_count = 0u;

    /* Free hash table bucket array. */
    if (sys->buckets != NULL) {
        secure_wipe(sys->buckets,
                    sys->bucket_count * sizeof(*sys->buckets));
        free(sys->buckets);
        sys->buckets = NULL;
    }

    sys->bucket_count = 0u;

    /* Final defensive wipe of control block. */
    secure_wipe(sys, sizeof(*sys));
}

/******************************************************************************
 * CRC32 and little-endian binary helpers
 ******************************************************************************/

/*
 * Standard reflected CRC32:
 *   polynomial 0xEDB88320
 *   init       0xFFFFFFFF
 *   final xor  0xFFFFFFFF
 */
static uint32_t crc32_bytes(const unsigned char *data, size_t len)
{
    if (data == NULL || len == 0u) {
        return 0u;
    }

    uint32_t crc = 0xFFFFFFFFu;

    for (size_t i = 0u; i < len; ++i) {
        crc ^= data[i];

        for (int bit = 0; bit < 8; ++bit) {
            uint32_t mask = 0u - (crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }

    return crc ^ 0xFFFFFFFFu;
}

static void put_u32_le(unsigned char *buf, uint32_t value)
{
    if (buf == NULL) {
        return;
    }

    buf[0] = (unsigned char)(value & 0xFFu);
    buf[1] = (unsigned char)((value >> 8u) & 0xFFu);
    buf[2] = (unsigned char)((value >> 16u) & 0xFFu);
    buf[3] = (unsigned char)((value >> 24u) & 0xFFu);
}

static uint32_t get_u32_le(const unsigned char *buf)
{
    if (buf == NULL) {
        return 0u;
    }

    return (uint32_t)buf[0] |
           ((uint32_t)buf[1] << 8u) |
           ((uint32_t)buf[2] << 16u) |
           ((uint32_t)buf[3] << 24u);
}

/******************************************************************************
 * Binary persistence
 ******************************************************************************/

static bool save_fellowship(const FellowshipSystem *sys, const char *path)
{
    if (sys == NULL || path == NULL) {
        return false;
    }

    #if SIZE_MAX > UINT32_MAX   /* dead (and -Wtype-limits noisy) on 32-bit size_t */
    if (sys->active_count > UINT32_MAX) {
        return false;
    }
#endif

    uint32_t count = (uint32_t)sys->active_count;

    /*
     * Portable size_t overflow guard.
     *
     * The naive test `count > SIZE_MAX / RECORD_BYTES` compares a uint32_t
     * against ~9.4e16 on LP64, which is tautologically false and trips
     * -Wtype-limits. Instead: multiply first, then verify with a division
     * round-trip. If (size_t)count * RECORD_BYTES wrapped modulo 2^N, the
     * wrapped value w satisfies w < count * RECORD_BYTES, hence
     * w / RECORD_BYTES < count, so the mismatch is detected exactly.
     * No tautological comparison on either 32-bit or 64-bit size_t.
     */
    const size_t count_sz    = (size_t)count;
    const size_t payload_len = count_sz * RECORD_BYTES;

    if (payload_len / RECORD_BYTES != count_sz) {
        return false;   /* size_t multiplication overflowed */
    }
    unsigned char *payload = NULL;

    if (payload_len > 0u) {
        payload = malloc(payload_len);
        if (payload == NULL) {
            return false;
        }
    }

    size_t off = 0u;

    for (const MemberNode *cur = sys->head;
         cur != NULL;
         cur = cur->next) {
        if (off + RECORD_BYTES > payload_len) {
            secure_wipe(payload, payload_len);
            free(payload);
            return false;
        }

        memcpy(payload + off, cur->name, MAX_NAME_LEN);
        off += MAX_NAME_LEN;

        memcpy(payload + off, cur->race, MAX_RACE_LEN);
        off += MAX_RACE_LEN;

        put_u32_le(payload + off, (uint32_t)cur->age);
        off += AGE_BYTES;
    }

    if (off != payload_len) {
        if (payload != NULL) {
            secure_wipe(payload, payload_len);
            free(payload);
        }
        return false;
    }

    uint32_t crc = crc32_bytes(payload, payload_len);

    unsigned char header[HEADER_BYTES];
    put_u32_le(header + 0u, FILE_MAGIC);
    put_u32_le(header + 4u, FILE_VERSION);
    put_u32_le(header + 8u, count);
    put_u32_le(header + 12u, crc);

    FILE *fp = fopen(path, "wb");
    if (fp == NULL) {
        if (payload != NULL) {
            secure_wipe(payload, payload_len);
            free(payload);
        }
        return false;
    }

    bool ok = (fwrite(header, 1u, sizeof(header), fp) == sizeof(header));

    if (ok && payload_len > 0u) {
        ok = (fwrite(payload, 1u, payload_len, fp) == payload_len);
    }

    if (fflush(fp) != 0) {
        ok = false;
    }

    if (ferror(fp)) {
        ok = false;
    }

    fclose(fp);

    if (payload != NULL) {
        secure_wipe(payload, payload_len);
        free(payload);
    }

    return ok;
}

static bool payload_appears_valid(const unsigned char *payload, size_t count)
{
    if (count > 0u && payload == NULL) {
        return false;
    }

    size_t off = 0u;

    char prev_name[MAX_NAME_LEN];
    bool has_prev = false;

    for (size_t i = 0u; i < count; ++i) {
        if (off + RECORD_BYTES > count * RECORD_BYTES) {
            return false;
        }

        const char *name = (const char *)(payload + off);
        const char *race = (const char *)(payload + off + MAX_NAME_LEN);

        if (memchr(name, 0, MAX_NAME_LEN) == NULL) {
            return false;
        }

        if (memchr(race, 0, MAX_RACE_LEN) == NULL) {
            return false;
        }

        if (!has_visible_text(name, MAX_NAME_LEN)) {
            return false;
        }

        if (!has_visible_text(race, MAX_RACE_LEN)) {
            return false;
        }

        uint32_t age = get_u32_le(payload + off + MAX_NAME_LEN + MAX_RACE_LEN);
        if (age > (uint32_t)MAX_AGE) {
            return false;
        }

        /*
         * Saved files are ordered, so duplicate names should be adjacent.
         * This is a cheap integrity/semantic check, not a full uniqueness proof.
         */
        if (has_prev && strcmp(prev_name, name) == 0) {
            return false;
        }

        memcpy(prev_name, name, MAX_NAME_LEN);
        prev_name[MAX_NAME_LEN - 1u] = '\0';
        has_prev = true;

        off += RECORD_BYTES;
    }

    return true;
}

static bool load_fellowship(FellowshipSystem *sys, const char *path)
{
    if (sys == NULL || path == NULL) {
        return false;
    }

    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        return false;
    }

    unsigned char header[HEADER_BYTES];

    if (fread(header, 1u, sizeof(header), fp) != sizeof(header)) {
        fclose(fp);
        return false;
    }

    uint32_t magic   = get_u32_le(header + 0u);
    uint32_t version = get_u32_le(header + 4u);
    uint32_t count32 = get_u32_le(header + 8u);
    uint32_t crc_expected = get_u32_le(header + 12u);

    if (magic != FILE_MAGIC || version != FILE_VERSION) {
        fclose(fp);
        return false;
    }

    if (count32 > MAX_LOAD_COUNT) {
        fclose(fp);
        return false;
    }

    size_t count = (size_t)count32;

    if (count > 0u && count > SIZE_MAX / RECORD_BYTES) {
        fclose(fp);
        return false;
    }

    size_t payload_len = count * RECORD_BYTES;
    unsigned char *payload = NULL;

    if (payload_len > 0u) {
        payload = malloc(payload_len);
        if (payload == NULL) {
            fclose(fp);
            return false;
        }

        if (fread(payload, 1u, payload_len, fp) != payload_len) {
            secure_wipe(payload, payload_len);
            free(payload);
            fclose(fp);
            return false;
        }
    }

    fclose(fp);

    /*
     * Verify integrity BEFORE modifying current system state.
     */
    uint32_t crc_actual = crc32_bytes(payload, payload_len);
    if (crc_actual != crc_expected) {
        if (payload != NULL) {
            secure_wipe(payload, payload_len);
            free(payload);
        }
        return false;
    }

    if (!payload_appears_valid(payload, count)) {
        if (payload != NULL) {
            secure_wipe(payload, payload_len);
            free(payload);
        }
        return false;
    }

    /* Verified: now replace current state. */
    clear_state(sys);

    /*
     * Optional pre-growth for load performance.
     * Failure here is non-fatal; insertion will still try to grow as needed.
     */
    if (count > 0u) {
        size_t target = (count > SIZE_MAX / 2u) ? count : (count * 2u);
        (void)hash_resize(sys, target);
    }

    bool ok = true;
    size_t off = 0u;

    for (size_t i = 0u; i < count; ++i) {
        if (off + RECORD_BYTES > payload_len) {
            ok = false;
            break;
        }

        char name[MAX_NAME_LEN];
        char race[MAX_RACE_LEN];

        memcpy(name, payload + off, MAX_NAME_LEN);
        name[MAX_NAME_LEN - 1u] = '\0';
        off += MAX_NAME_LEN;

        memcpy(race, payload + off, MAX_RACE_LEN);
        race[MAX_RACE_LEN - 1u] = '\0';
        off += MAX_RACE_LEN;

        uint32_t age32 = get_u32_le(payload + off);
        off += AGE_BYTES;

        if (!add_member(sys, name, race, (int)age32, false)) {
            ok = false;
            break;
        }
    }

    if (off != payload_len) {
        ok = false;
    }

    if (payload != NULL) {
        secure_wipe(payload, payload_len);
        free(payload);
    }

    /*
     * If a semantically invalid record slipped through and insertion failed,
     * clear partial state rather than leaving a partially loaded fellowship.
     */
    if (!ok) {
        clear_state(sys);
    }

    return ok;
}

/******************************************************************************
 * Safe console I/O
 ******************************************************************************/

/*
 * Safe line reader.
 * - No scanf("%s")
 * - fgets() bounded read
 * - detects and discards overly long lines
 * - trims leading/trailing whitespace
 */
static bool read_line(const char *prompt, char *out, size_t out_size)
{
    if (out == NULL || out_size == 0u) {
        return false;
    }

    if (prompt != NULL && prompt[0] != '\0') {
        fputs(prompt, stdout);
    }

    fflush(stdout);

    if (fgets(out, (int)out_size, stdin) == NULL) {
        return false;
    }

    size_t len = strlen(out);
    bool had_newline = (len > 0u && out[len - 1u] == '\n');

    if (had_newline) {
        out[len - 1u] = '\0';
    } else {
        /* Line was too large for buffer: consume the remainder. */
        int c;
        while ((c = getchar()) != '\n' && c != EOF) {
            /* discard */
        }
    }

    /* Trim leading whitespace. */
    char *start = out;
    while (*start != '\0' && isspace((unsigned char)*start)) {
        start++;
    }

    /* Trim trailing whitespace. */
    char *end = start + strlen(start);
    while (end > start && isspace((unsigned char)end[-1])) {
        end--;
    }

    *end = '\0';

    size_t trimmed_len = (size_t)(end - start);
    memmove(out, start, trimmed_len + 1u);

    return true;
}

static bool parse_age(const char *text, int *out)
{
    if (text == NULL || out == NULL || text[0] == '\0') {
        return false;
    }

    char *end = NULL;

    errno = 0;
    long value = strtol(text, &end, 10);

    if (errno != 0 || end == text || *end != '\0') {
        return false;
    }

    if (value < MIN_AGE || value > MAX_AGE) {
        return false;
    }

    *out = (int)value;
    return true;
}

static void print_member(const MemberNode *node)
{
    if (node == NULL) {
        return;
    }

    printf("Name: %s | Race: %s | Age: %d\n",
           node->name,
           node->race,
           node->age);
}

static void list_members(const FellowshipSystem *sys)
{
    if (sys == NULL) {
        return;
    }

    if (sys->active_count == 0u) {
        puts("Fellowship is empty.");
    } else {
        size_t index = 0u;

        for (const MemberNode *cur = sys->head;
             cur != NULL;
             cur = cur->next) {
            printf("%3zu. ", ++index);
            print_member(cur);
        }
    }

    printf("Active: %zu | Recycled pool: %zu | Undo depth: %zu\n",
           sys->active_count,
           sys->avail_count,
           sys->history_count);
}

static void print_menu(void)
{
    puts("\n=== ADVANCED FELLOWSHIP MANAGEMENT SYSTEM ===");
    puts("1. Add member");
    puts("2. Remove member");
    puts("3. List members (ordered DLL)");
    puts("4. Search member (O(1) hash lookup)");
    puts("5. Undo last action");
    puts("6. Save binary (fellowship.dat)");
    puts("7. Load binary (fellowship.dat)");
    puts("0. Exit");
    printf("Choice: ");
}

/******************************************************************************
 * Main
 ******************************************************************************/

int main(void)
{
    FellowshipSystem sys;

    if (!init_system(&sys, DEFAULT_BUCKET_COUNT)) {
        fprintf(stderr, "Fatal: failed to initialize fellowship system.\n");
        return EXIT_FAILURE;
    }

    /*
     * Optional startup persistence load.
     * If a saved file exists, validate it before deserializing.
     */
    FILE *probe = fopen(FELLOWSHIP_FILE, "rb");
    if (probe != NULL) {
        fclose(probe);

        if (load_fellowship(&sys, FELLOWSHIP_FILE)) {
            printf("[startup] Loaded saved fellowship from %s.\n",
                   FELLOWSHIP_FILE);
        } else {
            printf("[startup] %s exists but failed validation/load; "
                   "starting empty.\n",
                   FELLOWSHIP_FILE);
        }
    }

    bool running = true;

    while (running) {
        print_menu();

        char choice[INPUT_LEN];

        if (!read_line(NULL, choice, sizeof(choice))) {
            break; /* EOF */
        }

        if (choice[0] == '\0') {
            continue;
        }

        if (choice[1] != '\0') {
            puts("Invalid choice. Enter a single option digit.");
            continue;
        }

        switch (choice[0]) {
            case '1': {
                char name[INPUT_LEN];
                char race[INPUT_LEN];
                char age_text[INPUT_LEN];

                if (!read_line("Name: ", name, sizeof(name))) {
                    running = false;
                    break;
                }

                if (name[0] == '\0') {
                    puts("Name cannot be empty.");
                    break;
                }

                if (!read_line("Race: ", race, sizeof(race))) {
                    running = false;
                    break;
                }

                if (race[0] == '\0') {
                    puts("Race cannot be empty.");
                    break;
                }

                if (!read_line("Age: ", age_text, sizeof(age_text))) {
                    running = false;
                    break;
                }

                int age = 0;
                if (!parse_age(age_text, &age)) {
                    printf("Invalid age. Use an integer %d..%d.\n",
                           MIN_AGE, MAX_AGE);
                    break;
                }

                if (add_member(&sys, name, race, age, true)) {
                    printf("Added: %s\n", name);
                } else {
                    printf("Failed to add '%s'. It may already exist or "
                           "field lengths are invalid.\n", name);
                }

                break;
            }

            case '2': {
                char name[INPUT_LEN];

                if (!read_line("Name to remove: ", name, sizeof(name))) {
                    running = false;
                    break;
                }

                if (name[0] == '\0') {
                    puts("Name cannot be empty.");
                    break;
                }

                if (remove_member(&sys, name, true)) {
                    printf("Removed: %s\n", name);
                } else {
                    printf("Member not found: %s\n", name);
                }

                break;
            }

            case '3': {
                list_members(&sys);
                break;
            }

            case '4': {
                char name[INPUT_LEN];

                if (!read_line("Name to search: ", name, sizeof(name))) {
                    running = false;
                    break;
                }

                if (name[0] == '\0') {
                    puts("Name cannot be empty.");
                    break;
                }

                MemberNode *found = hash_find(&sys, name);

                if (found != NULL) {
                    print_member(found);
                } else {
                    printf("Member not found: %s\n", name);
                }

                break;
            }

            case '5': {
                if (undo_last(&sys)) {
                    puts("Undo completed.");
                } else {
                    puts("Nothing to undo, or undo could not be applied.");
                }
                break;
            }

            case '6': {
                if (save_fellowship(&sys, FELLOWSHIP_FILE)) {
                    printf("Saved active fellowship to %s.\n",
                           FELLOWSHIP_FILE);
                } else {
                    printf("Failed to save %s.\n", FELLOWSHIP_FILE);
                }
                break;
            }

            case '7': {
                if (load_fellowship(&sys, FELLOWSHIP_FILE)) {
                    printf("Loaded fellowship from %s.\n",
                           FELLOWSHIP_FILE);
                } else {
                    printf("Failed to load %s. File missing, corrupted, "
                           "or failed integrity validation.\n",
                           FELLOWSHIP_FILE);
                }
                break;
            }

            case '0': {
                running = false;
                break;
            }

            default: {
                puts("Invalid option.");
                break;
            }
        }
    }

    destroy_system(&sys);
    return EXIT_SUCCESS;
}
