#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <string.h>

#include <assert.h>

#include <arpa/inet.h>
#include <sys/time.h>

#include <tox/toxencryptsave.h>

#include "toxtore.h"

#define sqlite3_queryf toxtore_util_sqlite3_queryf

// #define TOXTORE_MUCHDEBUG


#define TOXTORE_TOX_PACKET_ID           170     // TODO standardize this?

#define TOXTORE_PACKET_MY_DEVICES       1
#define TOXTORE_PACKET_VECTOR_CLOCK     2
#define TOXTORE_PACKET_SEND_DOT         3

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
static inline uint64_t htonll(uint64_t x) {
    return ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32);
}
static inline uint64_t ntohll(uint64_t x) {
    return ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32);
}
#else
static inline uint64_t htonll(uint64_t x) { return x; }
static inline uint64_t ntohll(uint64_t x) { return x; }
#endif

typedef struct Sending_Message {
    struct Sending_Message *next;
    uint32_t tox_number;
    Dot dot;
} Sending_Message;

typedef struct First_Missing_Dot {
    uint8_t device_pk[TOX_PUBLIC_KEY_SIZE];
    uint64_t sn;
    struct First_Missing_Dot *next;
} First_Missing_Dot;

typedef struct Active_Device {
    struct Active_Device *next;
    uint8_t pk[TOX_PUBLIC_KEY_SIZE];
    uint32_t tox_friend_no;
    First_Missing_Dot *missing;
    bool is_reciprocal;
} Active_Device;

struct Toxtore {
    Tox* tox;
    void* user_data;

    size_t passphrase_len;
    uint8_t* passphrase;

    char* tox_save_path;
    char* tox_tmp_save_path;
    char* db_path;


    sqlite3 *db;

    Sending_Message *sending;
    Active_Device *devices;

    toxtore_friend_request_cb *friend_request_cb;
    toxtore_friend_message_cb *friend_message_cb;
    toxtore_conference_message_cb * conference_message_cb;
    toxtore_friend_read_receipt_cb *friend_read_receipt_cb;
    toxtore_friend_connection_status_cb *friend_connection_status_cb;
    toxtore_device_add_request_cb *device_add_request_cb;
};

void toxtore_friend_request_handler(Tox* tox,
                                    const uint8_t *public_key,
                                    const uint8_t *message,
                                    size_t length,
                                    void* user_data);
void toxtore_friend_message_handler(Tox* tox,
                                    uint32_t friend_number,
                                    TOX_MESSAGE_TYPE type,
                                    const uint8_t *message,
                                    size_t length,
                                    void* user_data);
void toxtore_conference_message_handler(Tox* tox,
                                        uint32_t conference_number,
                                        uint32_t peer_number,
                                        TOX_MESSAGE_TYPE type,
                                        const uint8_t *message,
                                        size_t length,
                                        void* user_data);
void toxtore_friend_read_receipt_handler(Tox* tox,
                                         uint32_t friend_number,
                                         uint32_t message_id,
                                         void* user_data);
void toxtore_friend_connection_status_handler(Tox *tox,
                                              uint32_t friend_number,
                                              TOX_CONNECTION connection_status,
                                              void* user_data);
void toxtore_friend_lossless_packet_handler(Tox* tox,
                                            uint32_t friend_number,
                                            const uint8_t *data,
                                            size_t length,
                                            void* user_data);


// -------------------------
// Helpers

// Sort array of public keys
int _toxtore_pk_memcmp(const void* a, const void* b) {
    return memcmp(a, b, TOX_PUBLIC_KEY_SIZE);
}
void toxtore_sort_pk_array(size_t n_pk, uint8_t *pks) {
    qsort(pks, n_pk, TOX_PUBLIC_KEY_SIZE, &_toxtore_pk_memcmp);
}

// ------------------------
// SERIALIZATION TO PACKETS

typedef union Packet_Ptr {
    uint8_t *u8;
    uint16_t *u16;
    uint32_t *u32;
    uint64_t *u64;
    struct {
        uint8_t bytes[TOX_PUBLIC_KEY_SIZE];
    } *pk;
    struct {
        uint8_t bytes[TOX_CONFERENCE_ID_SIZE];
    } *conf_id;
} Packet_Ptr;

size_t toxtore_make_packet_my_devices(Toxtore* tt, uint8_t **out)
{
    uint8_t n_devices = 0;
    for (Active_Device *p = tt->devices; p != NULL; n_devices++, p = p->next);

    size_t pkt_len = 3 + n_devices * TOX_PUBLIC_KEY_SIZE;
    *out = malloc(pkt_len);
    if (*out == NULL) return 0;

    Packet_Ptr pw = { .u8 = *out };
    *(pw.u8++) = TOXTORE_TOX_PACKET_ID;
    *(pw.u8++) = TOXTORE_PACKET_MY_DEVICES;
    *(pw.u8++) = n_devices;

    for (Active_Device *p = tt->devices; p != NULL; p = p->next) {
        memcpy(pw.pk++, p->pk, TOX_PUBLIC_KEY_SIZE);
    }

    assert(pw.u8 - *out == pkt_len);
    return pkt_len;
}

size_t toxtore_make_packet_vector_clock(Toxtore* tt, uint8_t **out)
{
    sqlite3_stmt *stmt;
    int res = sqlite3_queryf(tt->db, &stmt, "SELECT COUNT(*) FROM devices WHERE removed = 0;");
    if (res != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return 0;
    }
    uint8_t n_devices = sqlite3_column_int(stmt, 0) + 1;
    sqlite3_finalize(stmt);

    size_t pkt_len = 3 + n_devices * (TOX_PUBLIC_KEY_SIZE + 8);
    *out = malloc(pkt_len);
    if (*out == NULL) return 0;

    Packet_Ptr pw = { .u8 = *out };

    *pw.u8++ = TOXTORE_TOX_PACKET_ID;
    *pw.u8++ = TOXTORE_PACKET_VECTOR_CLOCK;
    *pw.u8++ = n_devices;

    uint8_t my_pk[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_public_key(tt->tox, my_pk);
    res = sqlite3_queryf(tt->db, &stmt,
        "SELECT MAX(seq_no) FROM events WHERE device = ?k", my_pk);
    if (res != SQLITE_ROW) {
        free(out);
        return 0;
    }
    memcpy(pw.pk++, my_pk, TOX_PUBLIC_KEY_SIZE);
    *pw.u64++ = htonll(sqlite3_column_int64(stmt, 0));
    sqlite3_finalize(stmt);

    res = sqlite3_queryf(tt->db, &stmt, "SELECT pk, got_until FROM devices WHERE removed = 0;");
    while (res == SQLITE_ROW) {
        memcpy(pw.pk++, sqlite3_column_blob(stmt, 0), TOX_PUBLIC_KEY_SIZE);
        *pw.u64++ = htonll(sqlite3_column_int64(stmt, 1));
        res = sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);

    assert(pw.u8 - *out == pkt_len);
    return pkt_len;
}

size_t toxtore_make_packet_send_dot(Toxtore* tt, Dot dot, uint8_t **out)
{
    sqlite3_stmt *stmt;
    int res = sqlite3_queryf(tt->db, &stmt,
                "SELECT timestamp, type, "
                    "arg_dot_dev, arg_dot_sn, arg_pk, arg_blob, arg_msg, arg_int, cache_flag "
                "FROM events WHERE device = ?k AND seq_no = ?I",
                dot.device_pk, dot.seq_no);
    if (res != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return 0;
    }

    size_t pkt_len = 2 + sizeof(Dot) + 1 + 8;   // header length

    int type = sqlite3_column_int(stmt, 1);
    switch (type) {
        case TOXTORE_EVENT_FRIEND_ADD:
            pkt_len += TOX_PUBLIC_KEY_SIZE + 1;
            break;
        case TOXTORE_EVENT_FRIEND_DEVICES:
            pkt_len += TOX_PUBLIC_KEY_SIZE + 2 + sqlite3_column_bytes(stmt, 5);
            break;
        case TOXTORE_EVENT_FRIEND_SEND:
        case TOXTORE_EVENT_FRIEND_RECV:
            pkt_len += TOX_PUBLIC_KEY_SIZE + 2 + 4 + sqlite3_column_bytes(stmt, 6);
            break;
        case TOXTORE_EVENT_CONFERENCE_SEND:
            pkt_len += TOX_CONFERENCE_ID_SIZE + 2 + 4 + sqlite3_column_bytes(stmt, 6);
            break;
        case TOXTORE_EVENT_CONFERENCE_RECV:
            pkt_len += TOX_PUBLIC_KEY_SIZE + TOX_CONFERENCE_ID_SIZE + 2 + 4 + sqlite3_column_bytes(stmt, 6);
            break;
        case TOXTORE_EVENT_FRIEND_DEL:
        case TOXTORE_EVENT_SEND_DONE:
        case TOXTORE_EVENT_MARK_READ:
            pkt_len += sizeof(Dot);
            break;
    }

    *out = malloc(pkt_len);
    if (*out == NULL) {
        sqlite3_finalize(stmt);
        return 0;
    }
    Packet_Ptr pw = { .u8 = *out };

    // Header
    *pw.u8++ = TOXTORE_TOX_PACKET_ID;                       // tox msg type
    *pw.u8++ = TOXTORE_PACKET_SEND_DOT;                     // toxtore send dot type
    memcpy(pw.pk++, dot.device_pk, TOX_PUBLIC_KEY_SIZE);    // dot dev
    *pw.u64++ = htonll(dot.seq_no);                         // dot seq no
    *pw.u8++ = type;                                        // event type
    *pw.u64++ = htonll(sqlite3_column_int64(stmt, 0));      // timestamp

    switch (type) {
        case TOXTORE_EVENT_FRIEND_ADD:
            if (sqlite3_column_bytes(stmt, 4) != TOX_PUBLIC_KEY_SIZE) goto error;
            memcpy(pw.pk++, sqlite3_column_blob(stmt, 4), TOX_PUBLIC_KEY_SIZE);     // friend pk
            *pw.u8++ = sqlite3_column_int(stmt, 8);                                 // removed?
            break;
        case TOXTORE_EVENT_FRIEND_DEVICES:
            if (sqlite3_column_bytes(stmt, 4) != TOX_PUBLIC_KEY_SIZE) goto error;
            memcpy(pw.pk++, sqlite3_column_blob(stmt, 4), TOX_PUBLIC_KEY_SIZE);     // pk
            *pw.u8++ = sqlite3_column_int(stmt, 8);                                 // obsolete?
            *pw.u8++ = (int)(sqlite3_column_bytes(stmt, 5) / TOX_PUBLIC_KEY_SIZE);  // ndevices
            memcpy(pw.u8, sqlite3_column_blob(stmt, 5), sqlite3_column_bytes(stmt, 5)); // devices
            pw.u8 += sqlite3_column_bytes(stmt, 5);
            break;
        case TOXTORE_EVENT_FRIEND_SEND:
        case TOXTORE_EVENT_FRIEND_RECV:
            if (sqlite3_column_bytes(stmt, 4) != TOX_PUBLIC_KEY_SIZE) goto error;
            memcpy(pw.pk++, sqlite3_column_blob(stmt, 4), TOX_PUBLIC_KEY_SIZE);     // who
            *pw.u8++ = sqlite3_column_int(stmt, 8);                                 // done send?
            *pw.u8++ = sqlite3_column_int(stmt, 7);                                 // arg_int msg type
            *pw.u32++ = htonl(sqlite3_column_bytes(stmt, 6));                       // msg len
            memcpy(pw.u8, sqlite3_column_text(stmt, 6), sqlite3_column_bytes(stmt, 6)); // msg
            pw.u8 += sqlite3_column_bytes(stmt, 6);
            break;
        case TOXTORE_EVENT_CONFERENCE_RECV:
            if (sqlite3_column_bytes(stmt, 4) != TOX_PUBLIC_KEY_SIZE) goto error;
            memcpy(pw.pk++, sqlite3_column_blob(stmt, 4), TOX_PUBLIC_KEY_SIZE);     // who
        case TOXTORE_EVENT_CONFERENCE_SEND:
            if (sqlite3_column_bytes(stmt, 5) != TOX_CONFERENCE_ID_SIZE) goto error;
            memcpy(pw.conf_id++, sqlite3_column_blob(stmt, 5), TOX_CONFERENCE_ID_SIZE); // conf id
            *pw.u8++ = sqlite3_column_int(stmt, 8);                                 // done send?
            *pw.u8++ = sqlite3_column_int(stmt, 7);                                 // arg_int msg type
            *pw.u32++ = htonl(sqlite3_column_bytes(stmt, 6));                       // msg len
            memcpy(pw.u8, sqlite3_column_text(stmt, 6), sqlite3_column_bytes(stmt, 6)); // msg
            pw.u8 += sqlite3_column_bytes(stmt, 6);
            break;
        case TOXTORE_EVENT_FRIEND_DEL:
        case TOXTORE_EVENT_SEND_DONE:
        case TOXTORE_EVENT_MARK_READ:
            if (sqlite3_column_bytes(stmt, 2) != TOX_PUBLIC_KEY_SIZE) goto error;
            memcpy(pw.pk++, sqlite3_column_blob(stmt, 2), TOX_PUBLIC_KEY_SIZE);
            *pw.u64++ = htonll(sqlite3_column_int64(stmt, 3));
            break;
    }

    sqlite3_finalize(stmt);
    assert(pw.u8 - *out == pkt_len);
    return pkt_len;

error:
    free(out);
    sqlite3_finalize(stmt);
    return 0;
}

// ----------------
// INTERNAL HELPERS

Dot toxtore_new_dot(Toxtore* tt)
{
    Dot d;
    tox_self_get_public_key(tt->tox, d.device_pk);
    sqlite3_stmt *stmt;
    int res = sqlite3_queryf(tt->db, &stmt, "SELECT MAX(seq_no) FROM events WHERE device = ?k", d.device_pk);
    if (res == SQLITE_ROW) {
        uint64_t i = sqlite3_column_int64(stmt, 0);
        d.seq_no = (i > 0 ? i+1 : 1);
    } else {
        fprintf(stderr, "Could not generate next sequence number\n");
        d.seq_no = 0;
    }
    sqlite3_finalize(stmt);
    return d;
}

uint64_t toxtore_new_timestamp(Toxtore* tt)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t time = tv.tv_sec * 1000 + tv.tv_usec / 1000;

    sqlite3_stmt *stmt;
    int res = sqlite3_queryf(tt->db, &stmt, "SELECT MAX(timestamp) FROM events");
    if (res == SQLITE_ROW) {
        uint64_t max_ts = sqlite3_column_int64(stmt, 0);
        if (max_ts > time) time = max_ts;
    }
    sqlite3_finalize(stmt);

    return time + 1;
}

void toxtore_sync_dot(Toxtore* tt, Dot d) {
    if (tt->devices == NULL) return;

    uint8_t *pkt;
    size_t pkt_len = toxtore_make_packet_send_dot(tt, d, &pkt);

    if (pkt_len == 0) {
        fprintf(stderr, "pkt_len=0 (could not build dot packet) in toxtore_sync_dot (%ld)\n", d.seq_no);
        return;
    }

    Active_Device *dev = tt->devices;
    while (dev != NULL) {
        if (dev->is_reciprocal) {
            TOX_ERR_FRIEND_BY_PUBLIC_KEY error;
            uint32_t friend_id = tox_friend_by_public_key(tt->tox, dev->pk, &error);
            if (error != TOX_ERR_FRIEND_BY_PUBLIC_KEY_OK) {
                friend_id = tox_friend_add_norequest(tt->tox, dev->pk, NULL);
            }
            tox_friend_send_lossless_packet(tt->tox, friend_id, pkt, pkt_len, NULL);
        }
        dev = dev->next;
    }
    free(pkt);
}

// --------------------
// Friend DB management

void toxtore_db_update_friends_table(Toxtore* tt, const uint8_t *pk, size_t n_devices, uint8_t *devices_pks)
{
    // Put in own new cluster
    sqlite3_stmt *stmt;
    uint64_t new_cluster;
    int res = sqlite3_queryf(tt->db, &stmt, "SELECT MAX(merged_id) FROM friends");
    if (res == SQLITE_ROW) {
        uint64_t i = sqlite3_column_int64(stmt, 0);
        new_cluster = (i > 0 ? i+1 : 1);
        sqlite3_finalize(stmt);
    } else {
        fprintf(stderr, "Could not generate new cluster id");
        sqlite3_finalize(stmt);
        return;
    }

    // Check that this pk is in the friends table
    res = sqlite3_queryf(tt->db, NULL,
        "INSERT OR REPLACE INTO friends(pk, other_pks, merged_id) VALUES(?k, ?B, ?I)",
        pk, devices_pks, n_devices * TOX_PUBLIC_KEY_SIZE, new_cluster);
    if (res != SQLITE_DONE) {
        fprintf(stderr, "Could not insert/update in friends table");
        return;
    }

    // If we have some devices, try to merge with the clusters of these devices
    if (n_devices > 0) {
        // 1. Extract list of unique clusters of other devices
        uint64_t *clusters = malloc(sizeof(uint64_t) * n_devices);
        int n_clusters = 0;
        int res = sqlite3_prepare_v2(tt->db, "SELECT merged_id FROM friends WHERE pk = ?", -1, &stmt, NULL);
        if (res != SQLITE_OK) {
            fprintf(stderr, "Prepare error line %d: %s\n", __LINE__, sqlite3_errmsg(tt->db));
            return;
        }
        for (int idev = 0; idev < n_devices; idev++) {
            sqlite3_bind_blob(stmt, 1, devices_pks + idev * TOX_PUBLIC_KEY_SIZE, TOX_PUBLIC_KEY_SIZE, SQLITE_TRANSIENT);
            res = sqlite3_step(stmt);
            if (res == SQLITE_ROW) {
                uint64_t cluster_id = sqlite3_column_int64(stmt, 0);
                bool exists = false;
                for (int jcl = 0; jcl < n_clusters; jcl++) {
                    if (clusters[jcl] == cluster_id) {
                        exists = true;
                        break;
                    }
                }
                if (!exists) clusters[n_clusters++] = cluster_id;
            } else {
                fprintf(stderr, "No device list found for idev=%d (%d %s)\n", idev, res, sqlite3_errmsg(tt->db));
            }
            sqlite3_reset(stmt);
            sqlite3_clear_bindings(stmt);
        }
        sqlite3_finalize(stmt);

        // 2. Try merge with each of them until one works
        for (int icl = 0; icl < n_clusters; icl++) {
            bool ok = true;
            int res = sqlite3_queryf(tt->db, &stmt,
                "SELECT pk, other_pks FROM friends WHERE merged_id = ?I",
                clusters[icl]);
            while (res == SQLITE_ROW) {
                const uint8_t *this_pk = sqlite3_column_blob(stmt, 0);
                const uint8_t *other_pks = sqlite3_column_blob(stmt, 1);
                size_t n_other_pks = sqlite3_column_bytes(stmt, 1) / TOX_PUBLIC_KEY_SIZE;
                bool found1 = false, found2 = false;
                for (int idev = 0; idev < n_devices; idev++) {
                    if (!memcmp(this_pk, devices_pks + idev * TOX_PUBLIC_KEY_SIZE, TOX_PUBLIC_KEY_SIZE)) {
                        found1 = true;
                        break;
                    }
                }
                for (int idev = 0; idev < n_other_pks; idev++) {
                    if (!memcmp(pk, other_pks + idev * TOX_PUBLIC_KEY_SIZE, TOX_PUBLIC_KEY_SIZE)) {
                        found2 = true;
                        break;
                    }
                }
                if (!found1 || !found2) {
                    ok = false;
                    break;
                }
                res = sqlite3_step(stmt);
            }
            sqlite3_finalize(stmt);

            // Found a cluster to merge, add here and stop :)
            if (ok) {
                sqlite3_queryf(tt->db, &stmt,
                    "UPDATE friends SET merged_id = ?i WHERE pk = ?k", 
                    (int32_t)clusters[icl], pk);
                return;
            }
        }
    }
}

void toxtore_db_ensure_friend(Toxtore* tt, const uint8_t *pk)
{
    int res = sqlite3_queryf(tt->db, NULL,
            "SELECT device, seq_no FROM events WHERE type = ?i AND arg_pk = ?k AND cache_flag = 0;", 
            TOXTORE_EVENT_FRIEND_ADD,
            pk);
    if (res == SQLITE_ROW) {
        // Already in DB
        return;
    }

    // Otherwise add to DB
    Dot d = toxtore_new_dot(tt);
    uint64_t ts = toxtore_new_timestamp(tt);
    // Friend not already there
    res = sqlite3_queryf(tt->db, NULL,
            "INSERT INTO events(device, seq_no, timestamp, type, arg_pk) "
            "VALUES(?k, ?I, ?I, ?i, ?k)",
            d.device_pk, d.seq_no, ts, TOXTORE_EVENT_FRIEND_ADD, pk);
    if (res == SQLITE_DONE) {
        toxtore_db_update_friends_table(tt, pk, 0, NULL);
        toxtore_sync_dot(tt, d);
    } else {
        fprintf(stderr, "Could not add friend (%d), skipping\n", res);
    }
}

void toxtore_db_set_friend_devices(Toxtore* tt, const uint8_t *pk, size_t n_devices, const uint8_t *devices_pks)
{
    uint8_t *sorted_pks = malloc(n_devices * TOX_PUBLIC_KEY_SIZE);
    if (sorted_pks == NULL) return;
    memcpy(sorted_pks, devices_pks, n_devices * TOX_PUBLIC_KEY_SIZE);
        
    toxtore_sort_pk_array(n_devices, sorted_pks);

    int res = sqlite3_queryf(tt->db, NULL,
        "SELECT device, seq_no FROM events "
        "WHERE type = ?i AND arg_pk = ?k AND arg_blob = ?B and cache_flag = 0;",
        (int32_t)TOXTORE_EVENT_FRIEND_DEVICES, pk, sorted_pks, n_devices * TOX_PUBLIC_KEY_SIZE);
    if (res == SQLITE_ROW) {
        // DB already up to date
        goto cleanup;
    }

    Dot d = toxtore_new_dot(tt);
    uint64_t ts = toxtore_new_timestamp(tt);

    sqlite3_exec(tt->db, "BEGIN", 0, 0, 0);
    res = sqlite3_queryf(tt->db, NULL,
        "UPDATE events SET cache_flag = 1 WHERE type = ?i AND arg_pk = ?k",
        (int32_t)TOXTORE_EVENT_FRIEND_DEVICES, pk);
    if (res != SQLITE_DONE) {
        sqlite3_exec(tt->db, "ROLLBACK", 0, 0, 0);
        goto cleanup;
    }

    res = sqlite3_queryf(tt->db, NULL,
        "INSERT INTO events(device, seq_no, timestamp, type, arg_pk, arg_blob) "
        "VALUES(?k, ?I, ?I, ?i, ?k, ?B)",
        d.device_pk, d.seq_no, ts, (int32_t)TOXTORE_EVENT_FRIEND_DEVICES,
        pk, sorted_pks, n_devices * TOX_PUBLIC_KEY_SIZE);
    if (res != SQLITE_DONE) {
        sqlite3_exec(tt->db, "ROLLBACK", 0, 0, 0);
        goto cleanup;
    }
    sqlite3_exec(tt->db, "COMMIT", 0, 0, 0);
    toxtore_sync_dot(tt, d);

    toxtore_db_update_friends_table(tt, pk, n_devices, sorted_pks);

cleanup:
    free(sorted_pks);
}

void toxtore_db_set_my_devices(Toxtore* tt)
{
    uint8_t my_pk[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_public_key(tt->tox, my_pk);

    size_t n_devices = 0;
    for (Active_Device *d = tt->devices; d != NULL; d = d->next) n_devices++;

    if (n_devices == 0) {
        toxtore_db_set_friend_devices(tt, my_pk, 0, NULL);
        return;
    }

    uint8_t *devices_pks = malloc(n_devices * TOX_PUBLIC_KEY_SIZE);
    if (devices_pks == NULL) return;

    uint8_t *p = devices_pks;
    for (Active_Device *d = tt->devices; d != NULL; d = d->next) {
        memcpy(p, d->pk, TOX_PUBLIC_KEY_SIZE);
        p += TOX_PUBLIC_KEY_SIZE;
    }

    toxtore_db_set_friend_devices(tt, my_pk, n_devices, devices_pks);
    free(devices_pks);
}

void toxtore_sync_internal_states(Toxtore* tt)
{
    // Add Tox friends to db
    size_t sz = tox_self_get_friend_list_size(tt->tox);
    uint32_t *friend_list = malloc(sizeof(uint32_t) * sz);
    if (friend_list == NULL) return;
    tox_self_get_friend_list(tt->tox, friend_list);

    for (int i = 0; i < sz; i++) {
        uint32_t friend_num = friend_list[i];
        uint8_t pk[TOX_PUBLIC_KEY_SIZE];
        tox_friend_get_public_key(tt->tox, friend_num, pk, NULL);

        toxtore_db_ensure_friend(tt, pk);
    }
    free(friend_list);

    // Add db friends to Tox
    sqlite3_stmt *stmt;
    int res = sqlite3_queryf(tt->db, &stmt, "SELECT arg_pk FROM events WHERE type = ?i AND cache_flag = 0;", TOXTORE_EVENT_FRIEND_ADD);
    while (res == SQLITE_ROW) {
        if (sqlite3_column_bytes(stmt, 0) == TOX_PUBLIC_KEY_SIZE) {
            TOX_ERR_FRIEND_BY_PUBLIC_KEY err;
            const uint8_t* pk = (const uint8_t*)sqlite3_column_blob(stmt, 0);
            tox_friend_by_public_key(tt->tox, pk, &err);
            if (err == TOX_ERR_FRIEND_BY_PUBLIC_KEY_NOT_FOUND) {
                tox_friend_add_norequest(tt->tox, pk, NULL);
            }
        }
        res = sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);

    // Get active devices
    res = sqlite3_queryf(tt->db, &stmt, "SELECT pk, is_reciprocal FROM devices WHERE removed = 0;");
    while (res == SQLITE_ROW) {
        const uint8_t *pk_ptr = sqlite3_column_blob(stmt, 0);

        TOX_ERR_FRIEND_BY_PUBLIC_KEY err;
        uint32_t friend_n = tox_friend_by_public_key(tt->tox, pk_ptr, &err);
        if (err == TOX_ERR_FRIEND_BY_PUBLIC_KEY_NOT_FOUND) {
            friend_n = tox_friend_add_norequest(tt->tox, pk_ptr, NULL);
        }

        Active_Device *dev = calloc(1, sizeof(Active_Device));
        if (dev == NULL) break;

        memcpy(dev->pk, pk_ptr, TOX_PUBLIC_KEY_SIZE);
        dev->tox_friend_no = friend_n;
        dev->is_reciprocal = sqlite3_column_int(stmt, 1);

        dev->next = tt->devices;
        tt->devices = dev;


        res = sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);
    
    // Make sure device list is consistent
    toxtore_db_set_my_devices(tt);
}


// ----------------------------
// IMPL
// Toxtore main API

Toxtore* toxtore_new(struct Tox_Options *options,
                     const char* save_basename,
                     size_t passphrase_len,
                     const uint8_t* passphrase,
                     TOX_ERR_NEW *error)
{
    if (error != NULL) *error = TOX_ERR_NEW_OK;

    Toxtore* toxtore = calloc(1, sizeof(Toxtore));
    if (toxtore == NULL) goto err0;

    toxtore->passphrase_len = passphrase_len;
    if (passphrase_len > 0) {
        toxtore->passphrase = malloc(passphrase_len);
        if (toxtore->passphrase == NULL) goto err1;
        memcpy(toxtore->passphrase, passphrase, passphrase_len);
    }

    toxtore->tox_save_path = malloc(strlen(save_basename) + 5);
    if (toxtore->tox_save_path == NULL) goto err15;
    snprintf(toxtore->tox_save_path, strlen(save_basename) + 5, "%s.tox", save_basename);

    toxtore->tox_tmp_save_path = malloc(strlen(save_basename) + 9);
    if (toxtore->tox_tmp_save_path == NULL) goto err2;
    snprintf(toxtore->tox_tmp_save_path, strlen(save_basename) + 9, "%s.tox.tmp", save_basename);

    toxtore->db_path = malloc(strlen(save_basename) + 12);
    if (toxtore->db_path == NULL) goto err3;
    snprintf(toxtore->db_path, strlen(save_basename) + 12, "%s.toxtore.db", save_basename);

    FILE *f = fopen(toxtore->tox_save_path, "rb");
    uint8_t *savedata = NULL;
    if (f) {
        fseek(f, 0, SEEK_END);
        long fsize = ftell(f);
        fseek(f, 0, SEEK_SET);

        savedata = malloc(fsize);
        if (savedata == NULL) goto err4;
        fread(savedata, fsize, 1, f);
        fclose(f);

        if (toxtore->passphrase_len > 0) {
            uint8_t* cipherdata = savedata;
            uint8_t* plaindata = malloc(fsize);
            if (plaindata == NULL) {
                free(savedata);
                goto err4;
            }
            TOX_ERR_DECRYPTION derror;
            bool success = tox_pass_decrypt(cipherdata, fsize, toxtore->passphrase, toxtore->passphrase_len, plaindata, &derror);
            if (success) {
                savedata = plaindata;
                free(cipherdata);
            } else {
                fprintf(stderr, "Could not decrypt tox savefile, invalid passphrase? (%d)\n", derror);
                if (error) *error = TOXTORE_ERR_NEW_BAD_PASSPHRASE;
                goto err4;
            }
        }

        tox_options_set_savedata_type(options, TOX_SAVEDATA_TYPE_TOX_SAVE);
        tox_options_set_savedata_data(options, savedata, fsize);
    }

    toxtore->tox = tox_new(options, error);
    if (error != NULL && *error != TOX_ERR_NEW_OK) goto err4;

    free(savedata);

    // Hijack callbacks
    tox_callback_friend_request(toxtore->tox, &toxtore_friend_request_handler);
    tox_callback_friend_message(toxtore->tox, &toxtore_friend_message_handler);
    tox_callback_conference_message(toxtore->tox, &toxtore_conference_message_handler);
    tox_callback_friend_read_receipt(toxtore->tox, &toxtore_friend_read_receipt_handler);
    tox_callback_friend_connection_status(toxtore->tox, &toxtore_friend_connection_status_handler);
    tox_callback_friend_lossless_packet(toxtore->tox, &toxtore_friend_lossless_packet_handler);

    // Init database
    int res = sqlite3_open(toxtore->db_path, &toxtore->db);
    if (res) {
        fprintf(stderr, "Could not open sqlite3 db: %s\n", toxtore->db_path);
        if (error != NULL) *error = TOXTORE_ERR_NEW_SQLITE;
        goto err5;
    }

    if (toxtore->passphrase != NULL) {
        sqlite3_key(toxtore->db, toxtore->passphrase, toxtore->passphrase_len);
        if (sqlite3_exec(toxtore->db, "SELECT count(*) FROM sqlite_master;", NULL, NULL, NULL) != SQLITE_OK) {
            // key is incorrect
            fprintf(stderr, "Incorrect key, cannot unlock sqlite3 db.\n");
            if (error) *error = TOXTORE_ERR_NEW_BAD_PASSPHRASE;
            goto err6;
        }
    }

    const char *sql = "CREATE TABLE IF NOT EXISTS events(\n"
                        "device         BLOB    NOT NULL    ,\n"
                        "seq_no         INTEGER NOT NULL    ,\n"
                        "timestamp      INTEGER NOT NULL    ,\n"
                        "type           INTEGER NOT NULL    ,\n"
                        "arg_dot_dev    BLOB                ,\n"
                        "arg_dot_sn     INTEGER             ,\n"
                        "arg_pk         BLOB                ,\n"
                        "arg_blob       BLOB                ,\n"
                        "arg_msg        TEXT                ,\n"
                        "arg_int        INTEGER             ,\n"
                        "cache_flag     INTEGER DEFAULT 0   ,\n"
                        "PRIMARY KEY (device, seq_no)\n"
                    ");\n"
                    "CREATE INDEX IF NOT EXISTS events_type ON events(type);\n"
                    "CREATE INDEX IF NOT EXISTS events_type_flag ON events(type, cache_flag);\n"
                    "CREATE INDEX IF NOT EXISTS events_ts ON events(timestamp);\n"
                    "CREATE TABLE IF NOT EXISTS devices(\n"
                        "pk             BLOB    NOT NULL    PRIMARY KEY ,\n"
                        "removed        INTEGER DEFAULT 0               ,\n"
                        "is_reciprocal  INTEGER DEFAULT 0               ,\n"
                        "got_until      INTEGER DEFAULT 0                \n"
                    ");\n"
                    "CREATE TABLE IF NOT EXISTS friends(\n"
                        "pk             BLOB    NOT NULL    PRIMARY KEY ,\n"
                        "other_pks      BLOB                            ,\n"
                        "merged_id      INTEGER                          \n"
                    ");\n"
                    "CREATE INDEX IF NOT EXISTS friends_merged_id ON friends(merged_id);\n"
                    ;

    char *err_msg;
    res = sqlite3_exec(toxtore->db, sql, 0, 0, &err_msg);
    if (res != SQLITE_OK) {
        fprintf(stderr, "Cannot create sqlite tables: %s\n", err_msg);
        sqlite3_free(err_msg);
        if (error) *error = TOXTORE_ERR_NEW_SQLITE;
        goto err6;
    }

    toxtore_sync_internal_states(toxtore);

    // Done !
    return toxtore;

err6:
    sqlite3_close(toxtore->db);
err5:
    tox_kill(toxtore->tox);
err4:
    free(toxtore->db_path);
err3:
    free(toxtore->tox_tmp_save_path);
err2:
    free(toxtore->tox_save_path);
err15:
    if (toxtore->passphrase != NULL) free(toxtore->passphrase);
err1:
    free(toxtore);
err0:
    if (error != NULL && *error == TOX_ERR_NEW_OK) *error = TOX_ERR_NEW_MALLOC;
    return NULL;
}

void toxtore_kill(Toxtore* tt)
{
    sqlite3_close(tt->db);
    tox_kill(tt->tox);
    free(tt->db_path);
    free(tt->tox_tmp_save_path);
    free(tt->tox_save_path);
    if (tt->passphrase != NULL) free(tt->passphrase);
    while (tt->devices != NULL) {
        Active_Device *d = tt->devices;
        tt->devices = d->next;
        while (d->missing != NULL) {
            First_Missing_Dot *m = d->missing;
            d->missing = m->next;
            free(m);
        }
        free(d);
    }
    while (tt->sending != NULL) {
        Sending_Message *s = tt->sending;
        tt->sending = s->next;
        free(s);
    }
    free(tt);
}

void toxtore_iterate(Toxtore* tt, void* user_data)
{
    tt->user_data = user_data;
    tox_iterate(tt->tox, tt);

    // Currently syncing: send some dots (not all!)
    for (Active_Device *d = tt->devices; d != NULL; d = d->next) {
        if (d->missing != NULL) {
            Dot dot;
            memcpy(dot.device_pk, d->missing->device_pk, TOX_PUBLIC_KEY_SIZE);
            dot.seq_no = d->missing->sn;
            uint8_t *pkt;
            size_t len = toxtore_make_packet_send_dot(tt, dot, &pkt);
            if (len == 0) {
                // Nothing more to send
                First_Missing_Dot *tmp = d->missing;
                d->missing = tmp->next;
                free(tmp);
            } else {
                tox_friend_send_lossless_packet(tt->tox, d->tox_friend_no, pkt, len, NULL);
                free(pkt);
                d->missing->sn++;
            }
        }
    }
}

int toxtore_save(Toxtore* tt)
{
    size_t size = tox_get_savedata_size(tt->tox);
    uint8_t *savedata = malloc(size);
    if (savedata == NULL) return -1;

    tox_get_savedata(tt->tox, savedata);

    if (tt->passphrase_len > 0) {
        uint8_t* plaindata = savedata;
        size_t ciphersize = size + TOX_PASS_ENCRYPTION_EXTRA_LENGTH;
        uint8_t* cipherdata = malloc(ciphersize);
        if (cipherdata == NULL) {
            free(savedata);
            return -1;
        }
        TOX_ERR_ENCRYPTION error;
        bool success = tox_pass_encrypt(savedata, size, tt->passphrase, tt->passphrase_len, cipherdata, &error);
        if (!success) {
            fprintf(stderr, "Could not encrypt data (%d)\n", error);
            free(cipherdata);
            free(plaindata);
            return -1;
        } else {
            free(plaindata);
            savedata = cipherdata;
            size = ciphersize;
        }
    }

    FILE *f = fopen(tt->tox_tmp_save_path, "wb");
    if (f == NULL) {
        free(savedata);
        return -2;
    }
    fwrite(savedata, size, 1, f);
    fclose(f);

    rename(tt->tox_tmp_save_path, tt->tox_save_path);

    free(savedata);

    return 0;
}

Tox* toxtore_get_tox(Toxtore* tt)
{
    return tt->tox;
}

sqlite3* toxtore_get_db(Toxtore* tt)
{
    return tt->db;
}

// --------- v ---------- Friend management --------- v ----------

uint32_t toxtore_friend_add(Toxtore* tt,
                            const uint8_t *address,
                            const uint8_t *message,
                            size_t length,
                            TOX_ERR_FRIEND_ADD *error)
{
    TOX_ERR_FRIEND_ADD myerr;
    if (error == NULL) error = &myerr;

    uint32_t id = tox_friend_add(tt->tox, address, message, length, error);

    if (*error == TOX_ERR_FRIEND_ADD_OK || *error == TOX_ERR_FRIEND_ADD_ALREADY_SENT) {
        toxtore_db_ensure_friend(tt, address);
        // TODO maybe add nospam to db and sync it
    }

    return id;
}

uint32_t toxtore_friend_add_norequest(Toxtore *tt,
                                      const uint8_t *public_key,
                                      TOX_ERR_FRIEND_ADD *error)
{
    TOX_ERR_FRIEND_ADD myerr;
    if (error == NULL) error = &myerr;

    uint32_t id = tox_friend_add_norequest(tt->tox, public_key, error);

    if (*error == TOX_ERR_FRIEND_ADD_OK || *error == TOX_ERR_FRIEND_ADD_ALREADY_SENT) {
        toxtore_db_ensure_friend(tt, public_key);
    }

    return id;
}

bool toxtore_friend_delete(Toxtore *tt, uint32_t friend_number, TOX_ERR_FRIEND_DELETE *error)
{
    TOX_ERR_FRIEND_DELETE myerr;
    if (error == NULL) error = &myerr;

    uint8_t pk[TOX_PUBLIC_KEY_SIZE];
    TOX_ERR_FRIEND_GET_PUBLIC_KEY err1;
    tox_friend_get_public_key(tt->tox, friend_number, pk, &err1);
    if (err1 != TOX_ERR_FRIEND_GET_PUBLIC_KEY_OK) {
        *error = TOX_ERR_FRIEND_DELETE_FRIEND_NOT_FOUND;
        return false;
    }

    bool ok = tox_friend_delete(tt->tox, friend_number, error);
    if (ok) {
        while (true) {
            sqlite3_stmt *stmt;
            int res = sqlite3_queryf(tt->db, &stmt,
                        "SELECT device, seq_no FROM events WHERE type = ?i AND arg_pk = ?k AND cache_flag = 0;",
                        TOXTORE_EVENT_FRIEND_ADD, pk);
            if (res == SQLITE_ROW) {
                if (sqlite3_column_bytes(stmt, 0) != TOX_PUBLIC_KEY_SIZE) {
                    fprintf(stderr, "DB corruption, device is not of good length\n");
                    sqlite3_finalize(stmt);
                    break;
                }
                Dot ev;
                memcpy(ev.device_pk, sqlite3_column_blob(stmt, 0), TOX_PUBLIC_KEY_SIZE);
                ev.seq_no = sqlite3_column_int64(stmt, 1);
                sqlite3_finalize(stmt);

                Dot d = toxtore_new_dot(tt);
                uint64_t ts = toxtore_new_timestamp(tt);

                sqlite3_exec(tt->db, "BEGIN", 0, 0, 0);
                int res = sqlite3_queryf(tt->db, NULL,
                            "UPDATE events SET cache_flag = 1 WHERE device = ?k AND seq_no = ?I",
                            ev.device_pk, ev.seq_no);
                if (res == SQLITE_DONE) {
                    res = sqlite3_queryf(tt->db, NULL,
                            "INSERT INTO events(device, seq_no, timestamp, type, arg_dot_dev, arg_dot_sn) "
                                "VALUES(?k, ?I, ?I, ?i, ?k, ?I)",
                            d.device_pk, d.seq_no, ts, TOXTORE_EVENT_FRIEND_DEL, 
                            ev.device_pk, ev.seq_no);
                    if (res == SQLITE_DONE) {
                        sqlite3_exec(tt->db, "COMMIT", 0, 0, 0);
                        toxtore_sync_dot(tt, d);
                    } else {
                        fprintf(stderr, "Coud not log delete friend event (%d)\n", res);
                        sqlite3_exec(tt->db, "ROLLBACK", 0, 0, 0);
                    }
                } else {
                    fprintf(stderr, "Coud not log delete friend event (%d)\n", res);
                    sqlite3_exec(tt->db, "ROLLBACK", 0, 0, 0);
                }
            } else {
                sqlite3_finalize(stmt);
                break;
            }
        }
    }

    return ok;
}

bool toxtore_is_same_person(Toxtore* tt, uint32_t friend_n1, uint32_t friend_n2)
{
    uint8_t pk1[TOX_PUBLIC_KEY_SIZE], pk2[TOX_PUBLIC_KEY_SIZE];
    TOX_ERR_FRIEND_GET_PUBLIC_KEY err;

    tox_friend_get_public_key(tt->tox, friend_n1, pk1, &err);
    if (err != TOX_ERR_FRIEND_GET_PUBLIC_KEY_OK) return false;
    tox_friend_get_public_key(tt->tox, friend_n2, pk2, &err);
    if (err != TOX_ERR_FRIEND_GET_PUBLIC_KEY_OK) return false;


    uint32_t merged_id[2];
    sqlite3_stmt *stmt;
    int res = sqlite3_queryf(tt->db, &stmt,
        "SELECT merged_id FROM friends WHERE pk IN (?k, ?k)",
        pk1, pk2);
    int nres = 0;
    while (res == SQLITE_ROW && nres < 2) {
        merged_id[nres++] = sqlite3_column_int(stmt, 0);
        res = sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);

    return nres == 2 && merged_id[0] == merged_id[1];
}

size_t toxtore_other_devices(Toxtore* tt, uint32_t friend_n, uint32_t** friend_nums)
{
    uint8_t pk[TOX_PUBLIC_KEY_SIZE];
    TOX_ERR_FRIEND_GET_PUBLIC_KEY err;
    tox_friend_get_public_key(tt->tox, friend_n, pk, &err);
    if (err != TOX_ERR_FRIEND_GET_PUBLIC_KEY_OK) return false;

    sqlite3_stmt *stmt;
    int res = sqlite3_queryf(tt->db, &stmt,
        "SELECT other_pks FROM friends WHERE pk = ?k", pk);
    if (res != SQLITE_ROW) goto error;

    size_t npk = sqlite3_column_bytes(stmt, 0) / TOX_PUBLIC_KEY_SIZE;
    if (npk == 0) goto error;

    *friend_nums = malloc(sizeof(uint32_t)*npk);
    if (*friend_nums == NULL) goto error;

    size_t used = 0;
    for (int ipk = 0; ipk < npk; ipk++) {
        TOX_ERR_FRIEND_BY_PUBLIC_KEY err1;
        uint32_t fi = tox_friend_by_public_key(tt->tox, sqlite3_column_blob(stmt, 0) + ipk*TOX_PUBLIC_KEY_SIZE, &err1);
        if (err1 == TOX_ERR_FRIEND_BY_PUBLIC_KEY_OK) {
            (*friend_nums)[used++] = fi;
        }
    }

    if (used == 0) {
        free(*friend_nums);
        *friend_nums = NULL;
    }
    return used;

error:
    sqlite3_finalize(stmt);
    return 0;
}

uint32_t toxtore_get_preferred_device(Toxtore* tt, uint32_t friend_n)
{
    // TODO
    return friend_n;
}

// --------- v ---------- Device management --------- v ----------

void toxtore_broadcast_my_devices(Toxtore* tt)
{
    uint8_t *pkt;
    size_t pkt_len = toxtore_make_packet_my_devices(tt, &pkt);
    if (pkt_len > 0) {
        size_t num_friends = tox_self_get_friend_list_size(tt->tox);
        uint32_t *friend_list = malloc(sizeof(uint32_t)*num_friends);
        tox_self_get_friend_list(tt->tox, friend_list);
        for (size_t i = 0; i < num_friends; i++)
            tox_friend_send_lossless_packet(tt->tox, friend_list[i], pkt, pkt_len, NULL);
        free(friend_list);
        free(pkt);
    }
}

bool toxtore_add_friend_as_device(Toxtore* tt, uint32_t friend_number)
{
    uint8_t pk[TOX_PUBLIC_KEY_SIZE];
    TOX_ERR_FRIEND_GET_PUBLIC_KEY error;
    tox_friend_get_public_key(tt->tox, friend_number, pk, &error);
    if (error != TOX_ERR_FRIEND_GET_PUBLIC_KEY_OK) {
        fprintf(stderr, "Could not find friend with such number (%d)\n", error);
        return false; // TODO report error
    }

    sqlite3_stmt *stmt;
    int res = sqlite3_queryf(tt->db, &stmt,
                "SELECT removed FROM devices WHERE pk = ?k AND removed = 0;",
                pk);
    bool exists, removed;
    if (res == SQLITE_ROW) {
        exists = true;
        removed = (sqlite3_column_int(stmt, 0) != 0);
    } else {
        exists = false;
    }
    sqlite3_finalize(stmt);

    res = sqlite3_queryf(tt->db, &stmt, "SELECT COUNT(*) FROM devices WHERE removed = 0;");
    if (res == SQLITE_ROW) {
        int n_dev = sqlite3_column_int(stmt, 0);
        if (n_dev >= TOXTORE_MAX_DEVICES) {
            fprintf(stderr, "Maximum device limit reached, cannot add more!");
            return false;
        }
    }
    sqlite3_finalize(stmt);

    bool added = false;
    if (exists && removed) {
        res = sqlite3_queryf(tt->db, NULL,
                    "UPDATE devices SET removed = 0 WHERE pk = ?k", pk);
        if (res == SQLITE_DONE && sqlite3_changes(tt->db) == 1) added = true;
    } else if (!exists) {
        res = sqlite3_queryf(tt->db, NULL,
                    "INSERT INTO devices(pk, removed) VALUES (?k, 0)", pk);
        if (res == SQLITE_DONE) added = true;
    }

    if (added) {
        Active_Device *dev = calloc(1, sizeof(Active_Device));
        if (dev != NULL) {
            memcpy(dev->pk, pk, TOX_PUBLIC_KEY_SIZE);
            dev->tox_friend_no = friend_number;
            dev->next = tt->devices;
            tt->devices = dev;

            res = sqlite3_queryf(tt->db, &stmt,
                "SELECT other_pks FROM friends WHERE pk = ?k", pk);
            if (res == SQLITE_ROW) {
                uint8_t my_pk[TOX_PUBLIC_KEY_SIZE];
                tox_self_get_public_key(tt->tox, my_pk);
                const uint8_t *other_pks = sqlite3_column_blob(stmt, 0);
                size_t npk = sqlite3_column_bytes(stmt, 0) / TOX_PUBLIC_KEY_SIZE;
                for (size_t ipk = 0; ipk < npk; ipk++) {
                    if (!memcmp(my_pk, other_pks + ipk * TOX_PUBLIC_KEY_SIZE, TOX_PUBLIC_KEY_SIZE)) {
                        dev->is_reciprocal = true;
                        break;
                    }
                }
            }
            sqlite3_finalize(stmt);
        }

        toxtore_db_set_my_devices(tt);
        toxtore_broadcast_my_devices(tt);

        if (dev->is_reciprocal) {
            uint8_t *pkt;
            int pkt_len = toxtore_make_packet_vector_clock(tt, &pkt);
            if (pkt_len > 0) {
                tox_friend_send_lossless_packet(tt->tox, friend_number, pkt, pkt_len, NULL);
                free(pkt);
            }
        }
    }
    return added;
}

bool _toxtore_device_list_remove_device(Active_Device **list, uint8_t *pk)
{
    if (*list == NULL) {
        return false;
    } else {
        if (!memcmp(list[0]->pk, pk, TOX_PUBLIC_KEY_SIZE)) {
            Active_Device *tmp = *list;
            *list = tmp->next;
            while (tmp->missing != NULL) {
                First_Missing_Dot *tmp2 = tmp->missing;
                tmp->missing = tmp2->next;
                free(tmp2);
            }
            free(tmp);
            return true;
        } else {
            return _toxtore_device_list_remove_device(&list[0]->next, pk);
        }
    }
}

bool toxtore_rm_friend_as_device(Toxtore* tt, uint32_t friend_number)
{
    uint8_t pk[TOX_PUBLIC_KEY_SIZE];
    TOX_ERR_FRIEND_GET_PUBLIC_KEY error;
    tox_friend_get_public_key(tt->tox, friend_number, pk, &error);
    if (error != TOX_ERR_FRIEND_GET_PUBLIC_KEY_OK) {
        fprintf(stderr, "Could not find friend with such pk (%d)\n", error);
        return false; // TODO report error
    }

    bool removed = _toxtore_device_list_remove_device(&tt->devices, pk);

    if (removed) {
        int res = sqlite3_queryf(tt->db, NULL,
                    "UPDATE devices SET removed = 1 WHERE pk = ?k AND removed = 0;", pk);
        if (res == SQLITE_DONE) {
            assert(sqlite3_changes(tt->db) == 1);
        } else {
            fprintf(stderr, "Could not remove device from SQL DB");
        }

        toxtore_db_set_my_devices(tt);
        toxtore_broadcast_my_devices(tt);
    }
    return removed;
}

size_t toxtore_device_list(Toxtore* tt, uint32_t** friends_nums)
{
    size_t n_devices = 0;
    for (Active_Device *p = tt->devices; p != NULL; p = p->next) n_devices++;

    if (n_devices == 0) {
        *friends_nums = NULL;
        return 0;
    }

    *friends_nums = malloc(n_devices * sizeof(uint32_t));
    if (friends_nums == NULL) {
        return 0;
    }

    uint32_t *ptr = *friends_nums;
    for (Active_Device *p = tt->devices; p != NULL; p = p->next) {
        *ptr++ = p->tox_friend_no;
    }
    assert(ptr - *friends_nums == n_devices);

    return n_devices;
}

bool toxtore_is_friend_my_device(Toxtore* tt, uint32_t friend_number, bool* out_reciprocal)
{
    for (Active_Device *p = tt->devices; p != NULL; p = p->next) {
        if (p->tox_friend_no == friend_number) {
            if (out_reciprocal != NULL) *out_reciprocal = p->is_reciprocal;
            return true;
        }
    }
    return false;
}

bool toxtore_is_pk_my_device(Toxtore* tt, uint8_t *pk, bool* out_reciprocal)
{
    for (Active_Device *p = tt->devices; p != NULL; p = p->next) {
        if (!memcmp(p->pk, pk, TOX_PUBLIC_KEY_SIZE)) {
            if (out_reciprocal != NULL) *out_reciprocal = p->is_reciprocal;
            return true;
        }
    }
    return false;
}

void toxtore_init_sync(Toxtore* tt, uint32_t friend_num)
{
    if (toxtore_is_friend_my_device(tt, friend_num, NULL)) {
        uint8_t *pkt;
        size_t pkt_len = toxtore_make_packet_my_devices(tt, &pkt);
        if (pkt_len > 0) {
            tox_friend_send_lossless_packet(tt->tox, friend_num, pkt, pkt_len, NULL);
            free(pkt);
        }

        pkt_len = toxtore_make_packet_vector_clock(tt, &pkt);
        if (pkt_len > 0) {
            tox_friend_send_lossless_packet(tt->tox, friend_num, pkt, pkt_len, NULL);
            free(pkt);
        }
    }
}

// --------- v ---------- Messaging --------- v ----------

Dot toxtore_friend_send_message(Toxtore* tt,
                                uint32_t friend_number,
                                TOX_MESSAGE_TYPE type,
                                const uint8_t* msg,
                                size_t length,
                                TOX_ERR_FRIEND_SEND_MESSAGE *error)
{
    TOX_ERR_FRIEND_SEND_MESSAGE myerr;
    if (error == NULL) error = &myerr;

    Dot d = toxtore_new_dot(tt);
    uint32_t t = tox_friend_send_message(tt->tox, friend_number, type, msg, length, error);

    if (*error == TOX_ERR_FRIEND_SEND_MESSAGE_OK
            || *error == TOX_ERR_FRIEND_SEND_MESSAGE_FRIEND_NOT_CONNECTED) {
        uint8_t pk[TOX_PUBLIC_KEY_SIZE];
        tox_friend_get_public_key(tt->tox, friend_number, pk, NULL);

        uint64_t ts = toxtore_new_timestamp(tt);
        int res = sqlite3_queryf(tt->db, NULL,
                    "INSERT INTO events(device, seq_no, timestamp, type, arg_pk, arg_int, arg_msg) VALUES(?k, ?I, ?I, ?i, ?k, ?i, ?S);",
                    d.device_pk, d.seq_no, ts, TOXTORE_EVENT_FRIEND_SEND, pk, (int32_t)type, msg, length);
        if (res == SQLITE_DONE) {
            toxtore_sync_dot(tt, d);
            if (*error == TOX_ERR_FRIEND_SEND_MESSAGE_OK) {
                Sending_Message *sm = calloc(1, sizeof(Sending_Message));
                if (sm != NULL) {
                    sm->tox_number = t;
                    sm->dot = d;

                    sm->next = tt->sending;
                    tt->sending = sm;
                }
            }
        } else {
            fprintf(stderr, "Could not log message send event (%d)\n", res);
            d.seq_no = 0;
        }
    }

    return d;
}

Dot toxtore_conference_send_message(Toxtore* tt,
                                    uint32_t conference_number,
                                    TOX_MESSAGE_TYPE type,
                                    const uint8_t *message,
                                    size_t length,
                                    TOX_ERR_CONFERENCE_SEND_MESSAGE *error)
{
    TOX_ERR_CONFERENCE_SEND_MESSAGE myerr;
    if (error == NULL) error = &myerr;

    Dot d = toxtore_new_dot(tt);
    tox_conference_send_message(tt->tox, conference_number, type, message, length, error);

    if (*error == TOX_ERR_CONFERENCE_SEND_MESSAGE_OK
            || *error == TOX_ERR_CONFERENCE_SEND_MESSAGE_NO_CONNECTION
            || *error == TOX_ERR_CONFERENCE_SEND_MESSAGE_FAIL_SEND)
    {
        uint8_t conf_id[TOX_CONFERENCE_ID_SIZE];
        tox_conference_get_id(tt->tox, conference_number, conf_id);

        uint64_t ts = toxtore_new_timestamp(tt);
        int flag = (*error == TOX_ERR_CONFERENCE_SEND_MESSAGE_OK ? 1 : 0);
        int res = sqlite3_queryf(tt->db, NULL,
                    "INSERT INTO events(device, seq_no, timestamp, type, arg_blob, arg_int, arg_msg, cache_flag) "
                    "VALUES(?k, ?I, ?I, ?i, ?B, ?S, ?i, ?i)",
                    d.device_pk, d.seq_no, ts, TOXTORE_EVENT_CONFERENCE_SEND,
                    conf_id, (size_t)TOX_CONFERENCE_ID_SIZE, (int32_t)type, message, length, (int32_t)flag);
        if (res == SQLITE_DONE) {
            toxtore_sync_dot(tt, d);
        } else {
            fprintf(stderr, "Could not log conf message send event (%d)\n", res);
        }
    }

    return d;
}

void toxtore_mark_read(Toxtore* tt, Dot ev)
{
    int res = sqlite3_queryf(tt->db, NULL, "SELECT device, seq_no FROM events WHERE device = ?k AND seq_no = ?I AND (type = ?i OR type = ?i) AND cache_flag = 0;",
            ev.device_pk, ev.seq_no, TOXTORE_EVENT_FRIEND_RECV, TOXTORE_EVENT_CONFERENCE_RECV);
    if (res == SQLITE_ROW) {
        Dot d = toxtore_new_dot(tt);
        uint64_t ts = toxtore_new_timestamp(tt);
        sqlite3_exec(tt->db, "BEGIN", 0, 0, 0);
        res = sqlite3_queryf(tt->db, NULL,
                    "UPDATE events SET cache_flag = 1 WHERE device = ?k AND seq_no = ?I",
                    ev.device_pk, ev.seq_no);
        if (res == SQLITE_DONE) {
            res = sqlite3_queryf(tt->db, NULL, 
                    "INSERT INTO events(device, seq_no, timestamp, type, arg_dot_dev, arg_dot_sn) "
                        "VALUES(?k, ?I, ?I, ?i, ?k, ?I); ",
                    d.device_pk, d.seq_no, ts, TOXTORE_EVENT_MARK_READ, ev.device_pk, ev.seq_no);
            if (res == SQLITE_DONE) {
                sqlite3_exec(tt->db, "COMMIT", 0, 0, 0);
                toxtore_sync_dot(tt, d);
            } else {
                fprintf(stderr, "Could log not mark read event (%d)\n", res);
                sqlite3_exec(tt->db, "ROLLBACK", 0, 0, 0);
            }
        } else {
            fprintf(stderr, "Could log not mark read event (%d)\n", res);
            sqlite3_exec(tt->db, "ROLLBACK", 0, 0, 0);
        }
    } else {
        // TODO: report error
        fprintf(stderr, "toxtore_mark_read: event not found\n");
    }
}

// ----------------------------------------------------
// Toxtore API: Callback setters

void toxtore_callback_friend_request(Toxtore *tt, toxtore_friend_request_cb *callback)
{
    tt->friend_request_cb = callback;
}

void toxtore_callback_friend_message(Toxtore *tt, toxtore_friend_message_cb *callback)
{
    tt->friend_message_cb = callback;
}

void toxtore_callback_conference_message(Toxtore* tt, toxtore_conference_message_cb *callback)
{
    tt->conference_message_cb = callback;
}

void toxtore_callback_friend_read_receipt(Toxtore *tt, toxtore_friend_read_receipt_cb *callback)
{
    tt->friend_read_receipt_cb = callback;
}

void toxtore_callback_friend_connection_status(Toxtore *tt, toxtore_friend_connection_status_cb *callback)
{
    tt->friend_connection_status_cb = callback;
}

void toxtore_callback_device_add_request(Toxtore* tt, toxtore_device_add_request_cb *callback)
{
    tt->device_add_request_cb = callback;
}

// ===================================================
// Handlers for Tox events

void toxtore_friend_request_handler(Tox* tox,
                                    const uint8_t *public_key,
                                    const uint8_t *message,
                                    size_t length,
                                    void* user_data)
{
    Toxtore* tt = (Toxtore*) user_data;

    bool auto_added = false;

    const char* expfx = TOXTORE_FRIEND_MSG_PREFIX_OTHER_DEVICE;
    if (length == TOXTORE_FRIEND_MSG_LEN_OTHER_DEVICE && !memcmp(message, expfx, strlen(expfx))) {
        uint8_t other_pk[TOX_PUBLIC_KEY_SIZE];
        bool correct = toxtore_util_hexdecode(other_pk, message + strlen(expfx), TOX_PUBLIC_KEY_SIZE);
        if (correct) {
            sqlite3_stmt *stmt;
            int res = sqlite3_queryf(tt->db, &stmt,
                "SELECT other_pks FROM friends WHERE pk = ?k", other_pk);
            bool found = false;
            if (res == SQLITE_ROW) {
                int npk = sqlite3_column_bytes(stmt, 0) / TOX_PUBLIC_KEY_SIZE;
                const uint8_t *by = sqlite3_column_blob(stmt, 0);
                for (int i = 0; i < npk; i++) {
                    if (!memcmp(public_key, by + i*TOX_PUBLIC_KEY_SIZE, TOX_PUBLIC_KEY_SIZE)) {
                        found = true;
                        break;
                    }
                }
            }
            sqlite3_finalize(stmt);
            if (found) {
                tox_friend_add_norequest(tt->tox, public_key, NULL);
                toxtore_db_ensure_friend(tt, public_key);
            }
        }
    }

    if (!auto_added && tt->friend_request_cb != NULL)
        tt->friend_request_cb(tt, public_key, message, length, tt->user_data);
}

void toxtore_friend_message_handler(Tox* tox,
                                    uint32_t friend_number,
                                    TOX_MESSAGE_TYPE type,
                                    const uint8_t *message,
                                    size_t length,
                                    void* user_data)
{
    Toxtore* tt = (Toxtore*) user_data;

    uint8_t pk[TOX_PUBLIC_KEY_SIZE];
    tox_friend_get_public_key(tox, friend_number, pk, NULL);

    Dot d = toxtore_new_dot(tt);
    uint64_t ts = toxtore_new_timestamp(tt);
    int res = sqlite3_queryf(tt->db, NULL,
                "INSERT INTO events(device, seq_no, timestamp, type, arg_pk, arg_int, arg_msg) VALUES(?k, ?I, ?I, ?i, ?k, ?i, ?S);",
                d.device_pk, d.seq_no, ts, TOXTORE_EVENT_FRIEND_RECV, pk, (int32_t)type, message, length);
    if (res == SQLITE_DONE) {
        toxtore_sync_dot(tt, d);
    } else {
        fprintf(stderr, "Could not log friend receive event (%d)\n", res);
    }

    if (tt->friend_message_cb != NULL)
        tt->friend_message_cb(tt, friend_number, d, type, message, length, tt->user_data);
}

void toxtore_conference_message_handler(Tox* tox,
                                        uint32_t conference_number,
                                        uint32_t peer_number,
                                        TOX_MESSAGE_TYPE type,
                                        const uint8_t *message,
                                        size_t length,
                                        void* user_data)
{
    Toxtore* tt = (Toxtore*) user_data;

    uint8_t pk[TOX_PUBLIC_KEY_SIZE];
    tox_conference_peer_get_public_key(tox, conference_number, peer_number, pk, NULL);
    uint8_t conf_id[TOX_CONFERENCE_ID_SIZE];
    tox_conference_get_id(tox, conference_number, conf_id);

    Dot d = toxtore_new_dot(tt);
    uint64_t ts = toxtore_new_timestamp(tt);
    int res = sqlite3_queryf(tt->db, NULL,
                "INSERT INTO events(device, seq_no, timestamp, type, arg_pk, arg_int, arg_msg, arg_blob) VALUES(?k, ?I, ?I, ?i, ?k, ?i, ?S, ?B);",
                d.device_pk, d.seq_no, ts, TOXTORE_EVENT_CONFERENCE_RECV, pk, (int32_t)type,
                message, length, conf_id, (size_t)TOX_CONFERENCE_ID_SIZE);
    if (res == SQLITE_DONE) {
        toxtore_sync_dot(tt, d);
    } else {
        fprintf(stderr, "Could not log conference receive event (%d)\n", res);
    }
    
    if (tt->conference_message_cb != NULL)
        tt->conference_message_cb(tt, conference_number, peer_number, d, type, message, length, tt->user_data);
}

bool _toxtore_find_dot_delete_sending(Sending_Message **s, uint32_t id, Dot *out)
{
    if (*s == NULL) {
        return false;
    } else {
        if (s[0]->tox_number == id) {
            Sending_Message *tmp = *s;
            *out = tmp->dot;
            *s = tmp->next;
            free(tmp);
            return true;
        } else {
            return _toxtore_find_dot_delete_sending(&s[0]->next, id, out);
        }
    }
}

void toxtore_friend_read_receipt_handler(Tox* tox,
                                         uint32_t friend_number,
                                         uint32_t message_id,
                                         void* user_data)
{
    Toxtore* tt = (Toxtore*) user_data;

    Dot ev;
    if (_toxtore_find_dot_delete_sending(&tt->sending, message_id, &ev)) {
        Dot d = toxtore_new_dot(tt);
        uint64_t ts = toxtore_new_timestamp(tt);
        sqlite3_exec(tt->db, "BEGIN", 0, 0, 0);
        int res = sqlite3_queryf(tt->db, NULL,
                    "UPDATE events SET cache_flag = 1 WHERE device = ?k AND seq_no = ?I",
                    ev.device_pk, ev.seq_no);
        if (res == SQLITE_DONE) {
            res = sqlite3_queryf(tt->db, NULL,
                    "INSERT INTO events(device, seq_no, timestamp, type, arg_dot_dev, arg_dot_sn) "
                        "VALUES(?k, ?I, ?I, ?i, ?k, ?I); ",
                    d.device_pk, d.seq_no, ts, TOXTORE_EVENT_SEND_DONE, ev.device_pk, ev.seq_no);
            if (res == SQLITE_DONE) {
                sqlite3_exec(tt->db, "COMMIT", 0, 0, 0);
                toxtore_sync_dot(tt, d);
            } else {
                fprintf(stderr, "Could not log send done event (%d)\n", res);
                sqlite3_exec(tt->db, "ROLLBACK", 0, 0, 0);
            }
        } else {
            fprintf(stderr, "Could not log send done event (%d)\n", res);
            sqlite3_exec(tt->db, "ROLLBACK", 0, 0, 0);
        }
        
        if (tt->friend_read_receipt_cb != NULL)
            tt->friend_read_receipt_cb(tt, friend_number, ev, tt->user_data);
    }
}

void toxtore_friend_connection_status_handler(Tox *tox,
                                              uint32_t friend_number,
                                              TOX_CONNECTION connection_status,
                                              void* user_data)
{
    Toxtore* tt = (Toxtore*) user_data;

    // When connected:
    // - send them our device list
    //   if they are in it, they will know we want to sync with them
    // - find messages we wanted to send them before but couldn't
 
    if (connection_status != TOX_CONNECTION_NONE) {
        // 1. Send device list
        uint8_t *pkt;
        size_t pkt_len = toxtore_make_packet_my_devices(tt, &pkt);
        if (pkt_len > 0) {
            tox_friend_send_lossless_packet(tt->tox, friend_number, pkt, pkt_len, NULL);
            free(pkt);
        }

        // 2. Send messages that we were not able to send before
        uint8_t pk[TOX_PUBLIC_KEY_SIZE];
        tox_friend_get_public_key(tt->tox, friend_number, pk, NULL);
        sqlite3_stmt* stmt;
        int res = sqlite3_queryf(tt->db, &stmt,
                    "SELECT device, seq_no, arg_int, arg_msg FROM events "
                    "WHERE type = ?i AND arg_pk = ?k AND cache_flag = 0 ORDER BY timestamp",
                    TOXTORE_EVENT_FRIEND_SEND, pk);
        while (res == SQLITE_ROW) {
            Dot d;
            d.seq_no = sqlite3_column_int64(stmt, 1);
            memcpy(d.device_pk, sqlite3_column_blob(stmt, 0), TOX_PUBLIC_KEY_SIZE);
            // TODO: this makes the message be sent too many times!
            // (once for each of our devices...)
            bool already_sending = false;
            for (Sending_Message *p = tt->sending; p != NULL; p = p->next) {
                if (p->dot.seq_no == d.seq_no && !memcmp(p->dot.device_pk, d.device_pk, TOX_PUBLIC_KEY_SIZE)) {
                    already_sending = true;
                    break;
                }
            }
            if (!already_sending) {
                TOX_ERR_FRIEND_SEND_MESSAGE err;
                uint32_t t = tox_friend_send_message(tt->tox, friend_number, sqlite3_column_int(stmt, 2), sqlite3_column_text(stmt, 3), sqlite3_column_bytes(stmt, 3), &err);
                if (err == TOX_ERR_FRIEND_SEND_MESSAGE_OK) {
                    Sending_Message *sm = calloc(1, sizeof(Sending_Message));
                    if (sm != NULL) {
                        sm->tox_number = t;
                        sm->dot = d;

                        sm->next = tt->sending;
                        tt->sending = sm;
                    }
                }
            }
            res = sqlite3_step(stmt);
        }
        sqlite3_finalize(stmt);
    }

    if (tt->friend_connection_status_cb != NULL)
        tt->friend_connection_status_cb(tt, friend_number, connection_status, tt->user_data);
}


// ----------------
// TOXTORE PACKET HANDLERS

#define PINVALID { fprintf(stderr, "Invalid packet received from %d:\n", friend_number); toxtore_util_stderr_hexdump(data, length); return; }

void toxtore_handle_packet_my_devices(Toxtore* tt,
                                      uint32_t friend_number,
                                      const uint8_t *data,
                                      size_t length)
{
    Packet_Ptr p = { .u8 = (uint8_t*)data };
    if (*p.u8++ != TOXTORE_TOX_PACKET_ID) PINVALID;
    if (*p.u8++ != TOXTORE_PACKET_MY_DEVICES) PINVALID;
    if (p.u8 >= data + length) PINVALID;
    uint8_t n_dev = *p.u8++;
    if (n_dev > TOXTORE_MAX_DEVICES) PINVALID;
    if (length - (p.u8 - data) != TOX_PUBLIC_KEY_SIZE * n_dev) PINVALID;
    uint8_t *devices_pks = p.u8;

    uint8_t pk[TOX_PUBLIC_KEY_SIZE];
    tox_friend_get_public_key(tt->tox, friend_number, pk, NULL);

    // Update db of friend devices
    toxtore_db_set_friend_devices(tt, pk, n_dev, devices_pks);

    // Check if we are in the pk list
    uint8_t my_pk[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_public_key(tt->tox, my_pk);
    bool are_in_pk_list = false;
    for (int i = 0; i < n_dev; i++) {
        if (!memcmp(devices_pks + i * TOX_PUBLIC_KEY_SIZE, my_pk, TOX_PUBLIC_KEY_SIZE)) {
            are_in_pk_list = true;
            break;
        }
    }
    // If in our device list, update reciprocal value
    bool is_my_device = false;
    for (Active_Device *p = tt->devices; p != NULL; p = p->next) {
        if (p->tox_friend_no == friend_number) {
            is_my_device = true;
            if (p->is_reciprocal != are_in_pk_list) {
                p->is_reciprocal = are_in_pk_list;
                sqlite3_queryf(tt->db, NULL,
                    "UPDATE devices SET is_reciprocal = ?i WHERE pk = ?k",
                    (int32_t)p->is_reciprocal, p->pk);
                // TODO: might want to create some callbacks to call here
            }
            break;
        }
    }
    if (are_in_pk_list) {
        if (is_my_device) {
            uint8_t *pkt;
            size_t pkt_len = toxtore_make_packet_vector_clock(tt, &pkt);
            if (pkt_len > 0) {
                tox_friend_send_lossless_packet(tt->tox, friend_number, pkt, pkt_len, NULL);
                free(pkt);
            }
        } else {
            // Check if it is a deleted device
            // If not, consider this as a device add request
            int res = sqlite3_queryf(tt->db, NULL,
                    "SELECT * FROM devices WHERE pk = ?k AND removed = 1;", pk);
            if (res != SQLITE_ROW) {
                tt->device_add_request_cb(tt, friend_number, pk, tt->user_data);
            }
        }
    }
}

void toxtore_handle_packet_vector_clock(Toxtore* tt,
                                        uint32_t friend_number,
                                        const uint8_t *data,
                                        size_t length)
{
    if (!toxtore_is_friend_my_device(tt, friend_number, NULL)) PINVALID;

    Packet_Ptr p = { .u8 = (uint8_t*)data };
    if (*p.u8++ != TOXTORE_TOX_PACKET_ID) PINVALID;
    if (*p.u8++ != TOXTORE_PACKET_VECTOR_CLOCK) PINVALID;
    if (p.u8 >= data + length) PINVALID;
    uint8_t n_dev = *p.u8++;
    if (n_dev > TOXTORE_MAX_DEVICES) PINVALID;
    if (length - (p.u8 - data) != (8 + TOX_PUBLIC_KEY_SIZE) * n_dev) PINVALID;

    Active_Device *dev = tt->devices;
    while (dev != NULL && dev->tox_friend_no != friend_number) dev = dev->next;
    if (dev == NULL) PINVALID;

    while (dev->missing != NULL) {
        First_Missing_Dot *m = dev->missing;
        dev->missing = m->next;
        free(m);
    }

    for (size_t i = 0; i < n_dev; i++) {
        uint8_t *pk = p.u8; p.pk++;
        uint64_t nlastsn = *p.u64++;
        uint64_t last_sn = ntohll(nlastsn);

        First_Missing_Dot *m = calloc(1, sizeof(First_Missing_Dot));
        if (m != NULL) {
            memcpy(m->device_pk, pk, TOX_PUBLIC_KEY_SIZE);
            m->sn = last_sn + 1;
            m->next = dev->missing;
            dev->missing = m;
        }
    }
}

void toxtore_handle_packet_send_dot(Toxtore* tt,
                                    uint32_t friend_number,
                                    const uint8_t *data,
                                    size_t length)
{
    if (!toxtore_is_friend_my_device(tt, friend_number, NULL)) PINVALID;

    Packet_Ptr p = { .u8 = (uint8_t*)data };
    if (*p.u8++ != TOXTORE_TOX_PACKET_ID) PINVALID;
    if (*p.u8++ != TOXTORE_PACKET_SEND_DOT) PINVALID;
    if (data + length - p.u8 < sizeof(Dot) + 1 + 8) PINVALID;

    Dot d;
    memcpy(d.device_pk, p.pk++, TOX_PUBLIC_KEY_SIZE);
    d.seq_no = ntohll(*p.u64++);
    uint8_t type = *p.u8++;
    uint64_t timestamp = ntohll(*p.u64++);

    sqlite3_queryf(tt->db, NULL,
        "UPDATE devices SET got_until = ?I WHERE pk = ?k AND got_until = ?I - 1",
        d.seq_no, d.device_pk, d.seq_no);

    int res = sqlite3_queryf(tt->db, NULL,
        "SELECT type FROM events WHERE device = ?k AND seq_no = ?I",
        d.device_pk, d.seq_no);
    if (res == SQLITE_ROW) {
        return;     // Already have it!
    }

    switch(type) {
        case TOXTORE_EVENT_FRIEND_ADD:
        {
            if (data+length - p.u8 != TOX_PUBLIC_KEY_SIZE + 1) PINVALID;
            uint8_t *pk = p.u8; p.pk++;
            uint8_t removed = *p.u8++;
            int res = sqlite3_queryf(tt->db, NULL,
                "INSERT INTO events(device, seq_no, timestamp, type, arg_pk, cache_flag) "
                "VALUES(?k, ?I, ?I, ?i, ?k, ?i)",
                d.device_pk, d.seq_no, timestamp, type, pk, (int32_t)removed);
            if (res == SQLITE_DONE && !removed) {
                tox_friend_add_norequest(tt->tox, pk, NULL);
                toxtore_db_ensure_friend(tt, pk);
            }
            break;
        }
        case TOXTORE_EVENT_FRIEND_DEL:
        {
            if (data+length - p.u8 != sizeof(Dot)) PINVALID;
            Dot d2;
            memcpy(d2.device_pk, p.pk++, TOX_PUBLIC_KEY_SIZE);
            d2.seq_no = ntohll(*p.u64++);
            sqlite3_queryf(tt->db, NULL, "UPDATE events SET cache_flag = 1 "
                "WHERE device = ?k AND seq_no = ?I and type = ?i",
                d2.device_pk, d2.seq_no, TOXTORE_EVENT_FRIEND_ADD);
            sqlite3_queryf(tt->db, NULL,
                "INSERT INTO events(device, seq_no, timestamp, type, arg_dot_dev, arg_dot_sn) "
                "VALUES(?k, ?I, ?I, ?i, ?k, ?I)",
                d.device_pk, d.seq_no, timestamp, type, d2.device_pk, d2.seq_no);
            // TODO IMPLEMENT ACTIONS HERE
            break;
        }
        case TOXTORE_EVENT_FRIEND_DEVICES:
        {
            if (data+length - p.u8 < TOX_PUBLIC_KEY_SIZE + 2) PINVALID;
            uint8_t *pk = p.u8; p.pk++;
            uint8_t obsolete = *p.u8++;
            uint8_t ndevices = *p.u8++;
            if (data+length - p.u8 != ndevices * TOX_PUBLIC_KEY_SIZE) PINVALID;
            uint8_t *device_pks = p.u8;
            int res = sqlite3_queryf(tt->db, NULL,
                "INSERT INTO events(device, seq_no, timestamp, type, arg_pk, arg_blob, cache_flag) "
                "VALUES(?k, ?I, ?I, ?i, ?k, ?B, ?i)",
                d.device_pk, d.seq_no, timestamp, type,
                pk, device_pks, ndevices * TOX_PUBLIC_KEY_SIZE, (int32_t)obsolete);
            if (res == SQLITE_DONE && !obsolete) {
                // Check if this is in fact the latest available information
                // If so, update our information
                sqlite3_stmt *stmt;
                res = sqlite3_queryf(tt->db, &stmt,
                    "SELECT device, seq_no FROM events WHERE type = ?i AND arg_pk = ?k "
                    "ORDER BY timestamp DESC LIMIT 1",
                    type, pk);
                if (res == SQLITE_ROW) {
                    if (sqlite3_column_bytes(stmt, 0) != TOX_PUBLIC_KEY_SIZE) {
                        fprintf(stderr, "Device column wrong length\n");
                        sqlite3_finalize(stmt);
                        return;
                    }
                    bool is_latest = sqlite3_column_int64(stmt, 1) == d.seq_no && !memcmp(sqlite3_column_blob(stmt, 0), d.device_pk, TOX_PUBLIC_KEY_SIZE);
                    if (is_latest) {
                        // We are the most recent info! Set other as obsolete & take new info in account.
                        sqlite3_queryf(tt->db, NULL,
                            "UPDATE events SET cache_flag = 1 WHERE type = ?i AND arg_pk = ?k AND (device != ?k OR seq_no != ?I)",
                            type, pk, d.device_pk, d.seq_no);
                        toxtore_db_update_friends_table(tt, pk, ndevices, device_pks);
                    } else {
                        // This new info is actually obsolete, set it as so
                        sqlite3_queryf(tt->db, NULL,
                            "UPDATE events SET cache_flag = 1 WHERE device = ?k AND seq_no = ?I", 
                            d.device_pk, d.seq_no);
                    }
                } else {
                    fprintf(stderr, "Database inconsistency (line %d)\n", __LINE__);
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
        case TOXTORE_EVENT_FRIEND_SEND:
        {
            if (data+length - p.u8 < TOX_PUBLIC_KEY_SIZE + 1 + 4) PINVALID;
            uint8_t *pk = p.u8; p.pk++;
            uint8_t done = *p.u8++;
            uint8_t msgtype = *p.u8++;
            uint32_t msglen = ntohl(*p.u32++);
            if (data+length - p.u8 != msglen) PINVALID;
            sqlite3_queryf(tt->db, NULL,
                "INSERT INTO events(device, seq_no, timestamp, type, arg_pk, arg_int, arg_msg, cache_flag) "
                "VALUES(?k, ?I, ?I, ?i, ?k, ?i, ?S, ?i)",
                d.device_pk, d.seq_no, timestamp, type,
                pk, (int32_t)msgtype, p.u8, msglen, (int32_t)done);
            break;
        }
        case TOXTORE_EVENT_CONFERENCE_SEND:
        {
            if (data+length - p.u8 < TOX_CONFERENCE_ID_SIZE + 1 + 4) PINVALID;
            uint8_t *conf_id = p.u8; p.u8 += TOX_CONFERENCE_ID_SIZE;
            uint8_t done = *p.u8++;
            uint8_t msgtype = *p.u8++;
            uint32_t msglen = ntohl(*p.u32++);
            if (data+length - p.u8 != msglen) PINVALID;
            sqlite3_queryf(tt->db, NULL,
                "INSERT INTO events(device, seq_no, timestamp, type, arg_blob, arg_int, arg_msg, cache_flag) "
                "VALUES(?k, ?I, ?I, ?i, ?B, ?i, ?S, ?i)",
                d.device_pk, d.seq_no, timestamp, type,
                conf_id, TOX_CONFERENCE_ID_SIZE, (int32_t)msgtype, p.u8, msglen, (int32_t)done);
            break;
        }
        case TOXTORE_EVENT_SEND_DONE:
        {
            if (data+length - p.u8 != sizeof(Dot)) PINVALID;
            Dot d2;
            memcpy(d2.device_pk, p.pk++, TOX_PUBLIC_KEY_SIZE);
            d2.seq_no = ntohll(*p.u64++);
            sqlite3_queryf(tt->db, NULL, "UPDATE events SET cache_flag = 1 "
                "WHERE device = ?k AND seq_no = ?I AND (type = ?i OR type = ?i)",
                d2.device_pk, d2.seq_no, (int32_t)TOXTORE_EVENT_FRIEND_SEND,
                (int32_t)TOXTORE_EVENT_CONFERENCE_SEND);
            sqlite3_queryf(tt->db, NULL,
                "INSERT INTO events(device, seq_no, timestamp, type, arg_dot_dev, arg_dot_sn) "
                "VALUES(?k, ?I, ?I, ?i, ?k, ?I)",
                d.device_pk, d.seq_no, timestamp, type, d2.device_pk, d2.seq_no);
            break;
        }
        case TOXTORE_EVENT_FRIEND_RECV:
        {
            if (data+length - p.u8 < TOX_PUBLIC_KEY_SIZE + 1 + 4) PINVALID;
            uint8_t *pk = p.u8; p.pk++;
            uint8_t read = *p.u8++;
            uint8_t msgtype = *p.u8++;
            uint32_t msglen = ntohl(*p.u32++);
            if (data+length - p.u8 != msglen) PINVALID;
            int res = sqlite3_queryf(tt->db, NULL,
                "INSERT INTO events(device, seq_no, timestamp, type, arg_pk, arg_int, arg_msg, cache_flag) "
                "VALUES(?k, ?I, ?I, ?i, ?k, ?i, ?S, ?i)",
                d.device_pk, d.seq_no, timestamp, type,
                pk, (int32_t)msgtype, p.u8, msglen, (int32_t)read);
            if (res == SQLITE_DONE && !read) {
                TOX_ERR_FRIEND_BY_PUBLIC_KEY err;
                uint32_t friend_no = tox_friend_by_public_key(tt->tox, pk, &err);
                if (err == TOX_ERR_FRIEND_BY_PUBLIC_KEY_OK) {
                    tt->friend_message_cb(tt, friend_no, d, type, p.u8, msglen, tt->user_data);
                }
            }
            break;
        }
        case TOXTORE_EVENT_CONFERENCE_RECV:
        {
            if (data+length - p.u8 < TOX_PUBLIC_KEY_SIZE + TOX_CONFERENCE_ID_SIZE + 1 + 4) PINVALID;
            uint8_t *pk = p.u8; p.u8 += TOX_PUBLIC_KEY_SIZE;
            uint8_t *conf_id = p.u8; p.u8 += TOX_CONFERENCE_ID_SIZE;
            uint8_t read = *p.u8++;
            uint8_t msgtype = *p.u8++;
            uint32_t msglen = ntohl(*p.u32++);
            if (data+length - p.u8 != msglen) PINVALID;
            int res = sqlite3_queryf(tt->db, NULL,
                "INSERT INTO events(device, seq_no, timestamp, type, arg_blob, arg_pk, arg_int, arg_msg, cache_flag) "
                "VALUES(?k, ?I, ?I, ?i, ?B, ?k, ?S, ?i)",
                d.device_pk, d.seq_no, timestamp, msgtype,
                conf_id, TOX_CONFERENCE_ID_SIZE, pk, (int32_t)type, p.u8, msglen, (int32_t)read);
            if (res == SQLITE_DONE && !read) {
                // TODO
            }
            break;
        }
        case TOXTORE_EVENT_MARK_READ:
        {
            if (data+length - p.u8 != sizeof(Dot)) PINVALID;
            Dot d2;
            memcpy(d2.device_pk, p.pk++, TOX_PUBLIC_KEY_SIZE);
            d2.seq_no = ntohll(*p.u64++);
            sqlite3_queryf(tt->db, NULL, "UPDATE events SET cache_flag = 1 "
                "WHERE device = ?k AND seq_no = ?I AND (type = ?i OR type = ?i)",
                d2.device_pk, d2.seq_no, (int32_t)TOXTORE_EVENT_FRIEND_RECV,
                (int32_t)TOXTORE_EVENT_CONFERENCE_RECV);
            sqlite3_queryf(tt->db, NULL,
                "INSERT INTO events(device, seq_no, timestamp, type, arg_dot_dev, arg_dot_sn) "
                "VALUES(?k, ?I, ?I, ?i, ?k, ?I)",
                d.device_pk, d.seq_no, timestamp, type, d2.device_pk, d2.seq_no);
            break;
        }
        default:
            PINVALID;
    }
}


void toxtore_friend_lossless_packet_handler(Tox* tox,
                                            uint32_t friend_number,
                                            const uint8_t *data,
                                            size_t length,
                                            void* user_data)
{
    Toxtore* tt = (Toxtore*) user_data;

    if (length >= 2 && data[0] == TOXTORE_TOX_PACKET_ID) {
#ifdef TOXTORE_MUCHDEBUG
        fprintf(stderr, "<<< from %d <<<\n", friend_number);
        stderr_hexdump(data, length);
#endif
        switch (data[1]) {
            case TOXTORE_PACKET_MY_DEVICES:
                toxtore_handle_packet_my_devices(tt, friend_number, data, length);
                break;
            case TOXTORE_PACKET_VECTOR_CLOCK:
                toxtore_handle_packet_vector_clock(tt, friend_number, data, length);
                break;
            case TOXTORE_PACKET_SEND_DOT:
                toxtore_handle_packet_send_dot(tt, friend_number, data, length);
                break;
            default:
                fprintf(stderr, "Unknown Toxtore packet type: %d\n", (int)data[1]);
        }
    } else {
        // TODO allow someone else to handle it
    }
}

/* vim: set sts=4 ts=4 sw=4 tw=0 et :*/
