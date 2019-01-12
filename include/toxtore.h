#include <stdbool.h>
#include <stddef.h>

#include <sqlcipher/sqlite3.h>
#include <tox/tox.h>

/* MULTI DEVICE MODEL
 * ------------------
 *
 * Each device has an independent Tox ID, so devices are identified by
 * their friend number in the Tox friend list.
 *
 * Use the following functions:
 *
 * - toxtore_add_friend_as_device to ask a Tox friend to sync with us when it is not
 *   a real friend but a Tox ID for another device of the same user.
 *
 * - toxtore_rm_friend_as_device to stop syncing with that device, for example if
 *   it has been compromised
 *
 * - toxtore_init_sync to launch the actual sync with another device
 *
 * A special callback device_add_request_cb is called when a Tox ID asks to sync with us.
 * Use toxtore_add_friend_as_device to accept.
 *
 *
 * FUNCTIONS REPLACED BY TOXTORE
 * -----------------------------
 *
 * Use the following functions instead of base Tox functions:
 *
 * - toxtore_friend_send_message instead of tox_friend_send_message
 *   (compatible but returns a dot instead of an uint32_t)
 * - toxtore_conference_send_message instead of tox_conference_send_message
 *   (compatible but returns a dot instead of an uint32_t)
 * - toxtore_friend_add instead of tox_friend_add (compatible)
 * - toxtore_friend_add_norequest instead of tox_friend_add_norequest (compatible)
 * - toxtore_friend_delete instead of tox_friend_delete (compatible)
 *
 *
 * CALLBACKS REPLACED BY TOXTORE
 * -----------------------------
 * 
 * TODO: Hijack ALL tox callbacks so that going to Toxtore is simply a matter of doing: 
 *      s/tox_callback_/toxtore_callback_/ and s/tox_iterate/toxtore_iterate/
 *  and changing the arguments of a few callbacks
 *
 * Toxtore will hijack the following Tox callbacks so dont't use them:
 *
 * tox_callback_friend_request
 * tox_callback_friend_message
 * tox_callback_conference_message
 * tox_callback_friend_read_receipt
 * tox_callback_friend_lossless_packet
 * tox_callback_friend_connection_status
 *
 * Instead, use the following callbacks:
 *
 * toxtore_callback_friend_request (compatible)
 * toxtore_callback_friend_message
 * toxtore_callback_conference_message
 * toxtore_callback_friend_read_receipt
 * toxtore_callback_friend_connection_status
 * (TODO: some are missing, add them)
 *
 *
 * DOTS AND MESSAGE READ STATUS
 * ----------------------------
 *
 * How Dots work: a Dot is an identifier for an event unique across the user's devices,
 * typically a message that was sent or received. The friend_message callback gives you a
 * Dot for the message in question and you must give back the same Dot to the
 * toxtore_mark_read function once the user saw the message.
 *
 * NB: read status is NOT communicated to your friend, but it is stored and synced
 * between devices.
 *
 *
 * TODOS
 * -----
 *
 * This is a minimal viable version of multi-device. Missing features are
 * discussed in toxtore_design.md
 *
 */

#define TOXTORE_EVENT_FRIEND_ADD         0
#define TOXTORE_EVENT_FRIEND_DEL         1
#define TOXTORE_EVENT_FRIEND_DEVICES     2
#define TOXTORE_EVENT_FRIEND_SEND       20
#define TOXTORE_EVENT_CONFERENCE_SEND   21
#define TOXTORE_EVENT_SEND_DONE         22
#define TOXTORE_EVENT_FRIEND_RECV       30
#define TOXTORE_EVENT_CONFERENCE_RECV   31
#define TOXTORE_EVENT_MARK_READ         32

#define TOXTORE_MAX_DEVICES             24      // constrained by packet size

typedef struct Toxtore Toxtore;

typedef struct Dot {
    uint8_t device_pk[TOX_PUBLIC_KEY_SIZE];
    uint64_t seq_no;
} Dot;

int sqlite3_queryf(sqlite3* db, sqlite3_stmt **arg_stmt, const char* fmt, ...);


#define TOXTORE_ERR_NEW_SQLITE ((TOX_ERR_NEW_LOAD_BAD_FORMAT)+10)
#define TOXTORE_ERR_NEW_BAD_PASSPHRASE ((TOX_ERR_NEW_LOAD_BAD_FORMAT)+11)

Toxtore* toxtore_new(struct Tox_Options *options,
                     const char* save_basename,
                     size_t passphrase_len,
                     const uint8_t* passphrase,
                     TOX_ERR_NEW *error);

void toxtore_kill(Toxtore* tt);

void toxtore_iterate(Toxtore* tt, void* user_data);

int toxtore_save(Toxtore* tt);

Tox* toxtore_get_tox(Toxtore* tt);

sqlite3* toxtore_get_db(Toxtore* tt);

// --------- v ---------- Friend management --------- v ----------

uint32_t toxtore_friend_add(Toxtore* tt,
                            const uint8_t *address,
                            const uint8_t *message,
                            size_t length,
                            TOX_ERR_FRIEND_ADD *error);

uint32_t toxtore_friend_add_norequest(Toxtore *tt,
                                      const uint8_t *public_key,
                                      TOX_ERR_FRIEND_ADD *error);

bool toxtore_friend_delete(Toxtore *tt, uint32_t friend_number, TOX_ERR_FRIEND_DELETE *error);

bool toxtore_is_same_person(Toxtore* tt, uint32_t friend_n1, uint32_t friend_n2);
size_t toxtore_other_devices(Toxtore* tt, uint32_t friend_n, uint32_t** friend_nums);
uint32_t toxtore_get_preferred_device(Toxtore* tt, uint32_t friend_n);

// --------- v ---------- Device management --------- v ----------

bool toxtore_add_friend_as_device(Toxtore* tt, uint32_t friend_number);
bool toxtore_rm_friend_as_device(Toxtore* tt, uint32_t friend_number);
size_t toxtore_device_list(Toxtore* tt, uint32_t** friends_nums);
bool toxtore_is_friend_my_device(Toxtore* tt, uint32_t friend_number, bool* out_reciprocal);
bool toxtore_is_pk_my_device(Toxtore* tt, uint8_t *pk, bool* out_reciprocal);

void toxtore_init_sync(Toxtore* tt, uint32_t friend_num);

// --------- v ---------- Messaging --------- v ----------

Dot toxtore_friend_send_message(Toxtore* tt,
                                uint32_t friend_number,
                                TOX_MESSAGE_TYPE type,
                                const uint8_t* msg,
                                size_t length,
                                TOX_ERR_FRIEND_SEND_MESSAGE *error);

Dot toxtore_conference_send_message(Toxtore* tt,
                                    uint32_t conference_number,
                                    TOX_MESSAGE_TYPE type,
                                    const uint8_t *message,
                                    size_t length,
                                    TOX_ERR_CONFERENCE_SEND_MESSAGE *error);

void toxtore_mark_read(Toxtore* tt, Dot ev);



/* ************************ *
 *          CALLBACKS       *
 * ************************ */

// When we receive a friend request
typedef void toxtore_friend_request_cb(Toxtore *tt,
                                       const uint8_t *public_key,
                                       const uint8_t *message,
                                       size_t length,
                                       void *user_data);
void toxtore_callback_friend_request(Toxtore *tt, toxtore_friend_request_cb *callback);

// When we receive a message from a friend
typedef void toxtore_friend_message_cb(Toxtore *tt,
                                       uint32_t friend_number,
                                       Dot dot,
                                       TOX_MESSAGE_TYPE type,
                                       const uint8_t *message,
                                       size_t length,
                                       void *user_data);
void toxtore_callback_friend_message(Toxtore *tt, toxtore_friend_message_cb *callback);

// When we receive a message in a conference
typedef void toxtore_conference_message_cb(Toxtore *tt,
                                           uint32_t conference_number,
                                           uint32_t peer_number,
                                           Dot dot,
                                           TOX_MESSAGE_TYPE type,
                                           const uint8_t *message,
                                           size_t length,
                                           void *user_data);
void toxtore_callback_conference_message(Toxtore* tt, toxtore_conference_message_cb *callback);

// When a message to a friend has been sent successfully
typedef void toxtore_friend_read_receipt_cb(Toxtore *tt,
                                            uint32_t friend_number,
                                            Dot dot,
                                            void *user_data);
void toxtore_callback_friend_read_receipt(Toxtore *tt, toxtore_friend_read_receipt_cb *callback);

// When a friend goes online/offline
typedef void toxtore_friend_connection_status_cb(Toxtore *tt,
                                                 uint32_t friend_number,
                                                 TOX_CONNECTION connection_status,
                                                 void *user_data);
void toxtore_callback_friend_connection_status(Toxtore *tt, toxtore_friend_connection_status_cb *callback);

// When a Tox ID asks to be another of our devices and sync with us
typedef void toxtore_device_add_request_cb(Toxtore *tt,
                                           uint32_t friend_number,
                                           const uint8_t *public_key,
                                           void *user_data);
void toxtore_callback_device_add_request(Toxtore* tt, toxtore_device_add_request_cb *callback);


/* vim: set sts=4 ts=4 sw=4 tw=0 et :*/
