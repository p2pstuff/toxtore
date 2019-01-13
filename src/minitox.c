/*
 * MiniTox - A minimal client for Tox
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <assert.h>

#include <termios.h>
#include <unistd.h>
#include <fcntl.h>

#include <tox/tox.h>
#include "toxtore.h"

#define sqlite3_queryf toxtore_util_sqlite3_queryf

/*******************************************************************************
 *
 * Consts & Macros
 *
 ******************************************************************************/

struct DHT_node {
    const char *ip;
    uint16_t port;
    const char key_hex[TOX_PUBLIC_KEY_SIZE*2 + 1];
};

struct DHT_node bootstrap_nodes[] = {

    // Setup tox bootrap nodes

    {"node.tox.biribiri.org",      33445, "F404ABAA1C99A9D37D61AB54898F56793E1DEF8BD46B1038B9D822E8460FAB67"},
    {"128.199.199.197",            33445, "B05C8869DBB4EDDD308F43C1A974A20A725A36EACCA123862FDE9945BF9D3E09"},
    {"2400:6180:0:d0::17a:a001",   33445, "B05C8869DBB4EDDD308F43C1A974A20A725A36EACCA123862FDE9945BF9D3E09"},
};


#define LINE_MAX_SIZE 512  // If input line's length surpassed this value, it will be truncated.

#define PORT_RANGE_START 33445     // tox listen port range
#define PORT_RANGE_END   34445

#define AREPL_INTERVAL  30  // Async REPL iterate interval. unit: millisecond.

#define DEFAULT_CHAT_HIST_COUNT  20 // how many items of chat history to show by default;

#define SAVEDATA_AFTER_COMMAND true // whether save data after executing any command

/// Macros for terminal display

#define CODE_ERASE_LINE    "\r\033[2K"

#define RESET_COLOR        "\x01b[0m"
#define SELF_TALK_COLOR    "\x01b[90m" // bright black
#define GUEST_TALK_COLOR   "\x01b[35m" // magenta
#define CMD_PROMPT_COLOR   "\x01b[34m" // blue

#define CMD_PROMPT   CMD_PROMPT_COLOR "> " RESET_COLOR // green
#define FRIEND_TALK_PROMPT  CMD_PROMPT_COLOR "%-.12s << " RESET_COLOR
#define GROUP_TALK_PROMPT  CMD_PROMPT_COLOR "%-.12s <<< " RESET_COLOR

#define GUEST_MSG_PREFIX  GUEST_TALK_COLOR "%s  %12.12s | " RESET_COLOR
#define SELF_MSG_PREFIX  SELF_TALK_COLOR "%s  %12.12s | " RESET_COLOR
#define CMD_MSG_PREFIX  CMD_PROMPT

#define GUEST_MSG_NEW_FLAG "\x01b[33m\x01b[1m*" RESET_COLOR
#define SELF_MSG_SENDING_FLAG "\x01b[31m…" RESET_COLOR

bool must_arepl_reprint = false;

#define PRINT(_fmt, ...) \
    fputs(CODE_ERASE_LINE,stdout);\
    printf(_fmt "\n", ##__VA_ARGS__);\
    must_arepl_reprint = true;

#define COLOR_PRINT(_color, _fmt,...) PRINT(_color _fmt RESET_COLOR, ##__VA_ARGS__)

#define INFO(_fmt,...) COLOR_PRINT("\x01b[36m", _fmt, ##__VA_ARGS__)  // cyan
#define WARN(_fmt,...) COLOR_PRINT("\x01b[33m", _fmt, ##__VA_ARGS__) // yellow
#define ERROR(_fmt,...) COLOR_PRINT("\x01b[31m", _fmt, ##__VA_ARGS__) // red


/*******************************************************************************
 *
 * Headers
 *
 ******************************************************************************/

Toxtore *toxtore;
Tox *tox;

typedef void CommandHandler(int narg, char **args);

struct Command {
    char* name;
    char* desc;
    int   narg;
    CommandHandler *handler;
};

struct GroupUserData {
    uint32_t friend_num;
    uint8_t *cookie;
    size_t length;
};

struct FriendUserData {
    uint8_t pubkey[TOX_PUBLIC_KEY_SIZE];
};

union RequestUserData {
    struct GroupUserData group;
    struct FriendUserData friend;
};

struct Request {
    char *msg;
    uint32_t id;
    bool is_friend_request;
    union RequestUserData userdata;
    struct Request *next;
};

struct GroupPeer {
    uint8_t pubkey[TOX_PUBLIC_KEY_SIZE];
    char name[TOX_MAX_NAME_LENGTH + 1];
};

struct Group {
    uint32_t group_num;
    char *title;
    struct GroupPeer *peers;
    size_t peers_count;

    struct Group *next;
};

struct Friend {
    uint32_t friend_num;
    char *name;
    char *status_message;
    uint8_t pubkey[TOX_PUBLIC_KEY_SIZE];
    TOX_CONNECTION connection;

    bool add_device_req;
    bool is_device;

    struct Friend *next;
};

int NEW_STDIN_FILENO = STDIN_FILENO;

struct Request *requests = NULL;

struct Friend *friends = NULL;
struct Friend self;
struct Group *groups = NULL;

enum TALK_TYPE { TALK_TYPE_FRIEND, TALK_TYPE_GROUP, TALK_TYPE_COUNT, TALK_TYPE_NULL = UINT32_MAX };

uint32_t TalkingTo = TALK_TYPE_NULL;


/*******************************************************************************
 *
 * Utils
 *
 ******************************************************************************/

#define RESIZE(key, size_key, length) \
    if ((size_key) < (length + 1)) { \
        size_key = (length+1);\
        key = calloc(1, size_key);\
    }

#define LIST_FIND(_p, _condition) \
    for (;*(_p) != NULL;_p = &((*_p)->next)) { \
        if (_condition) { \
            break;\
        }\
    }\

#define INDEX_TO_TYPE(idx) (idx % TALK_TYPE_COUNT)
#define INDEX_TO_NUM(idx)  (idx / TALK_TYPE_COUNT)
#define GEN_INDEX(num,type) (num * TALK_TYPE_COUNT + type)

bool str2uint(char *str, uint32_t *num) {
    char *str_end;
    long l = strtol(str,&str_end,10);
    if (str_end == str || l < 0 ) return false;
    *num = (uint32_t)l;
    return true;
}

char* getftime(void) {
    static char timebuf[64];

    time_t tt = time(NULL);
    struct tm *tm = localtime(&tt);
    strftime(timebuf, sizeof(timebuf), "%H:%M:%S", tm);
    return timebuf;
}

char* getftimets(uint64_t ts) {
    static char timebuf[64];

    time_t epoch_time = ts / 1000;
    struct tm *tm = localtime(&epoch_time);
    strftime(timebuf, sizeof(timebuf), "%H:%M:%S", tm);
    return timebuf;
}

const char * connection_enum2text(TOX_CONNECTION conn) {
    switch (conn) {
        case TOX_CONNECTION_NONE:
            return "Offline";
        case TOX_CONNECTION_TCP:
            return "Online(TCP)";
        case TOX_CONNECTION_UDP:
            return "Online(UDP)";
        default:
            return "UNKNOWN";
    }
}

struct Friend *getfriend(uint32_t friend_num) {
    struct Friend **p = &friends;
    LIST_FIND(p, (*p)->friend_num == friend_num);
    return *p;
}

struct Friend *addfriend(uint32_t friend_num) {
    struct Friend *f = calloc(1, sizeof(struct Friend));
    f->next = friends;
    friends = f;
    f->friend_num = friend_num;
    f->connection = TOX_CONNECTION_NONE;
    tox_friend_get_public_key(tox, friend_num, f->pubkey, NULL);
    return f;
}


bool delfriend(uint32_t friend_num) {
    struct Friend **p = &friends;
    LIST_FIND(p, (*p)->friend_num == friend_num);
    struct Friend *f = *p;
    if (f) {
        *p = f->next;
        if (f->name) free(f->name);
        if (f->status_message) free(f->status_message);
        free(f);
        return 1;
    }
    return 0;
}

struct Group *addgroup(uint32_t group_num) {
    struct Group *cf = calloc(1, sizeof(struct Group));
    cf->next = groups;
    groups = cf;

    cf->group_num = group_num;

    return cf;
}

bool delgroup(uint32_t group_num) {
    struct Group **p = &groups;
    LIST_FIND(p, (*p)->group_num == group_num);
    struct Group *cf = *p;
    if (cf) {
        *p = cf->next;
        if (cf->peers) free(cf->peers);
        if (cf->title) free(cf->title);
        free(cf);
        return 1;
    }
    return 0;
}

struct Group *getgroup(uint32_t group_num) {
    struct Group **p = &groups;
    LIST_FIND(p, (*p)->group_num == group_num);
    return *p;
}

uint8_t *hex2bin(const char *hex)
{
    size_t len = strlen(hex) / 2;
    uint8_t *bin = malloc(len);

    for (size_t i = 0; i < len; ++i, hex += 2) {
        sscanf(hex, "%2hhx", &bin[i]);
    }

    return bin;
}

char *bin2hex(const uint8_t *bin, size_t length) {
    char *hex = malloc(2*length + 1);
    char *saved = hex;
    for (int i=0; i<length;i++,hex+=2) {
        sprintf(hex, "%02X",bin[i]);
    }
    return saved;
}


/*******************************************************************************
 *
 * Async REPL
 *
 ******************************************************************************/

struct AsyncREPL {
    char *line;
    char *prompt;
    size_t sz;
    int  nbuf;
    int nstack;
};

struct termios saved_tattr;

struct AsyncREPL *async_repl;

void arepl_exit(void) {
    tcsetattr(NEW_STDIN_FILENO, TCSAFLUSH, &saved_tattr);
}

void setup_arepl(void) {
    if (!(isatty(STDIN_FILENO) && isatty(STDOUT_FILENO))) {
        fputs("! stdout & stdin should be connected to tty", stderr);
        exit(1);
    }
    async_repl = malloc(sizeof(struct AsyncREPL));
    async_repl->nbuf = 0;
    async_repl->nstack = 0;
    async_repl->sz = LINE_MAX_SIZE;
    async_repl->line = malloc(LINE_MAX_SIZE);
    async_repl->prompt = malloc(LINE_MAX_SIZE);

    strcpy(async_repl->prompt, CMD_PROMPT);

    // stdin and stdout may share the same file obj,
    // reopen stdin to avoid accidentally getting stdout modified.

    char stdin_path[4080];  // 4080 is large enough for a path length for *nix system.
#ifdef F_GETPATH   // macosx
    if (fcntl(STDIN_FILENO, F_GETPATH, stdin_path) == -1) {
        fputs("! fcntl get stdin filepath failed", stderr);
        exit(1);
    }
#else  // linux
    strcpy(stdin_path, "/dev/stdin");
    // if (readlink("/proc/self/fd/0", stdin_path, sizeof(stdin_path)) == -1) {
    //     fputs("! get stdin filename failed", stderr);
    //     exit(1);
    // }
#endif

    NEW_STDIN_FILENO = open(stdin_path, O_RDONLY);
    if (NEW_STDIN_FILENO == -1) {
        perror("reopen stdin failed");
        exit(1);
    }
    close(STDIN_FILENO);

    // Set stdin to Non-Blocking
    int flags = fcntl(NEW_STDIN_FILENO, F_GETFL, 0);
    fcntl(NEW_STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);

    /* Set stdin to Non-Canonical terminal mode. */
    struct termios tattr;
    tcgetattr(NEW_STDIN_FILENO, &tattr);
    saved_tattr = tattr;  // save it to restore when exit
    tattr.c_lflag &= ~(ICANON|ECHO); /* Clear ICANON. */
    tattr.c_cc[VMIN] = 1;
    tattr.c_cc[VTIME] = 0;
    tcsetattr(NEW_STDIN_FILENO, TCSAFLUSH, &tattr);

    atexit(arepl_exit);
}

void arepl_reprint(struct AsyncREPL *arepl) {
    fputs(CODE_ERASE_LINE, stdout);
    if (arepl->prompt) fputs(arepl->prompt, stdout);
    if (arepl->nbuf > 0) printf("%.*s", arepl->nbuf, arepl->line);
    if (arepl->nstack > 0) {
        printf("%.*s",(int)arepl->nstack, arepl->line + arepl->sz - arepl->nstack);
        printf("\033[%dD",arepl->nstack); // move cursor
    }
    fflush(stdout);
}

#define _AREPL_CURSOR_LEFT() arepl->line[arepl->sz - (++arepl->nstack)] = arepl->line[--arepl->nbuf]
#define _AREPL_CURSOR_RIGHT() arepl->line[arepl->nbuf++] = arepl->line[arepl->sz - (arepl->nstack--)]

int arepl_readline(struct AsyncREPL *arepl, char c, char *line, size_t sz){
    static uint32_t escaped = 0;
    if (c == '\033') { // mark escape code
        escaped = 1;
        return 0;
    }

    if (escaped>0) escaped++;

    switch (c) {
        case '\n': {
            int ret = snprintf(line, sz, "%.*s%.*s\n",(int)arepl->nbuf, arepl->line, (int)arepl->nstack, arepl->line + arepl->sz - arepl->nstack);
            arepl->nbuf = 0;
            arepl->nstack = 0;
            return ret;
        }

        case '\010':  // C-h
        case '\177':  // Backspace
            if (arepl->nbuf > 0) arepl->nbuf--;
            break;
        case '\025': // C-u
            arepl->nbuf = 0;
            break;
        case '\013': // C-k Vertical Tab
            arepl->nstack = 0;
            break;
        case '\001': // C-a
            while (arepl->nbuf > 0) _AREPL_CURSOR_LEFT();
            break;
        case '\005': // C-e
            while (arepl->nstack > 0) _AREPL_CURSOR_RIGHT();
            break;
        case '\002': // C-b
            if (arepl->nbuf > 0) _AREPL_CURSOR_LEFT();
            break;
        case '\006': // C-f
            if (arepl->nstack > 0) _AREPL_CURSOR_RIGHT();
            break;
        case '\027': // C-w: backward delete a word
            while (arepl->nbuf>0 && arepl->line[arepl->nbuf-1] == ' ') arepl->nbuf--;
            while (arepl->nbuf>0 && arepl->line[arepl->nbuf-1] != ' ') arepl->nbuf--;
            break;

        case 'D':
        case 'C':
            if (escaped == 3 && arepl->nbuf >= 1 && arepl->line[arepl->nbuf-1] == '[') { // arrow keys
                arepl->nbuf--;
                if (c == 'D' && arepl->nbuf > 0) _AREPL_CURSOR_LEFT(); // left arrow: \033[D
                if (c == 'C' && arepl->nstack > 0) _AREPL_CURSOR_RIGHT(); // right arrow: \033[C
                break;
            }
            // fall through to default case
        default:
            arepl->line[arepl->nbuf++] = c;
    }
    return 0;
}

/*******************************************************************************
 *
 * Tox Callbacks
 *
 ******************************************************************************/

void friend_message_cb(Toxtore *tt, uint32_t friend_num, Dot dot, TOX_MESSAGE_TYPE type, const uint8_t *message,
                                   size_t length, void *user_data)
{
    struct Friend *f = getfriend(friend_num);
    if (!f) return;

    if (GEN_INDEX(friend_num, TALK_TYPE_FRIEND) == TalkingTo) {
        toxtore_mark_read(toxtore, dot);
        if (type == TOX_MESSAGE_TYPE_ACTION) {
            PRINT(GUEST_MSG_PREFIX GUEST_MSG_NEW_FLAG " * %.*s", getftime(), f->name, (int)length, (char*)message);
        } else {
            PRINT(GUEST_MSG_PREFIX GUEST_MSG_NEW_FLAG " %.*s", getftime(), f->name, (int)length, (char*)message);
        }
    } else {
        INFO("* receive message from %s, use `/go <contact_index>` to talk\n",f->name);
    }
}

void friend_name_cb(Tox *tox, uint32_t friend_num, const uint8_t *name, size_t length, void *user_data) {
    struct Friend *f = getfriend(friend_num);

    if (f) {
        f->name = realloc(f->name, length+1);
        sprintf(f->name, "%.*s", (int)length, (char*)name);
        if (GEN_INDEX(friend_num, TALK_TYPE_FRIEND) == TalkingTo) {
            INFO("* Opposite changed name to %.*s", (int)length, (char*)name)
            sprintf(async_repl->prompt, FRIEND_TALK_PROMPT, f->name);
        }
    }
}

void friend_status_message_cb(Tox *tox, uint32_t friend_num, const uint8_t *message, size_t length, void *user_data) {
    struct Friend *f = getfriend(friend_num);
    if (f) {
        f->status_message = realloc(f->status_message, length + 1);
        sprintf(f->status_message, "%.*s",(int)length, (char*)message);
    }
}

void friend_connection_status_cb(Toxtore *toxtore, uint32_t friend_num, TOX_CONNECTION connection_status, void *user_data)
{
    struct Friend *f = getfriend(friend_num);
    if (f) {
        f->connection = connection_status;
        INFO("* %s is %s", f->name, connection_enum2text(connection_status));
    }
}

void friend_request_cb(Toxtore *tt, const uint8_t *public_key, const uint8_t *message, size_t length, void *user_data) {
    INFO("* receive friend request(use `/accept` to see).");

    struct Request *req = malloc(sizeof(struct Request));

    req->id = 1 + ((requests != NULL) ? requests->id : 0);
    req->is_friend_request = true;
    memcpy(req->userdata.friend.pubkey, public_key, TOX_PUBLIC_KEY_SIZE);
    req->msg = malloc(length + 1);
    sprintf(req->msg, "%.*s", (int)length, (char*)message);

    req->next = requests;
    requests = req;
}

void friend_added_cb(Toxtore *tt, uint32_t friend_no, const uint8_t *public_key, void *user_data) {
    addfriend(friend_no);
}

void self_connection_status_cb(Tox *tox, TOX_CONNECTION connection_status, void *user_data)
{
    self.connection = connection_status;
    INFO("* You are %s", connection_enum2text(connection_status));
}

void device_add_request_cb(Toxtore* tt, uint32_t friend_number, const uint8_t *public_key, void* user_data)
{
    for (struct Friend *p = friends; p != NULL; p = p->next) {
        if (p->friend_num == friend_number) {
            if (!p->is_device) {
                INFO("Device add request, type /contacts to view request");
                p->add_device_req = true;
            }
            break;
        }
    }
}

void group_invite_cb(Tox *tox, uint32_t friend_num, TOX_CONFERENCE_TYPE type, const uint8_t *cookie, size_t length, void *user_data) {
    struct Friend *f = getfriend(friend_num);
    if (f) {
        if (type == TOX_CONFERENCE_TYPE_AV) {
            WARN("* %s invites you to an AV group, which has not been supported.", f->name);
            return;
        }
        INFO("* %s invites you to a group(try `/accept` to see)",f->name);
        struct Request *req = malloc(sizeof(struct Request));
        req->id = 1 + ((requests != NULL) ? requests->id : 0);
        req->next = requests;
        requests = req;

        req->is_friend_request = false;
        req->userdata.group.cookie = malloc(length);
        memcpy(req->userdata.group.cookie, cookie, length),
        req->userdata.group.length = length;
        req->userdata.group.friend_num = friend_num;
        int sz = snprintf(NULL, 0, "%s%s", "From ", f->name);
        req->msg = malloc(sz + 1);
        sprintf(req->msg, "%s%s", "From ", f->name);
    }
}

void group_title_cb(Tox *tox, uint32_t group_num, uint32_t peer_number, const uint8_t *title, size_t length, void *user_data) {
    struct Group *cf = getgroup(group_num);
    if (cf) {
        cf->title = realloc(cf->title, length+1);
        sprintf(cf->title, "%.*s", (int)length, (char*)title);
        if (GEN_INDEX(group_num, TALK_TYPE_GROUP) == TalkingTo) {
            INFO("* Group title changed to %s", cf->title);
            sprintf(async_repl->prompt, GROUP_TALK_PROMPT, cf->title);
        }
    }
}

void group_message_cb(Toxtore *tt, uint32_t group_num, uint32_t peer_number, Dot dot, TOX_MESSAGE_TYPE type, const uint8_t *message, size_t length, void *user_data) {
    struct Group *cf = getgroup(group_num);
    if (!cf) return;

    if (tox_conference_peer_number_is_ours(tox, group_num, peer_number, NULL))  return;

    if (type != TOX_MESSAGE_TYPE_NORMAL) {
        INFO("* receive MESSAGE ACTION type from group %s, no supported", cf->title);
        return;
    }
    if (peer_number >= cf->peers_count) {
        ERROR("! Unknown peer_number, peer_count:%zu, peer_number:%u", cf->peers_count, peer_number);
        return;
    }

    struct GroupPeer *peer = &cf->peers[peer_number];

    if (GEN_INDEX(group_num, TALK_TYPE_GROUP) == TalkingTo) {
        toxtore_mark_read(toxtore, dot);
        PRINT(GUEST_MSG_PREFIX GUEST_MSG_NEW_FLAG " %.*s", getftime(), peer->name, (int)length, (char*)message);
    } else {
        INFO("* receive group message from %s, in group %s",peer->name, cf->title);
    }
}

void group_peer_list_changed_cb(Tox *tox, uint32_t group_num, void *user_data) {
    struct Group *cf = getgroup(group_num);
    if (!cf) return;

    TOX_ERR_CONFERENCE_PEER_QUERY err;
    uint32_t count = tox_conference_peer_count(tox, group_num, &err);
    if (err != TOX_ERR_CONFERENCE_PEER_QUERY_OK) {
        ERROR("get group peer count failed, errcode:%d",err);
        return;
    }
    if (cf->peers) free(cf->peers);
    cf->peers = calloc(count, sizeof(struct GroupPeer));
    cf->peers_count = count;

    for (int i=0;i<count;i++) {
        struct GroupPeer *p = cf->peers + i;
        tox_conference_peer_get_name(tox, group_num, i, (uint8_t*)p->name, NULL);
        tox_conference_peer_get_public_key(tox, group_num, i, p->pubkey,NULL);
    }
}
void group_peer_name_cb(Tox *tox, uint32_t group_num, uint32_t peer_num, const uint8_t *name, size_t length, void *user_data) {
    struct Group *cf = getgroup(group_num);
    if (!cf || peer_num >= cf->peers_count) {
        ERROR("! Unexpected group_num/peer_num in group_peer_name_cb");
        return;
    }

    struct GroupPeer *p = &cf->peers[peer_num];
    sprintf(p->name, "%.*s", (int)length, (char*)name);
}


/*******************************************************************************
 *
 * Tox Setup
 *
 ******************************************************************************/

void create_tox(const char* profile, const char* passphrase)
{
    char* savedata_basename = malloc(256);
    if (savedata_basename == NULL) {
        fprintf(stderr, "Malloc failure\n");
        exit(1);
    }
    snprintf(savedata_basename, 256, "%s/.config/tox/%s", getenv("HOME"), profile);

    struct Tox_Options *options = tox_options_new(NULL);
    tox_options_set_start_port(options, PORT_RANGE_START);
    tox_options_set_end_port(options, PORT_RANGE_END);

    TOX_ERR_NEW error;
    toxtore = toxtore_new(options, savedata_basename, 4, (uint8_t*)passphrase, &error);
    if (error != TOX_ERR_NEW_OK) {
        fprintf(stderr, "Could not create tox/toxtore: %d\n", error);
        exit(1);
    }
    tox = toxtore_get_tox(toxtore);

    tox_options_free(options);
}

void init_friends(void) {
    size_t sz = tox_self_get_friend_list_size(tox);
    uint32_t *friend_list = malloc(sizeof(uint32_t) * sz);
    tox_self_get_friend_list(tox, friend_list);

    size_t len;

    for (int i = 0;i<sz;i++) {
        uint32_t friend_num = friend_list[i];
        struct Friend *f = addfriend(friend_num);

        len = tox_friend_get_name_size(tox, friend_num, NULL) + 1;
        f->name = calloc(1, len);
        tox_friend_get_name(tox, friend_num, (uint8_t*)f->name, NULL);

        len = tox_friend_get_status_message_size(tox, friend_num, NULL) + 1;
        f->status_message = calloc(1, len);
        tox_friend_get_status_message(tox, friend_num, (uint8_t*)f->status_message, NULL);

        tox_friend_get_public_key(tox, friend_num, f->pubkey, NULL);
    }
    free(friend_list);

    // add self
    self.friend_num = TALK_TYPE_NULL;
    len = tox_self_get_name_size(tox) + 1;
    self.name = calloc(1, len);
    tox_self_get_name(tox, (uint8_t*)self.name);

    len = tox_self_get_status_message_size(tox) + 1;
    self.status_message = calloc(1, len);
    tox_self_get_status_message(tox, (uint8_t*)self.status_message);

    tox_self_get_public_key(tox, self.pubkey);
}

void bootstrap(void)
{
    INFO("Connecting to Tox network, please wait...")
    for (size_t i = 0; i < sizeof(bootstrap_nodes)/sizeof(struct DHT_node); i ++) {
        uint8_t *bin = hex2bin(bootstrap_nodes[i].key_hex);
        tox_bootstrap(tox, bootstrap_nodes[i].ip, bootstrap_nodes[i].port, bin, NULL);
        free(bin);
    }
}

void setup_tox(const char* profile, const char* passphrase)
{
    create_tox(profile, passphrase);
    init_friends();
    bootstrap();

    ////// register callbacks

    // self
    tox_callback_self_connection_status(tox, self_connection_status_cb);
    toxtore_callback_device_add_request(toxtore, device_add_request_cb);

    // friend
    toxtore_callback_friend_request(toxtore, friend_request_cb);
    toxtore_callback_friend_added(toxtore, friend_added_cb);
    toxtore_callback_friend_message(toxtore, friend_message_cb);
    tox_callback_friend_name(tox, friend_name_cb);
    tox_callback_friend_status_message(tox, friend_status_message_cb);
    toxtore_callback_friend_connection_status(toxtore, friend_connection_status_cb);

    // group
    tox_callback_conference_invite(tox, group_invite_cb);
    tox_callback_conference_title(tox, group_title_cb);
    toxtore_callback_conference_message(toxtore, group_message_cb);
    tox_callback_conference_peer_list_changed(tox, group_peer_list_changed_cb);
    tox_callback_conference_peer_name(tox, group_peer_name_cb);
}

/*******************************************************************************
 *
 * Commands
 *
 ******************************************************************************/

void command_help(int narg, char **args);

void command_guide(int narg, char **args) {
    PRINT("This program is an minimal workable implementation of Tox client.");
    PRINT("As it pursued simplicity at the cost of robustness and efficiency,");
    PRINT("It should only be used for learning or playing with, instead of daily use.\n");

    PRINT("Commands are any input lines with leading `/`,");
    PRINT("Command args are seprated by blanks,");
    PRINT("while some special commands may accept any-character string, like `/setname` and `/setstmsg`.\n");

    PRINT("Use `/setname <YOUR NAME>` to set your name");
    PRINT("Use `/info` to see your Name, Tox Id and Network Connection.");
    PRINT("Use `/contacts` to list friends and groups, and use `/go <TARGET>` to talk to one of them.");
    PRINT("Finally, use `/help` to get a list of available commands.\n");

    PRINT("HAVE FUN!\n")
}

void _print_friend_info(struct Friend *f, bool is_self) {
    PRINT("%-15s%s", "Name:", f->name);

    if (is_self) {
        uint8_t tox_id_bin[TOX_ADDRESS_SIZE];
        tox_self_get_address(tox, tox_id_bin);
        char *hex = bin2hex(tox_id_bin, sizeof(tox_id_bin));
        PRINT("%-15s%s","Tox ID:", hex);
        free(hex);
    }

    char *hex = bin2hex(f->pubkey, sizeof(f->pubkey));
    PRINT("%-15s%s","Public Key:", hex);
    free(hex);
    PRINT("%-15s%s", "Status Msg:",f->status_message);
    PRINT("%-15s%s", "Network:",connection_enum2text(f->connection));
}

void command_info(int narg, char **args) {
    if (narg == 0) { // self
        _print_friend_info(&self, true);
        return;
    }

    uint32_t contact_idx;
    if (!str2uint(args[0],&contact_idx)) goto FAIL;

    uint32_t num = INDEX_TO_NUM(contact_idx);
    switch (INDEX_TO_TYPE(contact_idx)) {
        case TALK_TYPE_FRIEND: {
            struct Friend *f = getfriend(num);
            if (f) {
                _print_friend_info(f, false);
                return;
            }
            break;
        }
        case TALK_TYPE_GROUP: {
            struct Group *cf = getgroup(num);
            if (cf) {
                PRINT("GROUP TITLE:\t%s",cf->title);
                PRINT("PEER COUNT:\t%zu", cf->peers_count);
                PRINT("Peers:");
                for (int i=0;i<cf->peers_count;i++){
                    PRINT("\t%s",cf->peers[i].name);
                }
                return;
            }
            break;
        }
    }
FAIL:
    WARN("^ Invalid contact index");
}

void command_setname(int narg, char **args) {
    char *name = args[0];
    size_t len = strlen(name);
    TOX_ERR_SET_INFO err;
    tox_self_set_name(tox, (uint8_t*)name, strlen(name), &err);

    if (err != TOX_ERR_SET_INFO_OK) {
        ERROR("! set name failed, errcode:%d", err);
        return;
    }

    self.name = realloc(self.name, len + 1);
    strcpy(self.name, name);
}

void command_setstmsg(int narg, char **args) {
    char *status = args[0];
    size_t len = strlen(status);
    TOX_ERR_SET_INFO err;
    tox_self_set_status_message(tox, (uint8_t*)status, strlen(status), &err);
    if (err != TOX_ERR_SET_INFO_OK) {
        ERROR("! set status message failed, errcode:%d", err);
        return;
    }

    self.status_message = realloc(self.status_message, len+1);
    strcpy(self.status_message, status);
}

void command_add(int narg, char **args) {
    char *hex_id = args[0];
    char *msg = "";
    if (narg > 1) msg = args[1];

    uint8_t *bin_id = hex2bin(hex_id);
    TOX_ERR_FRIEND_ADD err;
    uint32_t friend_num = toxtore_friend_add(toxtore, bin_id, (uint8_t*)msg, strlen(msg), &err);
    free(bin_id);

    if (err != TOX_ERR_FRIEND_ADD_OK) {
        ERROR("! add friend failed, errcode:%d",err);
        return;
    }

    addfriend(friend_num);
}

void command_del(int narg, char **args) {
    uint32_t contact_idx;
    if (!str2uint(args[0], &contact_idx)) goto FAIL;
    uint32_t num = INDEX_TO_NUM(contact_idx);
    switch (INDEX_TO_TYPE(contact_idx)) {
        case TALK_TYPE_FRIEND:
            if (delfriend(num)) {
                toxtore_friend_delete(toxtore, num, NULL);
                return;
            }
            break;
        case TALK_TYPE_GROUP:
            if (delgroup(num)) {
                tox_conference_delete(tox, num, NULL);
                return;
            }
            break;
    }
FAIL:
    WARN("^ Invalid contact index");
}

void command_contacts(int narg, char **args) {
    struct Friend *f = friends;
    PRINT("#Friends(conctact_index|name|connection|status message):\n");
    for (;f != NULL; f = f->next) {
        uint32_t index = GEN_INDEX(f->friend_num, TALK_TYPE_FRIEND);
        PRINT("%3d  %15.15s  %12.12s  %s", index, f->name, connection_enum2text(f->connection), f->status_message);
        if (f->add_device_req) {
            PRINT("  ^ This peer wants to synchronize with us! Type /dev_add %d to accept or /dev_del %d to reject.", index, index);
        }
        bool reciprocal;
        bool is_dev = toxtore_is_friend_my_device(toxtore, f->friend_num, &reciprocal);
        if (is_dev) {
            if (reciprocal) {
                PRINT("  ^ Currently synchronizing with this device :)");
            } else {
                PRINT("  ^ Awaiting for them to accept us as device...");
            }
        }
    }

    struct Group *cf = groups;
    PRINT("\n#Groups(contact_index|count of peers|name):\n");
    for (;cf != NULL; cf = cf->next) {
        PRINT("%3d  %10d  %s",GEN_INDEX(cf->group_num, TALK_TYPE_GROUP), tox_conference_peer_count(tox, cf->group_num, NULL), cf->title);
    }
}

void command_save(int narg, char **args) {
    toxtore_save(toxtore);
}

void command_go(int narg, char **args) {
    if (narg == 0) {
        TalkingTo = TALK_TYPE_NULL;
        strcpy(async_repl->prompt, CMD_PROMPT);
        return;
    }
    uint32_t contact_idx;
    if (!str2uint(args[0], &contact_idx)) goto FAIL;
    uint32_t num = INDEX_TO_NUM(contact_idx);
    switch (INDEX_TO_TYPE(contact_idx)) {
        case TALK_TYPE_FRIEND: {
            struct Friend *f = getfriend(num);
            if (f) {
                TalkingTo = contact_idx;
                sprintf(async_repl->prompt, FRIEND_TALK_PROMPT, f->name);
                return;
            }
            break;
        }
        case TALK_TYPE_GROUP: {
            struct Group *cf = getgroup(num);
            if (cf) {
                TalkingTo = contact_idx;
                sprintf(async_repl->prompt, GROUP_TALK_PROMPT, cf->title);
                return;
            }
            break;
       }
    }

FAIL:
    WARN("^ Invalid contact index");
}

void command_history(int narg, char **args) {
    if (TalkingTo == TALK_TYPE_NULL) {
        WARN("No conversation selected.");
        return;
    }

    uint32_t n = DEFAULT_CHAT_HIST_COUNT;
    if (narg > 0 && !str2uint(args[0], &n)) {
        WARN("Invalid args");
    }

    uint32_t num = INDEX_TO_NUM(TalkingTo);

    if (INDEX_TO_TYPE(TalkingTo) == TALK_TYPE_FRIEND) {
        struct Friend *f = getfriend(num);
        if (f) {
            uint8_t pk[TOX_PUBLIC_KEY_SIZE];
            tox_friend_get_public_key(tox, num, pk, NULL);

            sqlite3* db = toxtore_get_db(toxtore);
            sqlite3_stmt *stmt;
            int res = sqlite3_queryf(db, &stmt, "SELECT * FROM "
                    "(SELECT type, timestamp, arg_pk, arg_int, arg_msg, cache_flag, device, seq_no FROM events "
                        "WHERE (type = ?i OR type = ?i) AND arg_pk = ?k ORDER BY timestamp DESC LIMIT ?i) "
                    "ORDER BY timestamp ASC;",
                TOXTORE_EVENT_FRIEND_SEND, TOXTORE_EVENT_FRIEND_RECV, pk, n);

            size_t ns = tox_friend_get_name_size(tox, num, NULL);
            char* name = malloc(ns+1);
            tox_friend_get_name(tox, num, (uint8_t*)name, NULL);
            name[ns] = 0;
            
            PRINT("%s", "------------ HISTORY BEGIN ---------------");
            while (res != SQLITE_DONE) {
                int type = sqlite3_column_int(stmt, 0);
                uint64_t ts = sqlite3_column_int64(stmt, 1);
                TOX_MESSAGE_TYPE tox_msg_type = sqlite3_column_int(stmt, 3);
                size_t len = sqlite3_column_bytes(stmt, 4);
                const uint8_t* msg = sqlite3_column_text(stmt, 4);
                int flag = sqlite3_column_int(stmt, 5);
                switch (type) {
                    case TOXTORE_EVENT_FRIEND_RECV:
                        if (tox_msg_type == TOX_MESSAGE_TYPE_ACTION) {
                            PRINT(GUEST_MSG_PREFIX "%s * %.*s", getftimets(ts), name, (flag ? " " : GUEST_MSG_NEW_FLAG), (int)len, msg);
                        } else {
                            PRINT(GUEST_MSG_PREFIX "%s %.*s", getftimets(ts), name, (flag ? " " : GUEST_MSG_NEW_FLAG), (int)len, msg);
                        }
                        if (!flag) {
                            Dot d;
                            memcpy(d.device_pk, sqlite3_column_blob(stmt, 6), TOX_PUBLIC_KEY_SIZE);
                            d.seq_no = sqlite3_column_int64(stmt, 7);
                            toxtore_mark_read(toxtore, d);
                        }
                        break;
                    case TOXTORE_EVENT_FRIEND_SEND:
                        if (tox_msg_type == TOX_MESSAGE_TYPE_ACTION) {
                            PRINT(SELF_MSG_PREFIX "%s * %.*s", getftimets(ts), "(me)", (flag ? " " : SELF_MSG_SENDING_FLAG), (int)len, msg);
                        } else {
                            PRINT(SELF_MSG_PREFIX "%s %.*s", getftimets(ts), "(me)", (flag ? " " : SELF_MSG_SENDING_FLAG), (int)len, msg);
                        }
                        break;
                }
                res = sqlite3_step(stmt);
            }
            PRINT("%s", "------------ HISTORY   END ---------------");

            free(name);
        }
    } else if (INDEX_TO_TYPE(TalkingTo) == TALK_TYPE_GROUP) {
        // TODO
        WARN("Not implemented :(");
    }
}

void _command_accept(int narg, char **args, bool is_accept) {
    if (narg == 0) {
        struct Request * req = requests;
        for (;req != NULL;req=req->next) {
            PRINT("%-9u%-12s%s", req->id, (req->is_friend_request ? "FRIEND" : "GROUP"), req->msg);
        }
        return;
    }

    uint32_t request_idx;
    if (!str2uint(args[0], &request_idx)) goto FAIL;
    struct Request **p = &requests;
    LIST_FIND(p, (*p)->id == request_idx);
    struct Request *req = *p;
    if (req) {
        *p = req->next;
        if (is_accept) {
            if (req->is_friend_request) {
                TOX_ERR_FRIEND_ADD err;
                uint32_t friend_num = toxtore_friend_add_norequest(toxtore, req->userdata.friend.pubkey, &err);
                if (err != TOX_ERR_FRIEND_ADD_OK) {
                    ERROR("! accept friend request failed, errcode:%d", err);
                } else {
                    addfriend(friend_num);
                }
            } else { // group invite
                struct GroupUserData *data = &req->userdata.group;
                TOX_ERR_CONFERENCE_JOIN err;
                uint32_t group_num = tox_conference_join(tox, data->friend_num, data->cookie, data->length, &err);
                if (err != TOX_ERR_CONFERENCE_JOIN_OK) {
                    ERROR("! join group failed, errcode: %d", err);
                } else {
                    addgroup(group_num);
                }
            }
        }
        free(req->msg);
        free(req);
        return;
    }
FAIL:
    WARN("Invalid request index");
}

void command_accept(int narg, char **args) {
    _command_accept(narg, args, true);
}

void command_deny(int narg, char **args) {
    _command_accept(narg, args, false);
}

void command_invite(int narg, char **args) {
    uint32_t friend_contact_idx;
    if (!str2uint(args[0], &friend_contact_idx) || INDEX_TO_TYPE(friend_contact_idx) != TALK_TYPE_FRIEND) {
        WARN("Invalid friend contact index");
        return;
    }
    int err;
    uint32_t group_num;
    if (narg == 1) {
        group_num = tox_conference_new(tox, (TOX_ERR_CONFERENCE_NEW*)&err);
        if (err != TOX_ERR_CONFERENCE_NEW_OK) {
            ERROR("! Create group failed, errcode:%d", err);
            return;
        }
        addgroup(group_num);
    } else {
        uint32_t group_contact_idx;
        if (!str2uint(args[1], &group_contact_idx) || INDEX_TO_TYPE(group_contact_idx) != TALK_TYPE_GROUP) {
            ERROR("! Invalid group contact index");
            return;
        }
        group_num = INDEX_TO_NUM(group_contact_idx);
    }

    uint32_t friend_num = INDEX_TO_NUM(friend_contact_idx);
    tox_conference_invite(tox, friend_num, group_num, (TOX_ERR_CONFERENCE_INVITE*)&err);
    if (err != TOX_ERR_CONFERENCE_INVITE_OK) {
        ERROR("! Group invite failed, errcode:%d", err);
        return;
    }
}

void command_settitle(int narg, char **args) {
    uint32_t group_contact_idx;
    if (!str2uint(args[0], &group_contact_idx) || INDEX_TO_TYPE(group_contact_idx) != TALK_TYPE_GROUP){
        ERROR("! Invalid group contact index");
        return;
    }
    uint32_t group_num = INDEX_TO_NUM(group_contact_idx);
    struct Group *cf = getgroup(group_num);
    if (!cf) {
        ERROR("! Invalid group contact index");
        return;
    }

    char *title = args[1];
    size_t len = strlen(title);
    TOX_ERR_CONFERENCE_TITLE  err;
    tox_conference_set_title(tox, group_num, (uint8_t*)title, len, &err);
    if (err != TOX_ERR_CONFERENCE_TITLE_OK) {
        ERROR("! Set group title failed, errcode: %d",err);
        return;
    }

    cf->title = realloc(cf->title, len+1);
    sprintf(cf->title, "%.*s",(int)len,title);
}

void command_dev_add(int narg, char **args) {
    if (narg != 1) {
        ERROR("! Expected one argument")
        return;
    }
    uint32_t contact_idx;
    if (!str2uint(args[0], &contact_idx)) {
        ERROR("! Invalid contact index");
        return;
    }
    if (INDEX_TO_TYPE(contact_idx) != TALK_TYPE_FRIEND) {
        ERROR("! Not a friend's index");
        return;
    }
    uint32_t friend_no = INDEX_TO_NUM(contact_idx);
    if (toxtore_is_friend_my_device(toxtore, friend_no, NULL)) {
        INFO("Already added as one of our devices!");
        return;
    }
    struct Friend* f = getfriend(friend_no);
    assert(f != NULL);

    if (toxtore_add_friend_as_device(toxtore, friend_no)) {
        f->add_device_req = false;
        f->is_device = true;
        INFO("Added as device");
    } else {
        ERROR("! An error occured");
    }
}

void command_dev_del(int narg, char **args) {
    if (narg != 1) {
        ERROR("! Expected one argument")
        return;
    }
    uint32_t contact_idx;
    if (!str2uint(args[0], &contact_idx)) {
        ERROR("! Invalid contact index");
        return;
    }
    if (INDEX_TO_TYPE(contact_idx) != TALK_TYPE_FRIEND) {
        ERROR("! Not a friend's index");
        return;
    }
    uint32_t friend_no = INDEX_TO_NUM(contact_idx);
    struct Friend* f = getfriend(friend_no);

    if (f->add_device_req){
        f->add_device_req = false;
        INFO("Device add request rejected");
    }
    if (f->is_device) {
        if (toxtore_rm_friend_as_device(toxtore, friend_no)) {
            INFO("Deleted from our devices, we won't sync anymore !")
        } else {
            ERROR("! Toxtore error")
        }
    }
}

const char* _first_hex_bytes(const uint8_t* bytes) {
    static char buf[16 * 10];
    static int ibuf = 0;

    ibuf = (ibuf + 1) % 16;
    char* b = buf + ibuf * 10;
    snprintf(b, 10, "%02X%02X%02X%02X", bytes[0], bytes[1], bytes[2], bytes[3]);
    return b;
}

const char* _pk_list_hex(size_t n_devices, const uint8_t *devices_pk) {
    static char buf[16*10];

    char* p = buf, *endp = buf + 16 * 10;
    *p++ = '[';
    for (int i = 0; i < n_devices && i < 16; i++) {
        const uint8_t* k = devices_pk + i * TOX_PUBLIC_KEY_SIZE;
        if (i > 0) *p++ = ' ';
        p += snprintf(p, endp - p - 2, "%02X%02X%02X%02X", k[0], k[1], k[2], k[3]);
    }
    *p++ = ']';
    *p++ = 0;
    return buf;
}

void command_ttevents(int narg, char **args) {
    sqlite3 *db = toxtore_get_db(toxtore);
    sqlite3_stmt *stmt;
    int res = sqlite3_queryf(db, &stmt,
        "SELECT device, seq_no, timestamp, type, arg_dot_dev, arg_dot_sn, arg_pk, arg_blob, arg_msg, arg_int, cache_flag "
            "FROM events ORDER BY timestamp ASC");
    while (res == SQLITE_ROW) {
        switch(sqlite3_column_int(stmt, 3)) {
            case TOXTORE_EVENT_FRIEND_ADD:
                PRINT("%s (%s,%4lld) %s +F %s",
                    getftimets(sqlite3_column_int64(stmt, 2)),
                    _first_hex_bytes(sqlite3_column_blob(stmt, 0)),
                    sqlite3_column_int64(stmt, 1),
                    (sqlite3_column_int(stmt, 10) ? "*" : " "),
                    _first_hex_bytes(sqlite3_column_blob(stmt, 6)));
                break;
            case TOXTORE_EVENT_FRIEND_DEL:
                PRINT("%s (%s,%4lld) %s -F (%s, %lld)",
                    getftimets(sqlite3_column_int64(stmt, 2)),
                    _first_hex_bytes(sqlite3_column_blob(stmt, 0)),
                    sqlite3_column_int64(stmt, 1),
                    (sqlite3_column_int(stmt, 10) ? "*" : " "),
                    _first_hex_bytes(sqlite3_column_blob(stmt, 4)),
                    sqlite3_column_int64(stmt, 5));
                break;
            case TOXTORE_EVENT_FRIEND_NOSPAM:
                PRINT("%s (%s,%4lld) %s Fnospam %s %s",
                    getftimets(sqlite3_column_int64(stmt, 2)),
                    _first_hex_bytes(sqlite3_column_blob(stmt, 0)),
                    sqlite3_column_int64(stmt, 1),
                    (sqlite3_column_int(stmt, 10) ? "*" : " "),
                    _first_hex_bytes(sqlite3_column_blob(stmt, 6)),
                    _first_hex_bytes(sqlite3_column_blob(stmt, 7)));
                break;
            case TOXTORE_EVENT_FRIEND_DEVICES:
                PRINT("%s (%s,%4lld) %s Fdev %s %s",
                    getftimets(sqlite3_column_int64(stmt, 2)),
                    _first_hex_bytes(sqlite3_column_blob(stmt, 0)),
                    sqlite3_column_int64(stmt, 1),
                    (sqlite3_column_int(stmt, 10) ? "*" : " "),
                    _first_hex_bytes(sqlite3_column_blob(stmt, 6)),
                    _pk_list_hex(sqlite3_column_bytes(stmt, 7) / TOX_PUBLIC_KEY_SIZE, sqlite3_column_blob(stmt, 7)));
                break;
            case TOXTORE_EVENT_FRIEND_SEND:
                PRINT("%s (%s,%4lld) %s >> %s        | %s",
                    getftimets(sqlite3_column_int64(stmt, 2)),
                    _first_hex_bytes(sqlite3_column_blob(stmt, 0)),
                    sqlite3_column_int64(stmt, 1),
                    (sqlite3_column_int(stmt, 10) ? "*" : " "),
                    _first_hex_bytes(sqlite3_column_blob(stmt, 6)),
                    sqlite3_column_text(stmt, 8));
                break;
            case TOXTORE_EVENT_CONFERENCE_SEND:
                PRINT("%s (%s,%4lld) %s >>>> %s      | %s",
                    getftimets(sqlite3_column_int64(stmt, 2)),
                    _first_hex_bytes(sqlite3_column_blob(stmt, 0)),
                    sqlite3_column_int64(stmt, 1),
                    (sqlite3_column_int(stmt, 10) ? "*" : " "),
                    _first_hex_bytes(sqlite3_column_blob(stmt, 7)),
                    sqlite3_column_text(stmt, 8));
                break;
            case TOXTORE_EVENT_SEND_DONE:
                PRINT("%s (%s,%4lld) %s +S (%s, %lld)",
                    getftimets(sqlite3_column_int64(stmt, 2)),
                    _first_hex_bytes(sqlite3_column_blob(stmt, 0)),
                    sqlite3_column_int64(stmt, 1),
                    (sqlite3_column_int(stmt, 10) ? "*" : " "),
                    _first_hex_bytes(sqlite3_column_blob(stmt, 4)),
                    sqlite3_column_int64(stmt, 5));
                break;
            case TOXTORE_EVENT_FRIEND_RECV:
                PRINT("%s (%s,%4lld) %s << %s        | %s",
                    getftimets(sqlite3_column_int64(stmt, 2)),
                    _first_hex_bytes(sqlite3_column_blob(stmt, 0)),
                    sqlite3_column_int64(stmt, 1),
                    (sqlite3_column_int(stmt, 10) ? "*" : " "),
                    _first_hex_bytes(sqlite3_column_blob(stmt, 6)),
                    sqlite3_column_text(stmt, 8));
                break;
            case TOXTORE_EVENT_MARK_READ:
                PRINT("%s (%s,%4lld) %s +R (%s, %lld)",
                    getftimets(sqlite3_column_int64(stmt, 2)),
                    _first_hex_bytes(sqlite3_column_blob(stmt, 0)),
                    sqlite3_column_int64(stmt, 1),
                    (sqlite3_column_int(stmt, 10) ? "*" : " "),
                    _first_hex_bytes(sqlite3_column_blob(stmt, 4)),
                    sqlite3_column_int64(stmt, 5));
                break;
            default:
                PRINT("%s (%s,%4lld) %s %02d",
                    getftimets(sqlite3_column_int64(stmt, 2)),
                    _first_hex_bytes(sqlite3_column_blob(stmt, 0)),
                    sqlite3_column_int64(stmt, 1),
                    (sqlite3_column_int(stmt, 10) ? "*" : " "),
                    sqlite3_column_int(stmt, 3));
        }
        res = sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);
}

void command_ttfriends(int narg, char **args) {
    sqlite3 *db = toxtore_get_db(toxtore);
    sqlite3_stmt *stmt;
    int res = sqlite3_queryf(db, &stmt,
        "SELECT pk, other_pks, merged_id FROM friends ORDER BY merged_id ASC");
    while (res == SQLITE_ROW) {
        PRINT("%4d %s %s", sqlite3_column_int(stmt, 2),
            _first_hex_bytes(sqlite3_column_blob(stmt, 0)),
            _pk_list_hex(sqlite3_column_bytes(stmt, 1) / TOX_PUBLIC_KEY_SIZE, sqlite3_column_blob(stmt, 1)));
        res = sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);
}

#define COMMAND_ARGS_REST 10
#define COMMAND_LENGTH (sizeof(commands)/sizeof(struct Command))

struct Command commands[] = {
    {
        "guide",
        "- print the guide",
        0,
        command_guide,
    },
    {
        "help",
        "- print this message.",
        0,
        command_help,
    },
    {
        "save",
        "- save your data.",
        0,
        command_save,
    },
    {
        "info",
        "[<contact_index>] - show one contact's info, or yourself's info if <contact_index> is empty. ",
        0 + COMMAND_ARGS_REST,
        command_info,
    },
    {
        "setname",
        "<name> - set your name",
        1,
        command_setname,
    },
    {
        "setstmsg",
        "<status_message> - set your status message.",
        1,
        command_setstmsg,
    },
    {
        "add",
        "<toxid> <msg> - add friend",
        2,
        command_add,
    },
    {
        "del",
        "<contact_index> - del a contact.",
        1,
        command_del,
    },
    {
        "contacts",
        "- list your contacts(friends and groups).",
        0,
        command_contacts,
    },
    {
        "go",
        "[<contact_index>] - goto talk to a contact, or goto cmd mode if <contact_index> is empty.",
        0 + COMMAND_ARGS_REST,
        command_go,
    },
    {
        "history",
        "[<n>] - show previous <n> items(default:10) of current chat history",
        0 + COMMAND_ARGS_REST,
        command_history,
    },
    {
        "accept",
        "[<request_index>] - accept or list(if no <request_index> was provided) friend/group requests.",
        0 + COMMAND_ARGS_REST,
        command_accept,
    },
    {
        "deny",
        "[<request_index>] - deny or list(if no <request_index> was provided) friend/group requests.",
        0 + COMMAND_ARGS_REST,
        command_deny,
    },
    {
        "invite",
        "<friend_contact_index> [<group_contact_index>] - invite a friend to a group chat. default: create a group.",
        1 + COMMAND_ARGS_REST,
        command_invite,
    },
    {
        "settitle",
        "<group_contact_index> <title> - set group title.",
        2,
        command_settitle,
    },
    {
        "dev_add",
        "<friend number> - request Toxtore sync with this Tox ID",
        1,
        command_dev_add,
    },
    {
        "dev_del",
        "<friend number> - stop Toxtore sync with this Tox ID",
        1,
        command_dev_del,
    },
    {
        "ttevents",
        " - dump the toxtore event log",
        0,
        command_ttevents,
    },
    {
        "ttfriends",
        " - dump the toxtore friends table",
        0,
        command_ttfriends,
    },
};

void command_help(int narg, char **args){
    for (int i=1;i<COMMAND_LENGTH;i++) {
        printf("%-16s%s\n", commands[i].name, commands[i].desc);
    }
}

/*******************************************************************************
 *
 * Main
 *
 ******************************************************************************/

char *poptok(char **strp) {
    static const char *dem = " \t";
    char *save = *strp;
    *strp = strpbrk(*strp, dem);
    if (*strp == NULL) return save;

    *((*strp)++) = '\0';
    *strp += strspn(*strp,dem);
    return save;
}

void repl_iterate(void){
    static char buf[128];
    static char line[LINE_MAX_SIZE];
    while (1) {
        int n = read(NEW_STDIN_FILENO, buf, sizeof(buf));
        if (n <= 0) {
            break;
        }
        must_arepl_reprint = true;
        for (int i=0;i<n;i++) { // for_1
            char c = buf[i];
            if (c == '\004')          /* C-d */
                exit(0);
            if (!arepl_readline(async_repl, c, line, sizeof(line))) continue; // continue to for_1

            int len = strlen(line);
            line[--len] = '\0'; // remove trailing \n

            if (TalkingTo != TALK_TYPE_NULL && line[0] != '/' && line[0] != 0) {  // if talking to someone, just print the msg out.
                PRINT(SELF_MSG_PREFIX "%.*s", getftime(), "(me)", len, line);
                switch (INDEX_TO_TYPE(TalkingTo)) {
                    case TALK_TYPE_FRIEND:
                        toxtore_friend_send_message(toxtore, INDEX_TO_NUM(TalkingTo), TOX_MESSAGE_TYPE_NORMAL, (uint8_t*)line, strlen(line), NULL);
                        continue; // continue to for_1
                    case TALK_TYPE_GROUP:
                        toxtore_conference_send_message(toxtore, INDEX_TO_NUM(TalkingTo), TOX_MESSAGE_TYPE_NORMAL, (uint8_t*)line, strlen(line), NULL);
                        continue;  // continue to for_1
                }
            }

            PRINT(CMD_MSG_PREFIX "%s", line);  // take this input line as a command.
            if (len == 0) continue; // continue to for_1.  ignore empty line

            if (line[0] == '/') {
                char *l = line + 1; // skip leading '/'
                char *cmdname = poptok(&l);
                struct Command *cmd = NULL;
                for (int j=0; j<COMMAND_LENGTH;j++){ // for_2
                    if (strcmp(commands[j].name, cmdname) == 0) {
                        cmd = &commands[j];
                        break; // break for_2
                    }
                }
                if (cmd) {
                    char *tokens[cmd->narg];
                    int ntok = 0;
                    for (; l != NULL && ntok != cmd->narg; ntok++) {
                        // if it's the last arg, then take the rest line.
                        char *tok = (ntok == cmd->narg - 1) ? l : poptok(&l);
                        tokens[ntok] = tok;
                    }
                    if (ntok < cmd->narg - (cmd->narg >= COMMAND_ARGS_REST ? COMMAND_ARGS_REST : 0)) {
                        WARN("Wrong number of cmd args");
                    } else {
                        cmd->handler(ntok, tokens);
                        if (SAVEDATA_AFTER_COMMAND) toxtore_save(toxtore);
                    }
                    continue; // continue to for_1
                }
            }

            WARN("! Invalid command, use `/help` to get list of available commands.");
        } // end for_1
    } // end while
    if (must_arepl_reprint) {
        arepl_reprint(async_repl);
        must_arepl_reprint = false;
    }
}

void usage(int argc, char **argv) {
    printf("usage: %s [-h] [-n profile_name] [-u] [-P passphrase]\n\n", (argc > 0 ? argv[0] : "./mdmt"));
    printf("    -h          display this help screen\n");
    printf("    -n <name>   set profile name\n");
    printf("    -u          use unencrypted storage file\n");
    printf("    -P <pass>   use <pass> as encryption passphrase instead of prompting\n");
    exit(0);
}

int password_prompt(char *buf, int size)
{
    buf[0] = '\0';

    /* disable terminal echo */
    struct termios oflags, nflags;
    tcgetattr(fileno(stdin), &oflags);
    nflags = oflags;
    nflags.c_lflag &= ~ECHO;
    nflags.c_lflag |= ECHONL;

    if (tcsetattr(fileno(stdin), TCSANOW, &nflags) != 0) {
        return 0;
    }

    const char *p = fgets(buf, size-1, stdin);
    int len = strlen(buf);

    /* re-enable terminal echo */
    tcsetattr(fileno(stdin), TCSANOW, &oflags);

    if (p == NULL || len <= 1) {
        return 0;
    }

    /* eat overflowed stdin and return error */
    if (buf[--len] != '\n') {
        int ch;

        while ((ch = getchar()) != '\n' && ch > 0) {
        }

        return 0;
    }

    buf[len] = '\0';
    return len;
}

int main(int argc, char **argv) {
    const char* profile = "minitox";
    const char* passphrase = NULL;
    bool no_passphrase = false;

    int opt;
    while ((opt = getopt(argc, argv, "n:uP:h")) != -1){
        switch (opt) {
            case 'n':
                profile = optarg;
                break;
            case 'u':
                no_passphrase = true;
                break;
            case 'P':
                passphrase = optarg;
                break;
            case '?':
                printf("\n");
                usage(argc, argv);
                return 1;
            case 'h':
                usage(argc, argv);
                return 0;
            default:
                printf("Unknown option: -%c\n", opt);
                usage(argc, argv);
                return 1;
        }
    }

    printf("Tox profile name: %s\n", profile);

    if (no_passphrase && passphrase != NULL) {
        fprintf(stderr, "Cannot specify passphrase and -u at the same time!\n");
        exit(1);
    }

    if (passphrase == NULL && !no_passphrase) {
        char* pbuf = malloc(256);
        if (pbuf == NULL) {
            fprintf(stderr, "Could not malloc\n");
            exit(1);
        }

        printf("Enter passphrase: ");
        fflush(stdout);
        if (password_prompt(pbuf, 256) > 0) {
            passphrase = pbuf;
        } else {
            fprintf(stderr, "No passprase entered, use option -u to disable passphrase.\n");
            exit(1);
        }
    }

    fputs("Type `/guide` to print the guide.\n", stdout);
    fputs("Type `/help` to print command list.\n\n",stdout);

    setup_arepl();
    setup_tox(profile, passphrase);

    INFO("* Waiting to be online ...");

    uint32_t msecs = 0;
    while (1) {
        if (msecs >= AREPL_INTERVAL) {
            msecs = 0;
            repl_iterate();
        }
        toxtore_iterate(toxtore, NULL);
        uint32_t v = tox_iteration_interval(tox);
        msecs += v;

        struct timespec pause;
        pause.tv_sec = 0;
        pause.tv_nsec = v * 1000 * 1000;
        nanosleep(&pause, NULL);
    }

    return 0;
}

/* vim: set sts=4 ts=4 sw=4 tw=0 et :*/
