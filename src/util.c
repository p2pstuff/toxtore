#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "toxtore.h"

// FOR DEBUG
// FROM https://gist.github.com/ccbrown/9722406, THANK YOU <3

void toxtore_util_stderr_hexdump(const void* data, size_t size) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        fprintf(stderr, "%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            fprintf(stderr, " ");
            if ((i+1) % 16 == 0) {
                fprintf(stderr, "|  %s \n", ascii);
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    fprintf(stderr, " ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    fprintf(stderr, "   ");
                }
                fprintf(stderr, "|  %s \n", ascii);
            }
        }
    }
}

// ---------------------
// HELPER
// SQLITE3 VARARG QUERY
int toxtore_util_sqlite3_queryf(sqlite3* db, sqlite3_stmt **arg_stmt, const char* fmt, ...)
{
    sqlite3_stmt *own_stmt;
    sqlite3_stmt **stmt = (arg_stmt == NULL ? &own_stmt : arg_stmt);

    size_t sqllen = strlen(fmt) + 1;
    char* sql = malloc(sqllen);
    if (sql == NULL) return SQLITE_ERROR;

    int res = SQLITE_OK;

    const char *inptr = fmt;
    char *outptr = sql;
    while (*inptr) {
        if (*inptr == '?') {
            inptr++;
            if (*inptr == '?') {
                *(outptr++) = '?';
            } else {
                *(outptr++) = '?';
            }
            inptr++;
        } else {
            *(outptr++) = *(inptr++);
        }
    }
    *outptr = 0;

    static int query_counter = 0;
    query_counter++;
#ifdef TOXTORE_MUCHDEBUG
    fprintf(stderr, "[%d] %s\n", query_counter, sql);
#endif

    res = sqlite3_prepare_v2(db, sql, sqllen, stmt, NULL);
    if (res != SQLITE_OK) {
        fprintf(stderr, "[%d] Sqlite3 prepare error:\n    %s\n -> %s\n", query_counter, sql, sqlite3_errmsg(db));
        goto clean1;
    }

    va_list ap;
    va_start(ap, fmt);
    int bind_i = 1;
    inptr = fmt;
    while (*inptr) {
        if (*inptr == '?') {
            inptr++;
            switch (*inptr) {
                case '?':
                    break;
                case 's': {
                    const char* str = va_arg(ap, const char*);
                    sqlite3_bind_text(*stmt, bind_i++, str, -1, SQLITE_TRANSIENT);
                    break;
                }
                case 'S': {
                    const char* str = va_arg(ap, const char*);
                    size_t len = va_arg(ap, size_t);
                    sqlite3_bind_text(*stmt, bind_i++, str, len, SQLITE_TRANSIENT);
                    break;
                }
                case 'i': {
                    int32_t val = va_arg(ap, int32_t);
                    sqlite3_bind_int(*stmt, bind_i++, val);
                    break;
                }
                case 'I': {
                    int64_t val = va_arg(ap, int64_t);
                    sqlite3_bind_int64(*stmt, bind_i++, val);
                    break;
                }
                case 'B': {
                    const uint8_t *bytes = va_arg(ap, const uint8_t*);
                    size_t len = va_arg(ap, size_t);
                    sqlite3_bind_blob(*stmt, bind_i++, bytes, len, SQLITE_TRANSIENT);
                    break;
                }
                case 'k': {
                    const uint8_t *bytes = va_arg(ap, const uint8_t*);
                    sqlite3_bind_blob(*stmt, bind_i++, bytes, TOX_PUBLIC_KEY_SIZE, SQLITE_TRANSIENT);
                    break;
                }
                default:
                    fprintf(stderr, "Unknown format: %%%c\n", *inptr);
                    res = SQLITE_ERROR;
                    goto clean2;
            };
        }
        inptr++;
    }
    va_end(ap);

    res = sqlite3_step(*stmt);
    if (res != SQLITE_ROW && res != SQLITE_DONE) {
        fprintf(stderr, "Sqlite3 step error: %s\n", sqlite3_errmsg(db));
    }

clean2:
    if (arg_stmt == NULL) sqlite3_finalize(*stmt);
clean1:
    free(sql);
    return res;
}


// Hex encode and decode

void toxtore_util_hexencode(char* out, const uint8_t *in, size_t nbytes)
{
    const char* digits = "0123456789ABCDEF";
    for (size_t i = 0; i < nbytes; i++) {
        out[2*i]  = digits[(in[i] >> 4) & 0x0F];
        out[2*i+1] = digits[in[i] & 0x0F];
    }
}

static inline int _hexchr2num(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

bool toxtore_util_hexdecode(uint8_t* out, const char *in, size_t nbytes)
{
    for (size_t i = 0; i < nbytes; i++) {
        int hi = _hexchr2num(in[2*i]);
        int lo = _hexchr2num(in[2*i+1]);
        if (hi == -1 || lo == -1) return false;
        out[i] = (hi << 4) | lo;
    }
}