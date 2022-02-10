/* //vendor/sprd/modules/libatci/utils.cpp
 **
 ** Copyright 2006, The Android Open Source Project
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 **     http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 */

#include "utils.h"
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <utils/Log.h>
/**
 * Starts tokenizing an AT response string
 * returns -1 if this is not a valid response string, 0 on success.
 * updates *p_cur with current position
 */
int at_tok_start(char **p_cur, char start_flag) {
    if (*p_cur == NULL) {
        return -1;
    }
    // skip prefix
    // consume "^[^:]:"
    *p_cur = strchr(*p_cur, start_flag);
    if (*p_cur == NULL) {
        return -1;
    }
    (*p_cur)++;
    return 0;
}
static void skipWhiteSpace(char **p_cur) {
    if (*p_cur == NULL)
        return;
    while (**p_cur != '\0' && isspace(**p_cur)) {
        (*p_cur)++;
    }
}

static void skipNextComma(char **p_cur) {
    if (*p_cur == NULL)
        return;
    while (**p_cur != '\0' && **p_cur != ',') {
        (*p_cur)++;
    }
    if (**p_cur == ',') {
        (*p_cur)++;
    }
}

static char *nextTok(char **p_cur) {
    char *ret = NULL;
    skipWhiteSpace(p_cur);
    if (*p_cur == NULL) {
        ret = NULL;
    } else if (**p_cur == '"') {
        (*p_cur)++;
        ret = strsep(p_cur, "\"");
        skipNextComma(p_cur);
    } else {
        ret = strsep(p_cur, ",");
    }
    return ret;
}

/**
 * Parses the next integer in the AT response line and places it in *p_out
 * returns 0 on success and -1 on fail
 * updates *p_cur
 * "base" is the same as the base param in strtol
 */
static int at_tok_nextint_base(char **p_cur, int *p_out, int base, int uns) {
    char *ret;
    if (*p_cur == NULL) {
        return -1;
    }
    ret = nextTok(p_cur);
    if (ret == NULL) {
        return -1;
    } else {
        long l;
        char *end;
        if (uns)
            l = strtoul(ret, &end, base);

        else
            l = strtol(ret, &end, base);
        *p_out = (int)l;
        if (end == ret) {
            return -1;
        }
    }
    return 0;
}

/**
 * Parses the next base 10 integer in the AT response line
 * and places it in *p_out
 * returns 0 on success and -1 on fail
 * updates *p_cur
 */
int at_tok_nextint(char **p_cur, int *p_out) {
    return at_tok_nextint_base(p_cur, p_out, 10, 0);
}

/**
 * Parses the next base 16 integer in the AT response line
 * and places it in *p_out
 * returns 0 on success and -1 on fail
 * updates *p_cur
 */
int at_tok_nexthexint(char **p_cur, int *p_out) {
    return at_tok_nextint_base(p_cur, p_out, 16, 1);
}

int at_tok_nextbool(char **p_cur, char *p_out) {
    int ret;
    int result;
    ret = at_tok_nextint(p_cur, &result);
    if (ret < 0) {
        return -1;
    }
    if (!(result == 0 || result == 1)) {
        return -1;
    }
    if (p_out != NULL) {
        *p_out = (char)result;
    }
    return ret;
}

int at_tok_nextstr(char **p_cur, char **p_out) {
    if (*p_cur == NULL) {
        return -1;
    }
    *p_out = nextTok(p_cur);
    return 0;
}

/* returns 1 on "has more tokens" and 0 if no */
int at_tok_hasmore(char **p_cur) {
    return !(*p_cur == NULL || **p_cur == '\0');
}

/*****************************************************************************/

int strStartsWith(const char *line, const char *prefix) {
    for ( ; *line != '\0' && *prefix != '\0' ; line++, prefix++) {
        if (*line != *prefix) return 0;
    }
    return *prefix == '\0';
}

int getNewLine(char *p_cur) {
    while (((*p_cur++) != '\r') && *p_cur != '\0');
    if (*(--p_cur) == '\r') {
        *p_cur = '\0';
    }
    return 0;
}

void convertBinToHex(unsigned char *bin_ptr, int length, unsigned char *hex_ptr) {
    int i;
    unsigned char tmp;

    if (bin_ptr == NULL || hex_ptr == NULL) {
        return;
    }
    for (i=0; i<length; i++) {
        tmp = (unsigned char)((bin_ptr[i] & 0xf0)>>4);
        if (tmp <= 9) {
            *hex_ptr = (unsigned char)(tmp + '0');
        } else {
            *hex_ptr = (unsigned char)(tmp + 'A' - 10);
        }
        hex_ptr++;
        tmp = (unsigned char)(bin_ptr[i] & 0x0f);
        if (tmp <= 9) {
            *hex_ptr = (unsigned char)(tmp + '0');
        } else {
            *hex_ptr = (unsigned char)(tmp + 'A' - 10);
        }
        hex_ptr++;
    }
}

int convertHexToBin(unsigned char *hex_ptr, int length, unsigned char *bin_ptr) {
    unsigned char *dest_ptr = bin_ptr;
    int i;
    char ch;

    if (hex_ptr == NULL || bin_ptr == NULL) {
        return -1;
    }

    for (i = 0; i < length; i += 2) {
        ch = hex_ptr[i];
        if (ch >= '0' && ch <= '9') {
            *dest_ptr = (char)((ch - '0') << 4);
        } else if (ch >= 'a' && ch <= 'f') {
            *dest_ptr = (char)((ch - 'a' + 10) << 4);
        } else if (ch >= 'A' && ch <= 'F') {
            *dest_ptr = (char)((ch - 'A' + 10) << 4);
        } else {
            return -1;
        }

        ch = hex_ptr[i + 1];
        if (ch >= '0' && ch <= '9') {
            *dest_ptr |= (char)(ch - '0');
        } else if (ch >= 'a' && ch <= 'f') {
            *dest_ptr |= (char)(ch - 'a' + 10);
        } else if (ch >= 'A' && ch <= 'F') {
            *dest_ptr |= (char)(ch - 'A' + 10);
        } else {
            return -1;
        }

        dest_ptr++;
    }
    return 0;
}

/*****************************************************************************/

void list_init(ListNode **node) {
    *node = (ListNode *)calloc(1, sizeof(ListNode));
    if (*node == NULL) {
        RLOGE("Failed malloc memory!");
    } else {
        (*node)->next = *node;
        (*node)->prev = *node;
    }
}

void list_add_tail(ListNode *head, ListNode *item) {
    item->next = head;
    item->prev = head->prev;
    head->prev->next = item;
    head->prev = item;
}

void list_remove(ListNode *item) {
    item->next->prev = item->prev;
    item->prev->next = item->next;
}
