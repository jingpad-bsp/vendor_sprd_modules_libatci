/**
 * AT Command Interface Client Socket implementation
 *
 * Copyright (C) 2015 Spreadtrum Communications Inc.
 *
 */

#ifndef VSIM_H_
#define VSIM_H_

#ifdef __cplusplus
extern "C" {
#endif

#define APDU_BUFFER_BYTES               128
#define MAX_BUFFER_BYTES                (8 * 1024)

typedef unsigned char u8;
typedef unsigned short u16;

typedef int (*VSIM_COMMAND) (u8 slot, u8*apdu_req, u16 apdu_req_len, u8 *apdu_rsp, u16 apdu_rsp_len);

typedef enum {
    UNKNOWN,
    SELECT_FILE,
    READ_BINARY,
    READ_RECORD,
    UPDATE_RECORD,
    UPDATE_BINARY,
    AUTHEN
} INTSTYPE;

int vsim_init(int phoneId, VSIM_COMMAND pfnCommand, int restart);
int vsim_send_data(int phoneId, u8* data, u16 data_len);
int vsim_exit(int phoneId);
int vsim_set_authid(int authid);
int vsim_query_authid();
int vsim_set_virtual(int phoneId, int mode);
int vsim_set_nv(int phoneId, int type, int isWrite);
int vsim_query_virtual(int phoneId);
int vsim_get_auth_cause(int phoneId);
int vsim_set_timeout(int time);
int vsim_get_line(char *p_cur);
int vsim_parse_apdu(int slot, unsigned char *apdu_req, int apdu_req_len,
        unsigned char *apdu_rsp, int apdu_resp_len);
int vsim_set_timeout(int time);

#ifdef __cplusplus
}
#endif

#endif  // VSIM_H_
