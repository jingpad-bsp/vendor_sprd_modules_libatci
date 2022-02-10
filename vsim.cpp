/**
 * AT Command Interface Client Socket implementation
 *
 * Copyright (C) 2019 UNISOC Technologies Co.,Ltd.
 *
 */

#define LOG_TAG "ATCI_VSIM"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <utils/Log.h>
#include <pthread.h>
#include "utils.h"
#include "vsim.h"

#include <vendor/sprd/hardware/radio/1.0/IExtRadio.h>
#include <vendor/sprd/hardware/radio/1.0/IAtcRadioResponse.h>
#include <vendor/sprd/hardware/radio/1.0/IAtcRadioIndication.h>

using namespace vendor::sprd::hardware::radio::V1_0;
using ::vendor::sprd::hardware::radio::V1_0::ExtRadioResponseInfo;
using ::vendor::sprd::hardware::radio::V1_0::ExtRadioIndicationType;
using namespace std;
using ::android::hardware::hidl_string;
using ::android::hardware::Return;
using ::android::hardware::Void;
using android::sp;
using ::android::hardware::hidl_death_recipient;
using ::android::hidl::base::V1_0::IBase;

#define RADIO1_SERVICE_NAME         "slot1"
#define RADIO2_SERVICE_NAME         "slot2"
#define MAX_COMMAND_BYTES           (4 * 1024)
#define MAX_VSIM_COUNT              2

#define SIM_AUTH_RESPONSE_SUCCESS           0
#define SIM_AUTH_RESPONSE_SYNC_FAILURE      3
#define RESPONSE_TYPE_SIM                   0
#define RESPONSE_TYPE_AUTH                  1

#define VSIM_PROCESS_SUCCESS                0
#define VSIM_PROCESS_FAIL                   -1

bool s_vsimInitFlag[MAX_VSIM_COUNT] = {false, false};
int s_vsimMbauId = -1;

VSIM_COMMAND spfnCommand;

struct AtcRadioResponseImpl;
struct AtcRadioIndicationImpl;

int s_vsimAuthCause1 = 0;
int s_vsimAuthCause2 = 0;
bool s_isVsimExited[MAX_VSIM_COUNT];
pid_t s_vsimReqThreadTid[MAX_VSIM_COUNT];

sp<IExtRadio> s_vsimExtRadioProxy[MAX_VSIM_COUNT] = {
        NULL
#if (MAX_VSIM_COUNT >= 2)
        , NULL
#endif
#if (MAX_VSIM_COUNT >= 3)
        , NULL
#endif
#if (MAX_VSIM_COUNT >= 4)
        , NULL
#endif
};

sp<AtcRadioResponseImpl> s_vsimAtcRadioResponse[MAX_VSIM_COUNT] = {
        NULL
#if (MAX_VSIM_COUNT >= 2)
        , NULL
#endif
#if (MAX_VSIM_COUNT >= 3)
        , NULL
#endif
#if (MAX_VSIM_COUNT >= 4)
        , NULL
#endif
};

sp<AtcRadioIndicationImpl> s_vsimAtcRadioIndication[MAX_VSIM_COUNT] = {
        NULL
#if (MAX_VSIM_COUNT >= 2)
        , NULL
#endif
#if (MAX_VSIM_COUNT >= 3)
        , NULL
#endif
#if (MAX_VSIM_COUNT >= 4)
        , NULL
#endif
};

ListNode *s_vsimReqList[MAX_VSIM_COUNT] = {
        NULL
#if (MAX_VSIM_COUNT >= 2)
        , NULL
#endif
#if (MAX_VSIM_COUNT >= 3)
        , NULL
#endif
#if (MAX_VSIM_COUNT >= 4)
        , NULL
#endif
};

static pthread_mutex_t s_vsimReqListMutex[MAX_VSIM_COUNT] = {
        PTHREAD_MUTEX_INITIALIZER
#if (MAX_VSIM_COUNT >= 2)
        , PTHREAD_MUTEX_INITIALIZER
#endif
#if (MAX_VSIM_COUNT >= 3)
        , PTHREAD_MUTEX_INITIALIZER
#endif
#if (MAX_VSIM_COUNT >= 4)
        , PTHREAD_MUTEX_INITIALIZER
#endif
};

static pthread_cond_t s_vsimReqListCond[MAX_VSIM_COUNT] = {
        PTHREAD_COND_INITIALIZER
#if (MAX_VSIM_COUNT >= 2)
        , PTHREAD_COND_INITIALIZER
#endif
#if (MAX_VSIM_COUNT >= 3)
        , PTHREAD_COND_INITIALIZER
#endif
#if (MAX_VSIM_COUNT >= 4)
        , PTHREAD_COND_INITIALIZER
#endif
};

/******************************************************************************/
struct RadioProxyDeathRecipient : hidl_death_recipient {
    virtual void serviceDied(uint64_t cookie __unused,
            const android::wp<IBase>& who __unused) {
        RLOGE("rild service died");
        int simCount = 0;
        for (simCount = 0; simCount < MAX_VSIM_COUNT; simCount++) {
            s_vsimExtRadioProxy[simCount] = NULL;
        }
    }
};

sp<RadioProxyDeathRecipient> s_radioProxyHalDied = nullptr;

/******************************************************************************/
static bool copyHidlStringToCharPtr(char **dest, const hidl_string &src) {
    size_t len = src.size();
    if (len == 0) {
        RLOGD("copyHidlStringToCharPtr src len is 0");
        *dest = NULL;
        return true;
    }
    *dest = (char *) calloc(len + 1, sizeof(char));
    if (*dest == NULL) {
        RLOGE("copyHidlStringToCharPtr Memory allocation failed");
        return false;
    }
    strncpy(*dest, src.c_str(), len + 1);
    return true;
}

static hidl_string convertCharPtrToHidlString(const char *ptr) {
    hidl_string ret;
    if (ptr != NULL) {
        // TODO: replace this with strnlen
        ret.setToExternal(ptr, strlen(ptr));
    }
    return ret;
}

/*****************************************************************************/
struct AtcRadioResponseImpl : public IAtcRadioResponse {
    int32_t mSlotId;
    Return<void> vsimSendCmdResponse(const ExtRadioResponseInfo& info,
            const hidl_string& response);
};

Return<void> AtcRadioResponseImpl::vsimSendCmdResponse(const ExtRadioResponseInfo& info,
        const hidl_string& response) {
    char *atResp = NULL;
    if (!copyHidlStringToCharPtr(&atResp, response)) {
        return Void();
    }

    free(atResp);
    return Void();
}

/*****************************************************************************/

struct AtcRadioIndicationImpl : public IAtcRadioIndication {
    int32_t mSlotId;
    Return<void> vsimRSimReqInd(ExtRadioIndicationType type, const hidl_string& data);
};

Return<void> AtcRadioIndicationImpl::vsimRSimReqInd(ExtRadioIndicationType type,
        const hidl_string& data) {
    char *atData = NULL;
    if (!copyHidlStringToCharPtr(&atData, data)) {
        return Void();
    }
    RLOGD("vsimRSimReqInd atData: %s", atData);

    ListNode *pNode = (ListNode *)calloc(1, sizeof(ListNode));
    pNode->data = (void *)atData;

    if (s_vsimReqList[mSlotId] != NULL) {
        RLOGD("add to s_vsimReqList[%d]", mSlotId);
        pthread_mutex_lock(&s_vsimReqListMutex[mSlotId]);
        list_add_tail(s_vsimReqList[mSlotId], pNode);
        pthread_cond_signal(&s_vsimReqListCond[mSlotId]);
        pthread_mutex_unlock(&s_vsimReqListMutex[mSlotId]);
    } else {
        RLOGE("vsim has not init, ignore");
        free(pNode->data);
        free(pNode);
    }

    return Void();
}

/*****************************************************************************/

sp<IExtRadio> getVsimExtRadioProxy(int phoneId) {
    if (s_vsimExtRadioProxy[phoneId] == NULL) {
        RLOGD("getVsimExtRadioProxy");
        s_vsimExtRadioProxy[phoneId] = IExtRadio::getService(
                hidl_string(phoneId == 0 ? RADIO1_SERVICE_NAME : RADIO2_SERVICE_NAME));
    }
    return s_vsimExtRadioProxy[phoneId];
}

sp<AtcRadioResponseImpl> getVsimAtcRadioResponse(int phoneId) {
    if (s_vsimAtcRadioResponse[phoneId] == NULL) {
        s_vsimAtcRadioResponse[phoneId] =  new AtcRadioResponseImpl;
        s_vsimAtcRadioResponse[phoneId]->mSlotId = phoneId;
    }
    return s_vsimAtcRadioResponse[phoneId];
}

sp<AtcRadioIndicationImpl> getVsimAtcRadioIndication(int phoneId) {
    if (s_vsimAtcRadioIndication[phoneId] == NULL) {
        s_vsimAtcRadioIndication[phoneId] =  new AtcRadioIndicationImpl;
        s_vsimAtcRadioIndication[phoneId]->mSlotId = phoneId;
    }
    return s_vsimAtcRadioIndication[phoneId];
}

/*****************************************************************************/

/**
 * Convert AT commands to apdu for CRSM and MBAU
 */
int convertToApdu(int phoneId, char *atCommand, char *apdu, char *updatedApdu,
        int len) {
    int err;
    int ins_type = UNKNOWN;
    char *tmp = atCommand;

    RLOGD("atCommand = %s, %s", atCommand, tmp);
    if (strStartsWith(tmp, "\"CRSM\"")) {  // CRSM
        int ins;
        int efid;
        int p1, p2, p3;
        char *data = NULL;
        char *path = NULL;

        err = at_tok_start(&tmp, ':');
        if (err < 0) goto out;

        err = at_tok_nextint(&tmp, &ins);
        if (err < 0) goto out;

        err = at_tok_nextint(&tmp, &efid);
        if (err < 0) goto out;

        err = at_tok_nextint(&tmp, &p1);
        if (err < 0) goto out;

        err = at_tok_nextint(&tmp, &p2);
        if (err < 0) goto out;

        err = at_tok_nextint(&tmp, &p3);
        if (err < 0) goto out;

        err = at_tok_nextstr(&tmp, &data);
        if (err < 0) goto out;

        err = at_tok_nextstr(&tmp, &path);
        if (err < 0) goto out;

        RLOGD("ins = %X, efid = %X, p1 = %X, p2 = %X, p3 = %X, data = %s, path = %s",
                ins, efid, p1, p2, p3, data, path);

        switch (ins) {
            case 0xC0: {
                ins_type = SELECT_FILE;
                if (strstr(path, "7FFF")) {
                    RLOGD("path contain 7fff, select by path");
                    path = path + 4;
                    p3 = strlen(path) / 2 + 2;
                    snprintf(apdu, len * sizeof(char), "00A40804%02X%s%X", p3,
                            path, efid);
                } else {
                    snprintf(apdu, len * sizeof(char), "00A4000002%X", efid);
                }
                break;
            }
            case 0XB0: {
                ins_type = READ_BINARY;
                snprintf(apdu, len * sizeof(char), "00B0%02X%02X%02X", p1, p2, p3);
                break;
            }
            case 0xB2: {
                ins_type = READ_RECORD;
                snprintf(apdu, len * sizeof(char), "00B2%02X%02X%02X", p1, p2, p3);
                break;
            }
            case 0xDC: {
                ins_type = UPDATE_RECORD;
                if (strstr(path, "7FFF")) {
                    RLOGD("path contain 7fff, select by path");
                    path = path + 4;
                    int p3_temp = strlen(path) / 2 + 2;
                    snprintf(apdu, len * sizeof(char), "00A4080C%02X%s%X",
                            p3_temp, path, efid);
                } else {
                    snprintf(apdu, len * sizeof(char), "00A4000C02%X", efid);
                }
                snprintf(updatedApdu, len * sizeof(char), "00DC%02X%02X%02X%s",
                        p1, p2, p3, data);
                break;
            }
            case 0xD6: {
                ins_type = UPDATE_BINARY;
                if (strstr(path, "7FFF")) {
                    RLOGD("path contain 7fff, select by path");
                    path = path + 4;
                    int p3_temp = strlen(path) / 2 + 2;
                    snprintf(apdu, len * sizeof(char), "00A4080C%02X%s%X",
                            p3_temp, path, efid);
                } else {
                    snprintf(apdu, len * sizeof(char), "00A4000C02%X", efid);
                }
                snprintf(updatedApdu, len * sizeof(char), "00D60000%02X%s", p3, data);
                break;
            }
            default:
                RLOGE("Invalid ins %X", ins);
                break;
        }
    } else if (strStartsWith(tmp, "\"MBAU\"")) {  // MBAU
        ins_type = AUTHEN;
        char *rand = NULL;
        char *auth = NULL;
        int vsim_auth_cause;

        err = at_tok_start(&tmp, ':');
        if (err < 0) goto out;

        err = at_tok_nextstr(&tmp, &rand);
        if (err < 0) goto out;

        err = at_tok_nextstr(&tmp, &auth);
        if (err < 0) goto out;

        err = at_tok_nextint(&tmp, &vsim_auth_cause);
        if (err < 0) goto out;

        RLOGD("rand = %s, auth = %s, vsim_auth_cause = %d, phoneId = %d", rand,
                auth, vsim_auth_cause, phoneId);

        if (phoneId == 0) {
            s_vsimAuthCause1 = vsim_auth_cause;
        } else {
            s_vsimAuthCause2 = vsim_auth_cause;
        }
        if (auth != NULL && strlen(auth) != 0) {
            snprintf(apdu, len * sizeof(char), "008800812210%s10%s", rand, auth);
        } else {
            snprintf(apdu, len * sizeof(char), "00880081%02x%02x%s",
                    strlen(rand) / 2 + 1, strlen(rand) / 2, rand);
        }
    }

    RLOGD("apdu = %s, updatedApdu = %s", apdu, updatedApdu);

out:
    return ins_type;
}

/**
 * if select file or MBAU, need getResponse
 */
int getResponse(unsigned char *resp, char *apdu, int len, int ins) {
    RLOGE("getResponse resp: %s", resp);
    char *line = NULL;
    int sw1, sw2;
    line = strdup((char *)resp);
    int respLen = strlen(line);

    if (respLen != 4) {
        RLOGE("SCARD: unexpected resp len %d (expected 4)", respLen);
        goto error;
    }

    sscanf(&(line[0]), "%02x%02x", &sw1, &sw2);
    RLOGD("sw1 = %X, sw2 = %X", sw1, sw2);

    if (ins == SELECT_FILE) {
        if (sw1 == 0x98 && sw2 == 0x04) {
            RLOGE("Security status not satisfied (PIN_WLAN)");
            goto error;
        }
        if (sw1 == 0x6e) {
            RLOGE("used CLA not supported");
            goto error;
        }
        if (sw1 != 0x6c && sw1 != 0x9f && sw1 != 0x61) {
            RLOGE("unexpected response 0x%02X (expected 0x61, 0x6c, or 0x9f)", sw1);
            goto error;
        }
        snprintf(apdu, len * sizeof(char), "00C00000%X", sw2);
        RLOGD("SELECT_FILE, apdu = %s", apdu);
    } else if (ins == AUTHEN) {
        if (sw1 == 0x98 && sw2 == 0x62) {
            RLOGE("UMTS auth failed - MAC != XMAC");
            goto error;
        } else if (sw1 != 0x61) {
            RLOGE("unexpected response for UMTS auth request (resp=%02x %02x)",
                    sw1, sw2);
            goto error;
        }
        snprintf(apdu, len * sizeof(char), "00C00000%X", sw2);
        RLOGD("AUTHEN, apdu = %s", apdu);
    } else if (ins == UPDATE_RECORD || ins == UPDATE_BINARY) {
        if (sw1 == 0x98 && sw2 == 0x04) {
            RLOGE(" Security status not satisfied (PIN_WLAN)");
            goto error;
        }
        if (sw1 == 0x6e) {
            RLOGE("used CLA not supported");
            goto error;
        }
        if (sw1 != 0x90 || sw2 != 0x00) {
            RLOGE("unexpected response 0x%02X, 0x%02X (expected 0x90, 0x00)",
                    sw1, sw2);
            goto error;
        }
    }

    free(line);
    return 1;

error:
    free(line);
    return -1;
}

/**
 * convert status from apdu
 */
void convertStatusFromapdu(unsigned char *apdu, unsigned char *response, int type) {
    RLOGD("convertStatusFromapdu: apdu = %s, type = %d", apdu, type);
    int sw1, sw2, len;
    len = strlen((char *)apdu);

    if (len != 4) {
        RLOGE("SCARD: unexpected resp len %d (expected 4)", len);
        return;
    }

    sscanf((char *)&(apdu[0]), "%02x%02x", &sw1, &sw2);
    RLOGD("sw1 = %X, sw2 = %X", sw1, sw2);

    if (type == RESPONSE_TYPE_SIM) {
        snprintf((char *)response, (len + 20) * sizeof(char), "\"CRSM\",%d,%d",
                sw1, sw2);
    } else if (type == RESPONSE_TYPE_AUTH) {
        int status;
        if (sw1 == 0x98 && sw2 == 0x62) {
            RLOGE("UMTS auth failed - MAC != XMAC");
            status = 2;
        } else {
            RLOGE("unexpected response for UMTS auth request (resp=%02x %02x)",
                    sw1, sw2);
            status = 4;
        }
        snprintf((char *)response, (strlen((char *)apdu) + 20) * sizeof(char),
                "\"MBAU\",%d,", status);
    }
    RLOGD("response = %s", response);
}

/**
 * convert apdu to at commands
 */
void convertFromapdu(unsigned char *apdu, unsigned char *response, int type) {
    RLOGD("convertFromapdu: apdu = %s", apdu);

    if (type == RESPONSE_TYPE_SIM) {
        int sw1, sw2, len;

        len = strlen((char *)apdu);
        RLOGD("len = %d", len);

        sscanf((char *)&(apdu[len - 4]), "%02x%02x", &sw1, &sw2);
        RLOGD("sw1 = %X, sw2 = %X", sw1, sw2);

        apdu[len - 4] = '\0';
        RLOGD("apdu = %s", apdu);

        snprintf((char *)response, (len + 20) * sizeof(char),
                "\"CRSM\",%d,%d,\"%s\"", sw1, sw2, apdu);
        RLOGD("response = %s", response);
    } else if (type == RESPONSE_TYPE_AUTH) {
        int status, len, flag;
        char *res, *ck, *ik, *auts, *sres, *kc;
        int resLen, ckLen, ikLen, autsLen, sresLen, kcLen;

        sscanf((char *)&(apdu[0]), "%02X", &flag);
        RLOGD("flag = %X", flag);

        switch (flag) {
            case 0xDB: {
                // 0xdb + resLen + res + ckLen + ck  + ikLen + ik
                status = SIM_AUTH_RESPONSE_SUCCESS;
                sscanf((char *)&(apdu[2]), "%02X", &resLen);
                res = (char *) calloc((resLen * 2 + 1),  sizeof(char));
                memcpy(res, apdu + 4, resLen * 2);
                RLOGD("resLen = %X, res = %s", resLen, res);

                sscanf((char *)&(apdu[4 + resLen * 2]), "%02X", &ckLen);
                ck = (char *)calloc((ckLen * 2 + 1), sizeof(char));
                memcpy(ck, apdu + 6 + resLen * 2, ckLen * 2);
                RLOGD("ckLen = %X, ck = %s", ckLen, ck);

                sscanf((char *)&(apdu[6 + resLen * 2 + ckLen * 2]), "%02X", &ikLen);
                ik = (char *)calloc((ikLen * 2 + 1), sizeof(char));
                memcpy(ik, apdu + 8 + resLen * 2 + ckLen * 2, ikLen * 2);
                RLOGD("ikLen = %X, ik = %s", ikLen, ik);

                snprintf((char *)response, (strlen((char *)apdu) + 20) * sizeof(char),
                        "\"MBAU\",%d,\"%s\",\"%s\",\"%s\"", status, res, ck, ik);
                RLOGD("response = %s", response);
                free(res);
                free(ck);
                free(ik);
                break;
            }
            case 0xDC: {
                // 0xdc + autsLen + auts
                status = SIM_AUTH_RESPONSE_SYNC_FAILURE;
                sscanf((char *)&(apdu[2]), "%02X", &autsLen);
                auts = (char *)calloc((autsLen * 2 + 1), sizeof(char));
                memcpy(auts, apdu + 4, autsLen * 2);
                RLOGD("autsLen = %X, auts = %s", autsLen, auts);
                snprintf((char *)response, (strlen((char *)apdu) + 20) * sizeof(char),
                        "\"MBAU\",%d,\"%s\"",status, auts);
                RLOGD("response = %s", response);
                free(auts);
                break;
            }
            case 0x04: {
                // for triple case, didn't have flag field, just form by "sresLen sres kcLen kc 9000", and sresLen=4
                // 04 565B71AD 08 3624962EBCE1DD8F 9000
                len = strlen((char*)apdu);
                status = SIM_AUTH_RESPONSE_SUCCESS;
                sresLen = 4;
                RLOGE("sresLen = %X", sresLen);
                if (2 + sresLen * 2 > len) {
                    RLOGE("unexpected flag %x", sresLen);
                    break;
                }
                sres = (char *)malloc((sresLen * 2 + 1) * sizeof(char));
                memset(sres, 0, (sresLen * 2 + 1) * sizeof(char));
                memcpy(sres, apdu + 2, sresLen * 2);
                RLOGE("sres = %s", sres);

                sscanf((char*)&(apdu[2 + sresLen * 2]), "%02X", &kcLen);
                if (4 + sresLen * 2 + kcLen * 2 > len) {
                    RLOGE("unexpected flag %x", kcLen);
                    free(sres);
                    break;
                }
                RLOGE("kcLen = %X", kcLen);
                kc = (char *)malloc((kcLen * 2 + 1) * sizeof(char));
                memset(kc, 0, (kcLen * 2 + 1) * sizeof(char));
                memcpy(kc, apdu + 4 + sresLen * 2, kcLen * 2);
                RLOGE("kc = %s", kc);
                snprintf((char*)response, (strlen((char*)apdu) + 20) * sizeof(char),
                        "\"MBAU\",%d,\"%s\",\"%s\"",status, sres, kc);
                RLOGE("response = %s", response);
                free(sres);
                free(kc);
                break;
            }
            default:
                RLOGE("unexpected flag %x", flag);
                break;
        }
    }
}

static void processCRSM(char *atCommand) {
    int serviceId = -1;
    int err = 0;
    int type = -1;
    char *atData = atCommand;

    unsigned char apdu[APDU_BUFFER_BYTES] = {0};
    unsigned char apduHex[APDU_BUFFER_BYTES] = {0};
    unsigned char resp[MAX_BUFFER_BYTES]  = {0};
    unsigned char respHex[MAX_BUFFER_BYTES]  = {0};
    unsigned char data[MAX_BUFFER_BYTES]  = {0};
    unsigned char updatedApdu[APDU_BUFFER_BYTES] = {0};
    unsigned char updatedApduHex[APDU_BUFFER_BYTES] = {0};

    at_tok_nextint(&atData , &serviceId);

    type = RESPONSE_TYPE_SIM;

    int ins_type = convertToApdu(serviceId, atData, (char *)apduHex,
            (char *)updatedApduHex, APDU_BUFFER_BYTES);
    convertHexToBin(apduHex, strlen((char *)apduHex), apdu);
    convertHexToBin(updatedApduHex, strlen((char *)updatedApduHex), updatedApdu);
    RLOGD("spfnCommand apdu_req: %s ", apduHex);
    RLOGD("spfnCommand apdu_req_update: %s ", updatedApduHex);
    int len = spfnCommand((u8)serviceId, apdu,
            (u16)(strlen((char *)apduHex) / 2), resp, (u16)MAX_BUFFER_BYTES);
    convertBinToHex(resp, len, respHex);
    RLOGD("spfnCommand apdu_rsp: %s, ins_type: %d", respHex, ins_type);

    if (ins_type == SELECT_FILE || ins_type == UPDATE_RECORD ||
            ins_type == UPDATE_BINARY) {
        memset(apdu, 0 ,APDU_BUFFER_BYTES);
        memset(apduHex, 0 ,APDU_BUFFER_BYTES);
        memset(resp, 0 ,MAX_BUFFER_BYTES);
        err = getResponse(respHex, (char *)apduHex, APDU_BUFFER_BYTES,
                ins_type);
        convertHexToBin(apduHex, strlen((char *)apduHex), apdu);
        if (err < 0) {
            convertStatusFromapdu(respHex, data, type);
            RLOGD("send to vism:%s", data);
            vsim_send_data(serviceId, data, (u16)strlen((char *)data));
            return;
        } else {
            if (ins_type == SELECT_FILE) {
                RLOGD("spfnCommand apdu_req: %s, ins_type:%d", apduHex, ins_type);
                len = spfnCommand((u8)serviceId, apdu,
                        (u16)(strlen((char *)apduHex) / 2), resp,
                        (u16)MAX_BUFFER_BYTES);
                convertBinToHex(resp, len, respHex);
            } else {
                RLOGD("spfnCommand apdu_req: %s, ins_type: %d",
                        updatedApduHex, ins_type);
                len = spfnCommand((u8)serviceId, updatedApdu,
                        (u16)(strlen((char *)updatedApduHex) / 2), resp,
                        (u16)MAX_BUFFER_BYTES);
                convertBinToHex(resp, len, respHex);
            }
            RLOGD("spfnCommand apdu_rsp:%s  ins_type:%d", respHex, ins_type);
        }
    }

    if (strlen((char *)respHex) == 4) {
        RLOGE("resp len is 4, just return status");
        convertStatusFromapdu(respHex, data, type);
    } else {
        convertFromapdu(respHex, data, type);
    }
    RLOGD("send to vism: %s", data);
    vsim_send_data(serviceId, data, (u16)strlen((char *)data));
}

static void processMbau(void *param) {
    int type = RESPONSE_TYPE_AUTH;
    int serviceId = -1;
    char *line = (char *)param;

    unsigned char apdu[APDU_BUFFER_BYTES] = {0};
    unsigned char apduHex[APDU_BUFFER_BYTES] = {0};
    unsigned char resp[MAX_BUFFER_BYTES]  = {0};
    unsigned char respHex[MAX_BUFFER_BYTES]  = {0};
    unsigned char data[MAX_BUFFER_BYTES]  = {0};
    unsigned char updatedApduHex[APDU_BUFFER_BYTES] = {0};

    at_tok_nextint(&line , &serviceId);

    int ins_type = convertToApdu(serviceId, line, (char *)apduHex,
            (char *)updatedApduHex,  APDU_BUFFER_BYTES);
    convertHexToBin(apduHex, strlen((char *)apduHex), apdu);
    RLOGD("spfnCommand apdu_req: %s ", apduHex);
    int len = spfnCommand((u8)serviceId, apdu, (u16)(strlen((char *)apduHex) / 2),
            resp, (u16)MAX_BUFFER_BYTES);
    convertBinToHex(resp, len, respHex);
    RLOGD("spfnCommand apdu_rsp: %s, ins_type: %d", respHex, ins_type);

    memset(apdu, 0 ,APDU_BUFFER_BYTES);
    memset(apduHex, 0 ,APDU_BUFFER_BYTES);
    memset(resp, 0 ,MAX_BUFFER_BYTES);
    int error = getResponse(respHex, (char *)apduHex, APDU_BUFFER_BYTES, ins_type);
    convertHexToBin(apduHex, strlen((char *)apduHex), apdu);
    if (error < 0) {
        convertStatusFromapdu(respHex, data, type);
        RLOGD("send to vism: %s", data);
        vsim_send_data(serviceId, data, (u16)strlen((char *)data));
    } else {
        RLOGD("spfnCommand apdu_req: %s  ins_type:%d", apduHex, ins_type);
        len = spfnCommand((u8)serviceId, apdu, (u16)(strlen((char *)apduHex) / 2),
                resp, (u16)MAX_BUFFER_BYTES);
        convertBinToHex(resp, len, respHex);
        RLOGD("spfnCommand apdu_rsp: %s  ins_type: %d", respHex, ins_type);

        if (strlen((char *)respHex) == 4) {
            RLOGE("resp len is 4, just return status");
            convertStatusFromapdu(respHex, data, type);
        } else {
            convertFromapdu(respHex, data, type);
        }
        RLOGD("send to vsim: %s", data);
        vsim_send_data(serviceId, data, (u16)strlen((char *)data));
    }
}

void *processVsimRSimReq(void *param) {
    int simId = ((int *)param)[0];
    if (simId < 0 || simId >= MAX_VSIM_COUNT) {
        RLOGE("Invalid simId: %d", simId);
        return NULL;
    }

    s_vsimReqThreadTid[simId] = gettid();
    RLOGD("s_vsimReqThreadTid[%d] = %d", simId, s_vsimReqThreadTid[simId]);

    pthread_mutex_t *pListMutex = &s_vsimReqListMutex[simId];
    pthread_cond_t *pListCond = &s_vsimReqListCond[simId];
    ListNode *pList = s_vsimReqList[simId];
    ListNode *node = NULL;

    RLOGD("Start to process vsim request");
    while (1) {
        pthread_mutex_lock(pListMutex);
        if ((pList->next == pList && s_vsimInitFlag[simId] == true) ||
                s_vsimInitFlag[simId] == false) {
            pthread_cond_wait(pListCond, pListMutex);
        }
        pthread_mutex_unlock(pListMutex);

        for (node = pList->next; node != pList; node = pList->next) {
            char *atData = strdup((char *)(node->data));
            RLOGD("processVsimRSimReq atData: %s", atData);
            if (strstr(atData, "CRSM")) {
                processCRSM(atData);
            } else if (strstr(atData, "MBAU")) {
                processMbau(atData);
            } else {
                RLOGE("unsuported at data: %s", atData);
            }
            RLOGD("-->processVsimRSimReq free one command");
            free(atData);

            pthread_mutex_lock(pListMutex);
            node = pList->next;
            if (node != pList) {
                list_remove(node);  /* remove list node first, then free it */
                free(node->data);
                free(node);
            }
            pthread_mutex_unlock(pListMutex);
        }
    }

    free(param);
    return NULL;
}

int sendVsimATCmd(int phoneId, const char *atCmd, char *resp, size_t respLen) {
    RLOGD("sendVsimATCmd > AT Command '%s'. phoneId = %d", atCmd, phoneId);
    if (atCmd == NULL || resp == NULL || phoneId  < 0) {
        RLOGE("Invalid params");
        return -1;
    }
    sp<IExtRadio> mExtRadioProxy = getVsimExtRadioProxy(phoneId);
    if (mExtRadioProxy == NULL) {
        RLOGE("Failed to get connection to radio service, errno: %s", strerror(errno));
        return -1;
    }

    string pStr;
    auto cb = [&](hidl_string atResp) {
        pStr = atResp.c_str();
    };

    Return<void> status = mExtRadioProxy->sendCmdSync(phoneId, hidl_string(atCmd), cb);
    if (!status.isOk()) {
        RLOGE("rild service died");
        snprintf(resp, respLen, "ERROR");
        return -1;
    }

    snprintf(resp, respLen, "%s", pStr.c_str());

    return 0;
}

int vsim_init(int phoneId, VSIM_COMMAND pfn, int restart) {
    RLOGD("vsim_init, phoneId: %d, restart: %d", phoneId, restart);
    int ret = -1;
    int socket_id = phoneId;
    int respLen = MAX_BUFFER_BYTES;
    char resp[MAX_BUFFER_BYTES] = {0};
    sp<IExtRadio> mVsimExtRadioProxy = NULL;
    sp<AtcRadioResponseImpl> mVsimAtcRadioResponse = NULL;
    sp<AtcRadioIndicationImpl> mVsimAtcRadioIndication = NULL;

    if (phoneId < 0 || phoneId >= MAX_VSIM_COUNT) {
        RLOGE("Invalid phoneId");
        return -1;
    }

    char atCmdInit[MAX_BUFFER_BYTES] = "VSIM_INIT:AT+RSIMRSP=\"VSIM\",1";

    spfnCommand = pfn;
    s_vsimInitFlag[phoneId] = true;

    if (phoneId == 0) {
        s_vsimAuthCause1 = 0;
    } else {
        s_vsimAuthCause2 = 0;
    }

    if (s_vsimReqThreadTid[phoneId] <= 0) {
        pthread_mutex_lock(&s_vsimReqListMutex[phoneId]);
        list_init(&s_vsimReqList[phoneId]);
        pthread_mutex_unlock(&s_vsimReqListMutex[phoneId]);

        pthread_t tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        int *simId = (int *)calloc(1, sizeof(int));
        *simId = phoneId;
        ret = pthread_create(&tid, &attr, processVsimRSimReq, (void *)simId);
        if (ret < 0) {
            RLOGE("Failed to create processVsimRSimReq thread errno: %s", strerror(errno));
            free(simId);
            return -1;
        }
    }

    mVsimExtRadioProxy = getVsimExtRadioProxy(phoneId);
    if (mVsimExtRadioProxy == NULL) {
        RLOGE("Vsim failed to get connection to radio service, errno: %s",
                strerror(errno));
        return -1;
    }

    mVsimAtcRadioResponse = getVsimAtcRadioResponse(phoneId);
    if (mVsimAtcRadioResponse == NULL) {
        RLOGE("Vsim failed to get mVsimAtcRadioResponse, errno: %s",
                strerror(errno));
        return -1;
    }

    mVsimAtcRadioIndication = getVsimAtcRadioIndication(phoneId);
    if (mVsimAtcRadioIndication == NULL) {
        RLOGE("Vsim failed to get mVsimAtcRadioIndication, errno: %s",
                strerror(errno));
        return -1;
    }

    if (s_radioProxyHalDied == nullptr) {
        s_radioProxyHalDied= new RadioProxyDeathRecipient();
    }

    if (s_radioProxyHalDied != nullptr) {
        mVsimExtRadioProxy->linkToDeath(s_radioProxyHalDied, 1 /* cookie */);
    }

    Return<void> setStatus = mVsimExtRadioProxy->setAtcResponseFunctions(
            mVsimAtcRadioResponse, mVsimAtcRadioIndication);
    if (!setStatus.isOk()) {
        RLOGE("setAtcResponseFunctions : rild service died");
        return -1;
    }

    if (!restart) {
        if (sendVsimATCmd(socket_id, atCmdInit, resp, respLen) < 0) {
            RLOGE("Failed to sendVsimATCmd %s", atCmdInit);
            return -1;
        }
        RLOGD("vsim_init resp:%s",resp);
        if (strncasecmp(resp, "OK", 2) != 0) {
            return -1;
        }
    }

    return 1;
}

int vsim_send_data(int phoneId, u8* data, u16 data_len) {
    RLOGD("vsim_send_data, phoneId: %d", phoneId);
    // default sim0
    int socket_id = phoneId;
    char atCmd[MAX_BUFFER_BYTES] = {0};
    char resp[MAX_BUFFER_BYTES] = {0};

    // strlcat(atCmd, "%RSIMRSP=", sizeof(atCmd));
    strlcat(atCmd, "AT+RSIMRSP=", sizeof(atCmd));
    strlcat(atCmd, (char *)data, sizeof(atCmd));

    if (sendVsimATCmd(socket_id, atCmd, resp, data_len) < 0) {
        RLOGE("Failed to sendVsimATCmd %s", atCmd);
        return -1;
    }

    RLOGD("vsim_send_data resp:%s",resp);

    return 1;
}

int vsim_exit(int phoneId) {
    RLOGD("vsim_exit, phoneId: %d", phoneId);
    int socket_id = phoneId;
    char atCmd[MAX_BUFFER_BYTES] = "VSIM_EXIT:AT+RSIMRSP=\"VSIM\",0";
    char resp[MAX_BUFFER_BYTES] = {0};
    int respLen = MAX_BUFFER_BYTES;

    if (phoneId == 0) {
        s_vsimAuthCause1 = 0;
    } else {
        s_vsimAuthCause2 = 0;
    }
    if (sendVsimATCmd(socket_id, atCmd, resp, respLen) < 0) {
        RLOGE("Failed to sendVsimATCmd %s", atCmd);
        return -1;
    }

    pthread_mutex_lock(&s_vsimReqListMutex[phoneId]);
    s_vsimInitFlag[phoneId] = false;
    ListNode *pList = s_vsimReqList[phoneId];
    ListNode *node = NULL;
    RLOGD("vsim exit, ignore the s_vsimReqList");
    if (pList != NULL) {
        for (node = pList->next; node != pList; node = pList->next) {
            list_remove(node);
            free(node->data);
            free(node);
        }
    }
    pthread_cond_signal(&s_vsimReqListCond[phoneId]);
    pthread_mutex_unlock(&s_vsimReqListMutex[phoneId]);

    if (strncmp(resp, "OK", 2) == 0 && (!s_vsimInitFlag[MAX_VSIM_COUNT - 2]) &&
            (!s_vsimInitFlag[MAX_VSIM_COUNT - 1])) {
        RLOGD("vsim exit,free");
    }
    return 1;
}

int vsim_set_authid(int authid) {
    RLOGD("vsim_set_authid, authid: %d", authid);
    // 0 means sim1, 1 means sim2, default is sim2
    int socket_id = 1;

    char atCmd[MAX_BUFFER_BYTES] = {0};
    char resp[MAX_BUFFER_BYTES] = {0};

    if (s_vsimMbauId >= 0) {
        socket_id = s_vsimMbauId;
    }
    RLOGD("vsim authentication phone id: %d",socket_id);
    snprintf(atCmd, sizeof(atCmd), "AT+SPVSIMAUTHSET=%d", authid);

    if (sendVsimATCmd(socket_id, atCmd, resp, MAX_BUFFER_BYTES) < 0) {
        RLOGE("Failed to sendVsimATCmd %s", atCmd);
        return VSIM_PROCESS_FAIL;
    }

    RLOGD("vsim_set_authid resp:%s",resp);
    if (!strStartsWith(resp, "OK")) {
        return VSIM_PROCESS_FAIL;
    }

    return VSIM_PROCESS_SUCCESS;
}

int vsim_query_authid() {
    RLOGD("vsim_query_authid");
    int err = -1;
    int authid = -1;
    // default sim0
    int socket_id = 1;
    char atCmd[MAX_BUFFER_BYTES] = {0};
    char resp[MAX_BUFFER_BYTES] = {0};
    char *respTmp = resp;

    snprintf(atCmd, sizeof(atCmd), "AT+SPVSIMAUTHSET?");

    if (sendVsimATCmd(socket_id, atCmd, respTmp, MAX_BUFFER_BYTES) < 0) {
        RLOGE("Failed to sendVsimATCmd %s", atCmd);
        return -1;
    }

    RLOGD("vsim_query_authid resp:%s",respTmp);
    if (strStartsWith(respTmp, "+SPVSIMAUTHSET:")) {
        err = at_tok_start(&respTmp, ':');
        err = at_tok_nextint(&respTmp, &authid);
        return authid;
    }

    return -1;
}

int vsim_set_virtual(int phoneId, int mode) {
    RLOGD("vsim_set_virtual, phoneId: %d", phoneId);

    int ret = VSIM_PROCESS_FAIL;
    int socket_id = phoneId;   // default sim0
    char atCmd[MAX_BUFFER_BYTES] = {0};
    char resp[MAX_BUFFER_BYTES] = {0};

    RLOGD("vsim authentication id: %d",mode);
    snprintf(atCmd, sizeof(atCmd), "AT+VIRTUALSIMINIT=%d", mode);

    if (sendVsimATCmd(socket_id, atCmd, resp, MAX_BUFFER_BYTES) < 0) {
        RLOGE("Failed to sendVsimATCmd %s", atCmd);
        goto out;
    }

    RLOGD("vsim_set_virtual resp:%s",resp);
    if (strStartsWith(resp, "OK")) {
        goto out;
    }

    ret = VSIM_PROCESS_SUCCESS;

out:
    return ret;
}

int vsim_set_nv(int phoneId, int type, int isWrite) {
    RLOGD("vsim_set_nv, phoneId: %d", phoneId);

    int ret = VSIM_PROCESS_FAIL;
    int socket_id = phoneId;  // default sim0
    char atCmd[MAX_BUFFER_BYTES] = {0};
    char resp[MAX_BUFFER_BYTES] = {0};

    RLOGD("vsim_set_nv type:%d, isWrite:%d",type, isWrite);
    snprintf(atCmd, sizeof(atCmd), "AT+VIRTUALSIMINIT=%d,%d", type, isWrite);

    if (sendVsimATCmd(socket_id, atCmd, resp, MAX_BUFFER_BYTES) < 0) {
        RLOGE("Failed to sendVsimATCmd %s", atCmd);
        goto out;
    }

    RLOGD("vsim_set_nv resp:%s",resp);
    if (!strStartsWith(resp, "OK")) {
        goto out;
    }

    ret = VSIM_PROCESS_SUCCESS;

out:
    return ret;
}

int vsim_query_virtual(int phoneId) {
    RLOGD("vsim_query_virtual, phoneId: %d", phoneId);

    int err = -1;
    int vsimMode = -1;
    int socket_id = phoneId;  // default sim0
    char atCmd[MAX_BUFFER_BYTES] = {0};
    char resp[MAX_BUFFER_BYTES] = {0};
    char *respTmp = resp;

    strlcat(atCmd, "AT+VIRTUALSIMINIT?", sizeof(atCmd));

    if (sendVsimATCmd(socket_id, atCmd, respTmp, MAX_BUFFER_BYTES) < 0) {
        RLOGE("Failed to sendVsimATCmd %s", atCmd);
        return VSIM_PROCESS_FAIL;
    }

    RLOGD("vsim_query_virtual resp:%s",respTmp);
    if (strStartsWith(respTmp, "+VIRTUALSIMINIT:")) {
        err = at_tok_start(&respTmp, ':');
        err = at_tok_nextint(&respTmp, &vsimMode);
        return vsimMode;
    }

    return VSIM_PROCESS_FAIL;
}

int vsim_get_auth_cause(int phoneId) {
    if (phoneId == 0) {
        return s_vsimAuthCause1;
    } else {
        return s_vsimAuthCause2;
    }
}

int vsim_set_timeout(int time) {
    RLOGD("vsim_set_timeout, time: %d", time);

    int socket_id = 0;
    char atCmd[MAX_BUFFER_BYTES] = {0};
    char resp[MAX_BUFFER_BYTES] = {0};
    char *respTmp = resp;

    snprintf(atCmd, sizeof(atCmd), "VSIM_TIMEOUT:%d", time);

    if (sendVsimATCmd(socket_id, atCmd, respTmp, MAX_BUFFER_BYTES) < 0) {
        RLOGE("Failed to sendVsimATCmd %s", atCmd);
        return VSIM_PROCESS_FAIL;
    }

    RLOGD("vsim_set_timeout resp:%s",resp);
    if (!strStartsWith(resp, "OK")) {
        return VSIM_PROCESS_FAIL;
    }

    return VSIM_PROCESS_SUCCESS;
}

int parseFromApdu(char *apdu, char *response, int size) {
    int efid = -1;
    char path[128] = {0};
    char *line = NULL;
    char *tmp;
    line = strdup(apdu);
    tmp = line;
    printf("tmp =  %s\n", tmp);
    int ins;
    int p1, p2, p3;
    int len;
    char data[128] = {0};
    char rand[128] = {0};
    char autn[128] = {0};
    sscanf(&(tmp[2]), "%02x%02x%02x%02x", &ins, &p1, &p2, &p3);

    RLOGD("parseFromApdu: %x, %x, %x %x\n",ins, p1, p2, p3);
    if (ins == 0x88) {
        sscanf(&(tmp[12]), "%32s", rand);
        sscanf(&(tmp[46]), "%32s", autn);
        printf("Autn :%s, %s\n",rand, autn);
        sprintf(response, "AT^MBAU=\"%s\",\"%s\"", rand, autn);
        RLOGD("response:%s\n",response);
    } else {
        switch (ins) {
            case 0xA4:
                ins = 0xC0;
                printf("ins = %x\n", ins);

                if (p1 == 0x08 && p2 == 0x04 ) {
                    len = strlen(tmp);
                    snprintf(path, p3*2 + 1, "3FFF%s", &tmp[10]);
                    sscanf(&(tmp[len-4]), "%04x",  &efid);
                } else {
                   sscanf(&(tmp[10]), "%04x",  &efid);
                }
                p1 = 0;
                p2 = 0;
                p3 = 15;
                RLOGD("efid = %x\n",efid);
                RLOGD("path = %s\n",path);
                break;
            case 0xDC:
                sscanf(&(tmp[10]), "%s", data);
                break;
            case 0xD6:
                sscanf(&(tmp[10]), "%s", data);
                break;
            case 0xB0:
            case 0xB2:
                break;
            default:
                RLOGD("Invalid ins %X", ins);
                free(line);
                return -1;
        }
        sprintf(response, "AT+CRSM=%d,%d,%d,%d,%d,\"%s\",\"%s\"",ins, efid, p1,
                p2, p3, data, path);
        RLOGD("response: %s",response);
    }
    free(line);
    return 1;
}

int parseToApdu(char *atCmd, char *apdu, int size) {
    int err = -1;
    int sw1 = 0, sw2 = 0;
    int status;
    int resLen, ckLen, ikLen, autsLen;
    char *line = NULL;
    char *tmp;
    char *data;
    char *res, *ck, *ik, *auts;

    line = strdup(atCmd);
    tmp = line;
    RLOGD("tmp: %s", tmp);
    if (strStartsWith(tmp, "+CRSM:")) {
        err = at_tok_start(&tmp, ':');
        if (err < 0) goto error;

        err = at_tok_nextint(&tmp, &sw1);
        if (err < 0) goto error;

        err = at_tok_nextint(&tmp, &sw2);
        if (err < 0) goto error;

        if (at_tok_hasmore(&tmp)) {
            err = at_tok_nextstr(&tmp, &data);
            if (err < 0) goto error;

            sprintf(apdu, "%s%02x%02x", data, sw1, sw2);
        } else {
            sprintf(apdu, "%02x%02x", sw1, sw2);
        }
    } else if (strStartsWith(tmp, "^MBAU:")) {
        err = at_tok_start(&tmp, ':');
        if (err < 0) goto error;

        err = at_tok_nextint(&tmp, &status);
        if (err < 0) goto error;

        if (status == SIM_AUTH_RESPONSE_SUCCESS) {
            err = at_tok_nextstr(&tmp, &res);
            if (err < 0) goto error;
            resLen = strlen(res) / 2;

            err = at_tok_nextstr(&tmp, &ck);
            if (err < 0) goto error;
            ckLen = strlen(ck) / 2;

            err = at_tok_nextstr(&tmp, &ik);
            if (err < 0) goto error;
            ikLen = strlen(ik) / 2;
            // 0xdb + resLen + res + ckLen + ck  + ikLen + ik+sw1+sw2
            sw1 = 0x90;
            sw2 = 0x00;
            sprintf(apdu, "db%02x%s%02x%s%02x%s%02x%02x", resLen, res, ckLen, ck,
                    ikLen, ik, sw1, sw2);
            RLOGD("apdu %s", apdu);
        } else if (status == SIM_AUTH_RESPONSE_SYNC_FAILURE) {
            err = at_tok_nextstr(&tmp, &auts);
            if (err < 0) goto error;

            autsLen = strlen(auts) / 2;
            RLOGD("requestUSimAuthentication auts = %s, autsLen = %d",
                    auts, autsLen);
            // 0xdc + autsLen + auts
            sprintf(apdu, "dc%02x%s%02x%02x", autsLen, auts, sw1, sw2);
            RLOGD("apdu %s", apdu);
        } else {
            RLOGD("Invalid status  %x", status);
            goto error;
        }
    } else {
        RLOGD("Invalid AT  %s", tmp);
        goto error;
    }

    free(line);
    return 1;

error:
    free(line);
    return -1;
}

int vsim_parse_apdu(int slot, unsigned char *apdu_req, int apdu_req_len,
        unsigned char *apdu_rsp, int apdu_resp_len) {
    char atCmd[MAX_BUFFER_BYTES] = {0};
    char atResp[MAX_BUFFER_BYTES] = {0};
    char apduHex[MAX_BUFFER_BYTES] = {0};

    convertBinToHex(apdu_req, apdu_req_len, (unsigned char *)apduHex);
    if (parseFromApdu(apduHex, atCmd, MAX_BUFFER_BYTES) < 0) {
        return -1;
    }

    if (sendVsimATCmd(slot, atCmd, atResp, MAX_BUFFER_BYTES) < 0) {
        RLOGE("Failed to sendVsimATCmd %s", atCmd);
        return -1;
    }
    RLOGD("vsim_parse_apdu sendVsimATCmd resp:%s",atResp);
    memset(apduHex, 0, MAX_BUFFER_BYTES);

    getNewLine(atResp);
    if (parseToApdu(atResp, apduHex, apdu_resp_len * 2) < 0) {
        return -1;
    }
    convertHexToBin((unsigned char *)apduHex, strlen(apduHex), apdu_rsp);

    return strlen(apduHex) / 2;
}
