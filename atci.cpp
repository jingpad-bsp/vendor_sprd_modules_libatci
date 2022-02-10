/**
 * AT Command Interface Client Socket implementation
 *
 * Copyright (C) 2015 Spreadtrum Communications Inc.
 *
 */

#define LOG_TAG "ATCI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <utils/Log.h>
#include "atci.h"

#include <vendor/sprd/hardware/radio/1.0/IExtRadio.h>

using namespace vendor::sprd::hardware::radio::V1_0;
using namespace std;
using ::android::hardware::hidl_string;
using ::android::hardware::Return;
using ::android::hardware::Void;
using android::sp;

#define RADIO1_SERVICE_NAME         "slot1"
#define RADIO2_SERVICE_NAME         "slot2"
#define MAX_COMMAND_BYTES           (4 * 1024)

const char *sendCmd(int phoneId, const char *atCmd) {
    RLOGD("> AT Command '%s'. phoneId = %d", atCmd, phoneId);
    if (atCmd == NULL || phoneId  < 0) {
        RLOGE("Invalid params");
        return "ERROR";
    }
    sp<IExtRadio> mExtRadioProxy = IExtRadio::getService(
            hidl_string(phoneId == 0 ? RADIO1_SERVICE_NAME : RADIO2_SERVICE_NAME));
    if (mExtRadioProxy == NULL) {
        RLOGE("Failed to get connection to radio service, errno: %s", strerror(errno));
        return "ERROR";
    }

    string pStr;
    auto cb = [&](hidl_string atResp) {
        pStr = atResp.c_str();
    };

    Return<void> status = mExtRadioProxy->sendCmdSync(phoneId, hidl_string(atCmd), cb);
    if (!status.isOk()) {
        RLOGE("rild service died");
        return "ERROR";
    }

    static char resp[MAX_COMMAND_BYTES] = {0};
    memset(resp, 0, MAX_COMMAND_BYTES);
    snprintf(resp, MAX_COMMAND_BYTES, "%s", pStr.c_str());

    return resp;
}

int sendATCmd(int phoneId, const char *atCmd, char *resp, size_t respLen) {
    RLOGD("sendATCmd > AT Command '%s'. phoneId = %d", atCmd, phoneId);
    if (atCmd == NULL || resp == NULL || phoneId  < 0) {
        RLOGE("Invalid params");
        return -1;
    }
    sp<IExtRadio> mExtRadioProxy = IExtRadio::getService(
            hidl_string(phoneId == 0 ? RADIO1_SERVICE_NAME : RADIO2_SERVICE_NAME));
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
