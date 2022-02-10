# Copyright (C) 2016 Spreadtrum Communications Inc.
#

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
    atci.cpp \

LOCAL_SHARED_LIBRARIES := \
    liblog \
    libcutils \
    libutils \
    libhidlbase  \
    libhidltransport \
    libhwbinder \
    vendor.sprd.hardware.radio@1.0 \

LOCAL_MODULE := libatci

LOCAL_MODULE_TAGS := optional
LOCAL_PROPRIETARY_MODULE := true

include $(BUILD_SHARED_LIBRARY)

##########################################

#build static library
include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
    vsim.cpp \
    atci.cpp \
    utils.cpp

LOCAL_SHARED_LIBRARIES := \
    liblog \
    libcutils \
    libutils \
    libhidlbase \
    libhidltransport \
    libhwbinder \
    vendor.sprd.hardware.radio@1.0 \

LOCAL_MODULE:= libatci
LOCAL_MODULE_TAGS := optional

include $(BUILD_STATIC_LIBRARY)
