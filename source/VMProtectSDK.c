//
// Created by orange on 13.02.2026.
//
#include <VMProtectSDK.h>

void VMProtectBegin(const char *) {
}

void VMProtectBeginVirtualization(const char *) {
}

void VMProtectBeginMutation(const char *) {
}

void VMProtectBeginUltra(const char *) {
}

void VMProtectBeginVirtualizationLockByKey(const char *) {
}

void VMProtectBeginUltraLockByKey(const char *) {
}

void VMProtectEnd(void) {
}

bool VMProtectIsProtected() {
    return false;
}

bool VMProtectIsDebuggerPresent(bool) {
    return false;
}

bool VMProtectIsVirtualMachinePresent(void) {
    return false;
}

bool VMProtectIsValidImageCRC(void) {
    return false;
}

const char * VMProtectDecryptStringA(const char *value) {
    return value;
}

const unsigned short * VMProtectDecryptStringW(const unsigned short *value) {
    return value;
}

bool VMProtectFreeString(const void *value) {
    return true;
}

int VMProtectSetSerialNumber(const char *serial) {
    return SERIAL_STATE_FLAG_INVALID;
}

int VMProtectGetSerialNumberState() {
    return SERIAL_STATE_FLAG_INVALID;
}

bool VMProtectGetSerialNumberData(VMProtectSerialNumberData *data, int size) {
    return false;
}

int VMProtectGetCurrentHWID(char *hwid, int size) {
    return 0;
}

int VMProtectActivateLicense(const char *code, char *serial, int size) {
    return ACTIVATION_NOT_AVAILABLE;
}

int VMProtectDeactivateLicense(const char *serial) {
    return ACTIVATION_NOT_AVAILABLE;
}

int VMProtectGetOfflineActivationString(const char *code, char *buf, int size) {
    return ACTIVATION_NOT_AVAILABLE;
}

int VMProtectGetOfflineDeactivationString(const char *serial, char *buf, int size) {
    return ACTIVATION_NOT_AVAILABLE;
}
