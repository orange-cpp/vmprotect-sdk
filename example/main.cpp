//
// Created by orange on 13.02.2026.
//
#include <VMProtectSDK.h>
#include <cstdio>
#include <string>
int main() {
    VMProtectBeginVirtualization("main");
    std::string hwid;
    std::printf("Hello World!\n, Your hwid is 0x%p", hwid.c_str());

    VMProtectEnd();
}
