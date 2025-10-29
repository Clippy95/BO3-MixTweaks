#pragma once

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>
#include "MemoryMgr.h"
#define DEFINE_FUNC_STDCALL(address, name, return_type, ...) \
    typedef return_type(__stdcall* name##T)(__VA_ARGS__); \
    name##T name = (name##T)(address);

#define DEFINE_FUNC_FASTCALL(address, name, return_type, ...) \
    typedef return_type(__fastcall* name##T)(__VA_ARGS__); \
    name##T name = (name##T)(address);

#define DEFINE_FUNC_CDECL(address, name, return_type, ...) \
    typedef return_type(__cdecl* name##T)(__VA_ARGS__); \
    name##T name = (name##T)(address);

#define DEFINE_FUNC_THISCALL(address, name, return_type, ...) \
    typedef return_type(__thiscall* name##T)(__VA_ARGS__); \
    name##T name = (name##T)(address);

static bool is_wstore = false;

inline uintptr_t REBASE(uintptr_t steamaddress, uintptr_t wstore_address = NULL) {
    uintptr_t handle = (uintptr_t)GetModuleHandle(NULL);
    is_wstore = Memory::VP::MemEquals((0x142F3D078 - 0x140000000) + handle, { 0x73, 0x68, 0x6F, 0x77 });

    if (wstore_address != 0 && is_wstore) {
        if (wstore_address < 0x140000000) {

            return handle + wstore_address;
        }
        else {

            return handle + (wstore_address - 0x140000000);
        }
    }


    if (steamaddress < 0x140000000) {
        return handle + steamaddress;
    }
    else {
        return handle + (steamaddress - 0x140000000);
    }
}