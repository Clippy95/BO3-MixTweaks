// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "MinHook.h"
#include <Zydis.h>
#include <safetyhook.hpp>
#include "MemoryMgr.h"
#include "psapi.h"
#include "spoof.h"
#include "structs.hpp"

#include "IniReader.h"

SafetyHookInline whatever;

typedef unsigned __int8 _BYTE;

template<typename T>
SAFETYHOOK_NOINLINE void nop(T address, T waddress = NULL) {
    void* addr;

    if constexpr (std::is_pointer_v<T>) {
        addr = reinterpret_cast<void*>(address);
    }
    else if constexpr (std::is_integral_v<T>) {
        addr = reinterpret_cast<void*>(static_cast<uintptr_t>(address));
    }
    else {
        static_assert(std::is_pointer_v<T> || std::is_integral_v<T>,
            "Address must be a pointer or integral type");
    }

    addr = (void*)REBASE((uintptr_t)addr, (uintptr_t)waddress);

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, addr, 15,
        &instruction, operands))) {
        Memory::VP::Nop(addr, instruction.length);
    }
}


template<typename T>
bool forceJump(T address) {

    void* addr;

    if constexpr (std::is_pointer_v<T>) {
        addr = reinterpret_cast<void*>(address);
    }
    else if constexpr (std::is_integral_v<T>) {
        addr = reinterpret_cast<void*>(static_cast<uintptr_t>(address));
    }
    else {
        static_assert(std::is_pointer_v<T> || std::is_integral_v<T>,
            "Address must be a pointer or integral type");
        return false;
    }

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, addr, 15, &instruction, operands))) {
        return false;
    }

    // Check if it's a conditional jump
    bool isConditionalJump = false;
    uint8_t* instrBytes = static_cast<uint8_t*>(addr);

    switch (instruction.mnemonic) {
    case ZYDIS_MNEMONIC_JB:   // 72 (JC, JNAE, JB)
    case ZYDIS_MNEMONIC_JBE:  // 76 (JNA, JBE)
    case ZYDIS_MNEMONIC_JCXZ: // E3
    case ZYDIS_MNEMONIC_JECXZ:// E3
    case ZYDIS_MNEMONIC_JKNZD:
    case ZYDIS_MNEMONIC_JKZD:
    case ZYDIS_MNEMONIC_JL:   // 7C (JNGE, JL)
    case ZYDIS_MNEMONIC_JLE:  // 7E (JNG, JLE)
    case ZYDIS_MNEMONIC_JNB:  // 73 (JNC, JAE, JNB)
    case ZYDIS_MNEMONIC_JNBE: // 77 (JA, JNBE)
    case ZYDIS_MNEMONIC_JNL:  // 7D (JGE, JNL)
    case ZYDIS_MNEMONIC_JNLE: // 7F (JG, JNLE)
    case ZYDIS_MNEMONIC_JNO:  // 71
    case ZYDIS_MNEMONIC_JNP:  // 7B (JPO, JNP)
    case ZYDIS_MNEMONIC_JNS:  // 79
    case ZYDIS_MNEMONIC_JNZ:  // 75 (JNE, JNZ)
    case ZYDIS_MNEMONIC_JO:   // 70
    case ZYDIS_MNEMONIC_JP:   // 7A (JPE, JP)
    case ZYDIS_MNEMONIC_JRCXZ:// E3
    case ZYDIS_MNEMONIC_JS:   // 78
    case ZYDIS_MNEMONIC_JZ:   // 74 (JE, JZ)
        isConditionalJump = true;
        break;
    default:
        return false; // Not a conditional jump
    }

    if (!isConditionalJump) {
        return false;
    }

    // Determine if it's a short jump (2 bytes) or near jump (6 bytes)
    bool isShortJump = (instruction.length == 2);
    bool isNearJump = (instruction.length == 6 && instrBytes[0] == 0x0F);

    if (isShortJump) {
        // Short conditional jump (7x) -> convert to short unconditional jump (EB)
        // Example: 75 2F (JNZ) -> EB 2F (JMP short)
        Memory::VP::Patch(addr, { 0xEB, instrBytes[1] });
        return true;
    }
    else if (isNearJump) {
        // Near conditional jump (0F 8x) -> convert to near unconditional jump (E9)
        // Example: 0F 85 2F 00 00 00 (JNZ) -> E9 2F 00 00 00 90 (JMP near + NOP)
        Memory::VP::Patch(addr, {
            0xE9,
            instrBytes[2],
            instrBytes[3],
            instrBytes[4],
            instrBytes[5],
            0x90  // NOP to pad to original size
            });
        return true;
    }

    return false;
}

DEFINE_FUNC_CDECL(REBASE(0x142148350,0), Com_IsRunningUILevel, bool)

DEFINE_FUNC_FASTCALL(REBASE(0x1422BCED0, 0x1423A2790), unkchecker_1, char, __int64 a1)

DEFINE_FUNC_FASTCALL(REBASE(0x14133DBF0,0x1413DF170), Dvar_GenerateHash, dvarStrHash_t, const char* string)


DEFINE_FUNC_FASTCALL(REBASE(0x1422C3E00, 0x1423A84F0), Dvar_RegisterFloat, dvar_t*, dvarStrHash_t hash, const char* dvarName, float value, float _min, float _max, unsigned int flags,
    const char* description, bool unk)
void* spoof_t;


int *Com_SessionMode = (int*)REBASE(0x1568ED7F4, 0x158AE65C4);

bool Com_SessionMode_IsMode(eModes mode) {
    return *Com_SessionMode << 28 >> 28 == mode;
}

bool Dvar_IsSessionModeBaseDvar(dvar_t* dvar) {
    return dvar->type == DVAR_TYPE_SESSIONMODE_BASE_DVAR;
}

const dvar_t* register_dvar_float(const char* dvar_name, float value, float min, float max, const unsigned int flags,
        const char* description = "NONE")
{
    const auto hash = Dvar_GenerateHash(dvar_name);
    printf("call before hash 0x%X name %s\n",hash,dvar_name);
    auto* registered_dvar = spoof_call((void*)spoof_t, Dvar_RegisterFloat, (dvarStrHash_t)hash, dvar_name, value, min, max, flags, description, false);
    printf("called after\n");
    if (registered_dvar)
    {
        registered_dvar->debugName = dvar_name;
    }

    return registered_dvar;
}



bool* UI_level_check2 = (bool*)REBASE(0x1568ED91E, 0x1548FD0EF);

__int64* UI_unkchecker_1_input = (__int64*)REBASE(0x1568ED8C8, 0x148DEE3D8);




bool Com_IsRunningUILevel_create() {
    //return false;
    //printf("wtf %p unk %p boolpt %p bool val %d function %p\n", UI_unkchecker_1_input, *UI_unkchecker_1_input, UI_level_check2,*UI_level_check2, unkchecker_1);
    return spoof_call(spoof_t, unkchecker_1,*UI_unkchecker_1_input) && *UI_level_check2;
}



typedef float vec_t;

union vec3_t
{
    struct
    {
        vec_t x;
        vec_t y;
        vec_t z;
    };
    vec_t v[3];
};

//union vec4_t
//{
//    vec_t v[4];
//    struct
//    {
//        vec_t x;
//        vec_t y;
//        vec_t z;
//        vec_t w;
//    };
//    struct
//    {
//        vec_t r;
//        vec_t g;
//        vec_t b;
//        vec_t a;
//    };
//    vec3_t xyz;
//};







union GfxMatrix
{
    float f[4][4];
    vec4_t m[4];
};


struct __declspec(align(4)) GfxViewParms
{
    GfxMatrix viewMatrix;
    GfxMatrix projectionMatrix;
    GfxMatrix projectionMatrixWithZfar;
    GfxMatrix viewProjectionMatrix;
    GfxMatrix viewProjectionMatrixWithZfar;
    GfxMatrix inverseViewProjectionMatrix;
    GfxMatrix projectionMatrixWithoutJitter;
    GfxMatrix viewProjectionMatrixWithoutJitter;
    GfxMatrix inverseViewProjectionMatrixWithoutJitter;
    vec4_t origin;
    vec3_t axis[3];
    float depthHackNearClip;
    float zNear;
    float zFar;
    float tanHalfFovX;
    float tanHalfFovY;
    int bspCellIndex;
    bool isExtraCamera;
};


void* __fastcall InfinitePerspectiveMatrix(float tanHalfFovX, float tanHalfFovY, float zNear, GfxMatrix* a4)
{
    void* result; // rax

    result = memset(a4, 0, sizeof(GfxMatrix));
    a4->f[3][2] = zNear;
    a4->f[2][3] = 1.0;
    a4->f[1][1] = 1.0 / tanHalfFovY;
    a4->f[0][0] = 1.0 / tanHalfFovX;
    return result;
}

void* __fastcall InfinitePerspectiveMatrix(float tanHalfFovX, float tanHalfFovY, float zNear, float (*mtx)[4])
{
    return InfinitePerspectiveMatrix(tanHalfFovX, tanHalfFovY, zNear, (GfxMatrix*)mtx);
}

void set_gunfov(GfxViewParms* view_parms)
{
    // calc gun fov (includes weapon zoom)
    const float gun_fov = 80.f;
    const float w_fov = 0.75f * tanf(gun_fov * 0.01745329238474369f * 0.5f);
    const float tan_half_x = (3440.f / 1440.f) * w_fov;
    const float tan_half_y = w_fov;

    // calc projection matrix
    float proj_mtx[4][4] = {};
    InfinitePerspectiveMatrix(tan_half_x, tan_half_y, view_parms->zNear, proj_mtx);

    // only overwrite the projection matrix ;)
    memcpy(view_parms->projectionMatrix.m, proj_mtx, sizeof(GfxMatrix));
}

SafetyHookInline R_SetViewParmsForScene_og;
__int64 __fastcall R_SetViewParmsForSceneH(__int64 a1, GfxViewParms* a2, bool isExtraCamera) {

    auto result = R_SetViewParmsForScene_og.unsafe_fastcall<__int64>(a1, a2, isExtraCamera);
    if(!isExtraCamera)
    set_gunfov(a2);
    return result;

}

SafetyHookInline Add_Dvarst;

const dvar_t* cg_fovscale;

__int64 Add_Dvars_Hook() {
    auto result = Add_Dvarst.ccall<__int64>();

    cg_fovscale = register_dvar_float("cg_fovscale_m", 1.f, 0.1f, 4.f, 0x4400, "Scales FOV globally");
    if (cg_fovscale) {
        printf("fovscale value is uhh %f\n", cg_fovscale->current.value.value);
    }

    return result;
}

SafetyHookMid cg_fov_midhook;
SafetyHookMid matrix_hack;

float cg_fovscale_override = 1.f;

float get_cg_fovscale() {
    //if (!cg_fovscale)
    //    return cg_fovscale_override;
    //if(cg_fovscale->current.value.value != 1.f)
    //return cg_fovscale->current.value.value;

    return cg_fovscale_override;

}

void wstore_patchrank() {
    return;
    if (!is_wstore)
        return;

    { // 0x1420D5BA0
        nop(0x1416B2C84);
        nop(0x1416B27AA);
        nop(0x1416B4ABB);
        {
            nop(0x1416B23A3);
            Memory::VP::Patch(REBASE(0x1416B23A3), { 0xB0,0x01 }); // mov al, 1
        }

        nop(0x1416B3689);
        nop(0x1416B42B5);
        nop(0x1416B2F92);
        nop(0x1416B2208);
        nop(0x141FA67A7);
        nop(0x141F9A472);

    }

    nop(0x14220E517);
    nop(0x14070A4E8);
    nop(0x1416B0F1E);
    nop(0x1416B0F50);
    nop(0x14220E572);
    nop(0x1414108B5);
    nop(0x141FAB262);
    nop(0x1420E1662);
    nop(0x14230DE5B);
    nop(0x142315B68);
    nop(0x142323602);
    nop(0x142335E84);
    nop(0x1426D5FE1);
    nop(0x141C360B7);
    nop(0x141C363BF);
    nop(0x141FDB312);
    nop(0x1423263BC);



    // mostly steam 0x1420F74A4 ?
    nop(0x140B9A2AD);
    nop(0x1413CEC04);
    nop(0x1413CECED);
    nop(0x141B4DE2D);
    nop(0x141F0D472);
    nop(0x141FDAA83);
    nop(0x1420277ED);
    nop(0x14220E4D7);
    nop(0x14220E517);
    nop(0x142310F9E);
    nop(0x142312739);
    nop(0x1423129AD);
    nop(0x142313D1B);
    nop(0x1423B65F5);
    nop(0x1426D5ACB);

    nop(0x141B42F87);

    nop(0x1416B9D12); // 0x1415E7EBB (in steam this kept calling the function over and over so its been optimized here as there's supposed to be more)

    nop(0x1416B9F5B); // 0x1415E87BB
    nop(0x1416B50EB); // 0x1415EBAC9

    //forceJump(0x14277C208);

}

void Changemin_safearea(SafetyHookContext& ctx) {
    ctx.xmm3.f32[0] = 0.1f;
}

struct screen_info1
{
    _BYTE gap0[12];
    unsigned __int8 unk_bool_1;
    _BYTE gapD[15];
    uint32_t Width;
    uint32_t Height_2;
    unsigned int unsigned_int24;
    uint32_t Height;
};

SafetyHookInline render_setup_x_141DA7B50D;
typedef void*(__fastcall* render_setup_x_141DA7B50T)(screen_info1* screen_info_1);

DEFINE_FUNC_FASTCALL(REBASE(0x14202BB40,0x14202BB40), UI_CoD_ShutdownAndInit,void*,bool frontend)

void* __fastcall render_setup_x_141DA7B50(screen_info1* screen) {

    auto func = render_setup_x_141DA7B50D.original<render_setup_x_141DA7B50T>();
    float* aspect_ratio = (float*)REBASE(0x142FA7CA0, 0x142F87788);
    Memory::VP::Patch(aspect_ratio, (float)screen->Width / (float)screen->Height);

    auto result = spoof_call(spoof_t, func, screen);
    //auto result = render_setup_x_141DA7B50D.unsafe_fastcall<void*>(screen);
    return result;
}

DWORD Start_MixTweaks(LPVOID lpThreadParameter) {

    CIniReader ini;
    cg_fovscale_override = std::clamp(ini.ReadFloat("FOV", "cg_fovscale", 1.f),0.1f,std::numeric_limits<float>::max());

    spoof_t = (void*)REBASE(0x6DB96, 0x1027);


    if (is_wstore && (false == true)) {
        Add_Dvarst = safetyhook::create_inline(REBASE(0x140866AA0, 0x1423ABE50), &Add_Dvars_Hook);

        static auto safearea_min_1 = safetyhook::create_mid(REBASE(0, 0x141493A9E), Changemin_safearea);
        static auto safearea_min_2 = safetyhook::create_mid(REBASE(0, 0x141493AE2), Changemin_safearea);
        static auto safearea_fucky = safetyhook::create_mid(REBASE(0, 0x141493B23), [](SafetyHookContext& ctx) {

            dvar_t* qword_1440E5D20 = *(dvar_t**)REBASE(0, 0x1440E5D20);
            qword_1440E5D20->current.value.value = 0.2f;
            qword_1440E5D20->latched.value.value = 0.2f;
            });
    }
    if (ini.ReadInteger("Fixes", "CustomAspectRatios", 1) != 0) {
        render_setup_x_141DA7B50D = safetyhook::create_inline(REBASE(0x141CBDB90, 0x141DA7B50), &render_setup_x_141DA7B50);
    }
    Sleep(5000);


    is_wstore = Memory::VP::MemEquals(REBASE(0x142F3D078, 0x142F3D078), { 0x73, 0x68, 0x6F, 0x77 });

    //is_wstore = false;


    if (is_wstore) {
        cg_fovscale = register_dvar_float("cg_fovscale_m", 1.f, 0.1f, 4.f, 0x4400, "Scales FOV globally");
        Com_IsRunningUILevel = Com_IsRunningUILevel_create;

        if (!IsDebuggerPresent())
        {
            AllocConsole();
            FILE* fDummy;
            freopen_s(&fDummy, "CONIN$", "r", stdin);
            freopen_s(&fDummy, "CONOUT$", "w", stderr);
            freopen_s(&fDummy, "CONOUT$", "w", stdout);
        }

        if (ini.ReadInteger("Misc", "AllowRank_Modded", 1) != 0) {
            wstore_patchrank();
        }



    }
    //MH_Initialize();
    //MH_CreateHook((void*)REBASE(0x1404D6230, 0x1405AFA30), cg_calc_fov, (LPVOID*)&cg_calc_fov_og);
   // MH_EnableHook(MH_ALL_HOOKS);

    Memory::VP::Patch<char>(REBASE(0x14133D2FE, 0x1413DF336), 0xEB);

    
    //matrix_hack = safetyhook::create_mid(REBASE(0x141CF08F7, 0x141DD5469), [](SafetyHookContext& ctx) {
    //    set_gunfov((GfxViewParms*)(ctx.rdi));
    //    });

    cg_fov_midhook = safetyhook::create_mid(REBASE(0x1404DADAC, 0x1405B7E89), [](SafetyHookContext& ctx) {
        if (!Com_IsRunningUILevel()) {
            float* fov_x = (float*)(ctx.rbp + 0x18);
            float* dx_dz = (float*)(ctx.rbp + 0x28);
            float* dy_dz = (float*)(ctx.rbp + 0x20);
            float scale = 2.f;
            scale = get_cg_fovscale();
            *fov_x *= scale;
            *dx_dz *= scale;
            *dy_dz *= scale;


        }

        });


    return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: {
        CreateThread(NULL, NULL, Start_MixTweaks, NULL, NULL, NULL);
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

