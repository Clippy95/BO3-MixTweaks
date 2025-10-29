// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "MinHook.h"
#include <safetyhook.hpp>
#include "MemoryMgr.h"
#include "psapi.h"
#include "spoof.h"
#include "structs.hpp"
SafetyHookInline whatever;

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







struct GfxMatrix
{
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


void InfinitePerspectiveMatrix(const float tan_half_fov_x, const float tan_half_fov_y, const float z_near, float(*mtx)[4])
{
    // Clear the matrix
    memset(mtx, 0, sizeof(float) * 16);

    mtx[0][0] = 0.99951172f / tan_half_fov_x;
    mtx[1][1] = 0.99951172f / tan_half_fov_y;
    mtx[2][2] = 0.99951172f;
    mtx[2][3] = 1.0f;
    mtx[3][2] = 0.99951171875f * -z_near;
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
    if (!cg_fovscale)
        return cg_fovscale_override;
    if(cg_fovscale->current.value.value != 1.f)
    return cg_fovscale->current.value.value;

    return cg_fovscale_override;

}

DWORD Start_MixTweaks(LPVOID lpThreadParameter) {

    spoof_t = (void*)REBASE(0x6DB96,0x1027);
    if (is_wstore) {
        Add_Dvarst = safetyhook::create_inline(REBASE(0x140866AA0, 0x1423ABE50), &Add_Dvars_Hook);
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

    }
    //MH_Initialize();
    //MH_CreateHook((void*)REBASE(0x1404D6230, 0x1405AFA30), cg_calc_fov, (LPVOID*)&cg_calc_fov_og);
   // MH_EnableHook(MH_ALL_HOOKS);

    Memory::VP::Patch<char>(REBASE(0x14133D2FE, 0x1413DF336), 0xEB);


    //matrix_hack = safetyhook::create_mid(REBASE(0x141DE3759, 0x141DE3759), [](SafetyHookContext& ctx) {
    //    set_gunfov((GfxViewParms*)(ctx.rdi));
    //    });

    cg_fov_midhook = safetyhook::create_mid(REBASE(0x1404DADAC, 0x1405B7E89), [](SafetyHookContext& ctx) {
        if (!Com_IsRunningUILevel()) {
            float* fov_x = (float*)(ctx.rbp + 0x18);
            float* dx_dz = (float*)(ctx.rbp + 0x28);
            float* dy_dz = (float*)(ctx.rbp + 0x20);
            float scale = 2.f;
            scale = 1.55f;
            if (cg_fovscale) {
                scale = cg_fovscale->current.value.value;
            }
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

