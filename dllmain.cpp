#include <windows.h>
#include <cstdio>
#include <cstdarg>
#include "safteyhook.hpp"

// ==============================
// Known Addresses (adjust from IDA)
// ==============================
static constexpr uintptr_t kAddr_sub_509CF0 = 0x00509CF0;
static constexpr uintptr_t kAddr_sub_50A340 = 0x0050A340;
static constexpr uintptr_t kAddr_sub_41CB60 = 0x0041CB60;
static constexpr uintptr_t kAddr_sub_4E5210 = 0x004E5210;
static constexpr uintptr_t kAddr_sub_509B40 = 0x00509B40;
static constexpr uintptr_t kAddr_sub_46DB40 = 0x0046DB40;
static constexpr uintptr_t kAddr_sub_509DC0 = 0x00509DC0;
static constexpr uintptr_t kAddr_sub_50CBBF = 0x0050CBBF;
static constexpr uintptr_t kAddr_sub_46B440 = 0x0046B440; // try_server_connect
static constexpr uintptr_t kAddr_sub_4E5450 = 0x004E5450;
SafetyHookInline g_Sub4E5450_hook{};



// ==============================
// Hook handles
// ==============================
SafetyHookInline g_Sub509CF0_hook{};
SafetyHookInline g_Sub50A340_hook{};
SafetyHookInline g_Sub41CB60_hook{};
SafetyHookInline g_Sub4E5210_hook{};
SafetyHookInline g_Sub509B40_hook{};
SafetyHookInline g_Sub46DB40_hook{};
SafetyHookInline g_Sub509DC0_hook{};
SafetyHookInline g_Sub50CBBF_hook{};
SafetyHookInline g_Sub46B440_hook{};

// ==============================
// Memory dump helper
// ==============================
void dump_bytes(void* ptr, size_t len)
{
    if (!ptr || IsBadReadPtr(ptr, len))
        return;

    unsigned char* p = reinterpret_cast<unsigned char*>(ptr);
    for (size_t i = 0; i < len; ++i)
    {
        printf("%02X ", p[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    if (len % 16 != 0)
        printf("\n");
}

// ==============================
// Hook: sub_46B440 (try_server_connect)
// ==============================
// Forward declaration for trampoline
extern SafetyHookInline g_Sub46B440_hook;

// Safe handler implementation
// Forward declaration
extern SafetyHookInline g_Sub46B440_hook;

// Log + safe call handler
void log_server_connect(int port, const char* host, int a3)
{
    FILE* f = fopen("wulfram_engine_debug.log", "a");

    if (!host || IsBadReadPtr(host, 1))
        host = "<invalid>";

    printf("[HOOK sub_46B440] Connecting to host='%s' port=%d a3=0x%X\n", host, port, a3);
    if (f)
    {
        fprintf(f, "[HOOK sub_46B440] Connecting to host='%s' port=%d a3=0x%X\n", host, port, a3);
        fclose(f);
    }
}



FILE* __cdecl hooked_sub_4E5450(char* file, int line, const char* fmt, ...)
{
    if (!fmt || IsBadReadPtr(fmt, 1))
        return g_Sub4E5450_hook.call<FILE*>(file, line, fmt);

    char formatted[1024] = { 0 };
    va_list args;
    va_start(args, fmt);
    vsnprintf(formatted, sizeof(formatted), fmt, args);
    va_end(args);

    // Log to console
    printf("[HOOK sub_4E5450] %s:%d -> %s\n",
        file ? file : "(null)", line, formatted);

    // Append to file
    FILE* f = fopen("wulfram_engine_debug.log", "a");
    if (f)
    {
        fprintf(f, "[sub_4E5450] %s:%d -> %s\n",
            file ? file : "(null)", line, formatted);
        fclose(f);
    }

    FILE* result = nullptr;
    __try
    {
        // Call the original safely
        result = g_Sub4E5450_hook.call<FILE*>(file, line, fmt);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        printf("[HOOK sub_4E5450] ⚠️ Exception calling original!\n");
    }

    return result;
}




// ==============================
// Hook: sub_41CB60 (simple debug print)
// ==============================
void __cdecl hooked_sub_41CB60(const char* fmt, ...)
{
    if (!fmt || IsBadReadPtr(fmt, 1))
        return;

    char buf[512] = { 0 };
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    printf("[GAME LOG] %s\n", buf);
    g_Sub41CB60_hook.call<void>(fmt);
}

// ==============================
// Hook: sub_509B40 (packet handler registration)
// ==============================
int __fastcall hooked_sub_509B40(void* _this, void*, unsigned char packetId, void* handler)
{
    printf("[HOOK sub_509B40] Register handler ID=%u (0x%02X) -> 0x%p\n",
        packetId, packetId, handler);

    if (packetId == 34) printf("   ↳ LOGIN_STATUS (ID 34)\n");
    else if (packetId == 35) printf("   ↳ MOTD (ID 35)\n");
    else if (packetId == 36) printf("   ↳ BEHAVIOR (ID 36)\n");

    return g_Sub509B40_hook.thiscall<int>(_this, packetId, handler);
}

// ==============================
// Hook: sub_50CBBF (engine debug logger, ASCII-safe)
// ==============================
void* __cdecl hooked_sub_50CBBF(const char* fmt, ...)
{
    if (!fmt || IsBadReadPtr(fmt, 1))
        return g_Sub50CBBF_hook.call<void*>(fmt);

    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(fmt, &mbi, sizeof(mbi)))
    {
        if (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
        {
            printf("[HOOK sub_50CBBF] <skipped executable ptr @ %p>\n", fmt);
            return g_Sub50CBBF_hook.call<void*>(fmt);
        }
    }

    bool likely_text = true;
    int printable = 0, total = 0;
    for (int i = 0; i < 128 && fmt[i]; ++i)
    {
        unsigned char c = (unsigned char)fmt[i];
        if (c >= 32 && c <= 126)
            printable++;
        total++;
    }
    if (total > 0 && printable < total * 0.85)
        likely_text = false;

    char buf[1024] = { 0 };

    if (likely_text)
    {
        va_list args;
        va_start(args, fmt);
        vsnprintf(buf, sizeof(buf), fmt, args);
        va_end(args);
        printf("[HOOK sub_50CBBF] %s\n", buf);
    }
    else
    {
        printf("[HOOK sub_50CBBF] <binary data @ %p>\n", fmt);
        const unsigned char* p = reinterpret_cast<const unsigned char*>(fmt);
        for (int i = 0; i < 64; ++i)
        {
            if (IsBadReadPtr(p + i, 1)) break;
            printf("%02X ", p[i]);
            if ((i + 1) % 16 == 0) printf("\n");
        }
        printf("\n");
    }

    return g_Sub50CBBF_hook.call<void*>(fmt);
}

// ==============================
// Hook: sub_4E5210 (ASCII-safe debug printer)
// ==============================
int __cdecl hooked_sub_4E5210(const char* fmt, ...)
{
    if (!fmt || IsBadReadPtr(fmt, 1))
        return g_Sub4E5210_hook.call<int>(fmt);

    char buf[1024] = { 0 };
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    uintptr_t ret = (uintptr_t)_ReturnAddress();
    printf("[HOOK sub_4E5210] %s\n", buf);
    printf("              (Called from 0x%08X)\n", (unsigned)ret);

    return g_Sub4E5210_hook.call<int>(fmt);
}

// ==============================
// Hook: sub_509CF0
// ==============================
int __fastcall hooked_sub_509CF0(void* _this, void*, const char* a2, int a3, int a4, int a5)
{
    printf("[HOOK sub_509CF0] this=%p name=%s a3=%d a4=%d a5=0x%X\n",
        _this, a2 ? a2 : "(null)", a3, a4, a5);

    int result = g_Sub509CF0_hook.thiscall<int>(_this, a2, a3, a4, a5);
    printf("[HOOK sub_509CF0] result=0x%X\n", result);
    return result;
}

// ==============================
// Hook: sub_50A340
// ==============================
int __fastcall hooked_sub_50A340(void* _this, void*, int packet_ptr)
{
    printf("[HOOK sub_50A340] Sending packet ptr=0x%X\n", packet_ptr);
    dump_bytes((void*)packet_ptr, 256);
    return g_Sub50A340_hook.thiscall<int>(_this, packet_ptr);
}

// ==============================
// Hook: LOGIN_STATUS
// ==============================
char __cdecl hooked_sub_46DB40(int a1, int a2, int a3)
{
    printf("[HOOK LOGIN_STATUS] a1=0x%X a2=0x%X a3=0x%X\n", a1, a2, a3);
    dump_bytes((void*)a3, 32);
    return g_Sub46DB40_hook.call<char>(a1, a2, a3);
}

// ==============================
// Hook: sub_509DC0 (__stdcall)
// ==============================
int __stdcall hooked_sub_509DC0(int a1, int a2)
{
    printf("[HOOK sub_509DC0] called this=0x%X conn=0x%X\n", a1, a2);

    if (a1 && !IsBadReadPtr((void*)a1, 0x20))
    {
        DWORD* obj = (DWORD*)a1;
        printf("  this[6]=0x%X\n", obj[6]);
        if (obj[6])
            dump_bytes((void*)obj[6], 32);
    }

    int result = 0;
    __try
    {
        result = g_Sub509DC0_hook.call<int>(a1, a2);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        printf("[HOOK sub_509DC0] ⚠️ Exception inside original — recovered.\n");
    }
    return result;
}

// ==============================
// DLL Entry Point
// ==============================
BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        AllocConsole();
        SetConsoleTitleW(L"Wulfram2 Packet Logger");
        FILE* fp;
        freopen_s(&fp, "CONOUT$", "w", stdout);
        freopen_s(&fp, "CONOUT$", "w", stderr);
        printf("Starting Wulfram2 Packet Logger...\n");

        g_Sub509CF0_hook = safetyhook::create_inline((void*)kAddr_sub_509CF0, (void*)&hooked_sub_509CF0);
        g_Sub50A340_hook = safetyhook::create_inline((void*)kAddr_sub_50A340, (void*)&hooked_sub_50A340);
        g_Sub41CB60_hook = safetyhook::create_inline((void*)kAddr_sub_41CB60, (void*)&hooked_sub_41CB60);
        g_Sub4E5210_hook = safetyhook::create_inline((void*)kAddr_sub_4E5210, (void*)&hooked_sub_4E5210);
        g_Sub509B40_hook = safetyhook::create_inline((void*)kAddr_sub_509B40, (void*)&hooked_sub_509B40);
        g_Sub46DB40_hook = safetyhook::create_inline((void*)kAddr_sub_46DB40, (void*)&hooked_sub_46DB40);
        g_Sub509DC0_hook = safetyhook::create_inline((void*)kAddr_sub_509DC0, (void*)&hooked_sub_509DC0);
        g_Sub50CBBF_hook = safetyhook::create_inline((void*)kAddr_sub_50CBBF, (void*)&hooked_sub_50CBBF);
        g_Sub4E5450_hook = safetyhook::create_inline(
            (void*)kAddr_sub_4E5450,
            (void*)&hooked_sub_4E5450
        );
        

        printf("[HOOKS INSTALLED]\n");
        printf("  sub_509CF0  @ 0x%08X\n", (unsigned)kAddr_sub_509CF0);
        printf("  sub_50A340  @ 0x%08X\n", (unsigned)kAddr_sub_50A340);
        printf("  sub_41CB60  @ 0x%08X\n", (unsigned)kAddr_sub_41CB60);
        printf("  sub_4E5210  @ 0x%08X (DEBUG PRINT)\n", (unsigned)kAddr_sub_4E5210);
        printf("  sub_509B40  @ 0x%08X\n", (unsigned)kAddr_sub_509B40);
        printf("  sub_46DB40  @ 0x%08X (LOGIN_STATUS)\n", (unsigned)kAddr_sub_46DB40);
        printf("  sub_509DC0  @ 0x%08X (INCOMING DISPATCH)\n", (unsigned)kAddr_sub_509DC0);
        printf("  sub_50CBBF  @ 0x%08X (DEBUG LOGGER)\n", (unsigned)kAddr_sub_50CBBF);
        printf("  sub_4E5450  @ 0x%08X (ERROR LOGGER)\n", (unsigned)kAddr_sub_4E5450);
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        g_Sub509CF0_hook.reset();
        g_Sub50A340_hook.reset();
        g_Sub41CB60_hook.reset();
        g_Sub4E5210_hook.reset();
        g_Sub509B40_hook.reset();
        g_Sub46DB40_hook.reset();
        g_Sub509DC0_hook.reset();
        g_Sub50CBBF_hook.reset();
        g_Sub46B440_hook.reset(); 
        g_Sub4E5450_hook.reset();
    }
    return TRUE;
}
