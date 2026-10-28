// capa - coarse behaviour categories for imported API names (see capa.h)

#include "capa.h"

#include <stdio.h>
#include <string.h>

static const char *const cat_names[CAPA_NCAT] = {
    "process-injection", "process-access", "anti-debug", "keyboard-input",
    "network", "crypto", "privilege-token",
};

static const char *const cat_explain[CAPA_NCAT] = {
    "write/run code inside another process",
    "open, list or read other processes",
    "detect or hinder a debugger",
    "observe keystrokes / install input hooks",
    "talk to the network or download files",
    "encrypt, decrypt or protect data",
    "change privileges or act as another user",
};

struct capa_entry { const char *api; int cat; };

// Names without the A/W suffix; capa_category strips it before matching.
static const struct capa_entry table[] = {
    // 0 process-injection
    { "VirtualAllocEx", 0 }, { "VirtualProtectEx", 0 }, { "WriteProcessMemory", 0 },
    { "CreateRemoteThread", 0 }, { "CreateRemoteThreadEx", 0 }, { "NtCreateThreadEx", 0 },
    { "RtlCreateUserThread", 0 }, { "QueueUserAPC", 0 }, { "NtQueueApcThread", 0 },
    { "SetThreadContext", 0 }, { "NtMapViewOfSection", 0 }, { "NtUnmapViewOfSection", 0 },
    { "ZwUnmapViewOfSection", 0 }, { "NtWriteVirtualMemory", 0 },
    // 1 process-access
    { "OpenProcess", 1 }, { "ReadProcessMemory", 1 }, { "NtReadVirtualMemory", 1 },
    { "CreateToolhelp32Snapshot", 1 }, { "Process32First", 1 }, { "Process32Next", 1 },
    { "EnumProcesses", 1 }, { "EnumProcessModules", 1 }, { "MiniDumpWriteDump", 1 },
    // 2 anti-debug
    { "IsDebuggerPresent", 2 }, { "CheckRemoteDebuggerPresent", 2 },
    { "NtQueryInformationProcess", 2 }, { "NtSetInformationThread", 2 },
    { "OutputDebugString", 2 },
    // 3 keyboard-input
    { "SetWindowsHookEx", 3 }, { "GetAsyncKeyState", 3 }, { "GetKeyboardState", 3 },
    { "RegisterRawInputDevices", 3 }, { "GetRawInputData", 3 },
    // 4 network
    { "WSAStartup", 4 }, { "connect", 4 }, { "InternetOpen", 4 }, { "InternetOpenUrl", 4 },
    { "InternetReadFile", 4 }, { "HttpSendRequest", 4 }, { "WinHttpOpen", 4 },
    { "WinHttpSendRequest", 4 }, { "URLDownloadToFile", 4 }, { "WSASocket", 4 },
    // 5 crypto
    { "CryptEncrypt", 5 }, { "CryptDecrypt", 5 }, { "CryptGenKey", 5 },
    { "BCryptEncrypt", 5 }, { "BCryptDecrypt", 5 }, { "BCryptGenerateSymmetricKey", 5 },
    { "CryptProtectData", 5 }, { "CryptUnprotectData", 5 },
    // 6 privilege-token
    { "AdjustTokenPrivileges", 6 }, { "ImpersonateLoggedOnUser", 6 }, { "DuplicateTokenEx", 6 },
    { "SetThreadToken", 6 }, { "CreateProcessWithToken", 6 }, { "CreateProcessAsUser", 6 },
    { "LogonUser", 6 },
};

const char *capa_name(int i)
{
    return (i >= 0 && i < CAPA_NCAT) ? cat_names[i] : "";
}

const char *capa_explain(const char *category)
{
    for (int i = 0; i < CAPA_NCAT; i++) {
        if (strcmp(category, cat_names[i]) == 0) {
            return cat_explain[i];
        }
    }
    return "";
}

static int lookup(const char *api)
{
    char base[96];
    size_t n = strlen(api);
    if (n == 0 || n >= sizeof base) {
        return -1;
    }
    for (size_t i = 0; i < sizeof table / sizeof table[0]; i++) {
        if (strcmp(api, table[i].api) == 0) {
            return table[i].cat;
        }
    }
    // Retry without an A/W suffix (CreateProcessAsUserW -> CreateProcessAsUser).
    if (api[n - 1] == 'A' || api[n - 1] == 'W') {
        memcpy(base, api, n - 1);
        base[n - 1] = '\0';
        for (size_t i = 0; i < sizeof table / sizeof table[0]; i++) {
            if (strcmp(base, table[i].api) == 0) {
                return table[i].cat;
            }
        }
    }
    return -1;
}

const char *capa_category(const char *api)
{
    int c = lookup(api);
    return c < 0 ? NULL : cat_names[c];
}

void capa_init(capa_sum *s)
{
    memset(s, 0, sizeof *s);
}

void capa_add(capa_sum *s, const char *api)
{
    int c = lookup(api);
    if (c < 0) {
        return;
    }
    if (s->count[c] < CAPA_EXAMPLES) {
        snprintf(s->example[c][s->count[c]], sizeof s->example[c][0], "%s", api);
    }
    s->count[c]++;
}

const char *capa_packer_section(const char *name)
{
    static const struct { const char *sec, *packer; } k[] = {
        { "UPX0", "UPX" }, { "UPX1", "UPX" }, { "UPX2", "UPX" }, { "UPX!", "UPX" },
        { ".aspack", "ASPack" }, { ".adata", "ASPack" },
        { ".MPRESS1", "MPRESS" }, { ".MPRESS2", "MPRESS" },
        { ".vmp0", "VMProtect" }, { ".vmp1", "VMProtect" }, { ".vmp2", "VMProtect" },
        { ".themida", "Themida" }, { ".winlice", "WinLicense" },
        { "PEC2", "PECompact" }, { "pec1", "PECompact" },
        { ".petite", "Petite" }, { ".nsp0", "NsPack" }, { ".nsp1", "NsPack" },
        { ".nsp2", "NsPack" }, { ".enigma1", "Enigma" }, { ".enigma2", "Enigma" },
        { ".rlpack", "RLPack" }, { "MEW", "MEW" }, { ".packed", "unknown packer" },
    };
    for (size_t i = 0; i < sizeof k / sizeof k[0]; i++) {
        if (strcmp(name, k[i].sec) == 0) {
            return k[i].packer;
        }
    }
    return NULL;
}
