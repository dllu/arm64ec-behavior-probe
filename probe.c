#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

typedef LONG NTSTATUS;
typedef NTSTATUS (WINAPI *NtMapViewOfSection_t)(HANDLE,HANDLE,PVOID*,ULONG_PTR,SIZE_T,LARGE_INTEGER*,SIZE_T*,DWORD,ULONG,ULONG);
typedef NTSTATUS (WINAPI *NtUnmapViewOfSection_t)(HANDLE,PVOID);
typedef PVOID (WINAPI *RtlFindExportedRoutineByName_t)(HMODULE,const char*);
typedef BOOL (WINAPI *IsWow64Process2_t)(HANDLE,USHORT*,USHORT*);

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0)
#endif

#ifndef ViewShare
#define ViewShare 1
#endif

static NtMapViewOfSection_t pNtMapViewOfSection;
static NtUnmapViewOfSection_t pNtUnmapViewOfSection;
static RtlFindExportedRoutineByName_t pRtlFindExportedRoutineByName;

static DWORD hook_code[] =
{
    0x58000048, /* ldr x8, 1f */
    0xd61f0100, /* br x8 */
    0, 0        /* 1: .quad ptr */
};

static const DWORD log_params_code[] =
{
    0x10008009, /* adr x9, .+0x1000 */
    0xf940012a, /* ldr x10, [x9] */
    0xa8810540, /* stp x0, x1, [x10], #0x10 */
    0xa8810d42, /* stp x2, x3, [x10], #0x10 */
    0xa8811544, /* stp x4, x5, [x10], #0x10 */
    0xa8811d46, /* stp x6, x7, [x10], #0x10 */
    0xf900012a, /* str x10, [x9] */
    0xf9400520, /* ldr x0, [x9, #0x8] */
    0xd65f03c0, /* ret */
};

struct hook
{
    const char *label;
    const char *names[4];
    BYTE *target;
    BYTE old_code[sizeof(hook_code)];
};

static void *log_code;
static uint64_t *results;

static void reset_results(void)
{
    memset(results + 1, 0xcc, 0x1000 - sizeof(*results));
    results[0] = (uint64_t)(uintptr_t)(results + 2);
    results[1] = STATUS_SUCCESS;
}

static void dump_results(const char *hook, const char *scenario)
{
    uint64_t *regs = results + 2;
    unsigned int i, count = (unsigned int)((results[0] - (uint64_t)(uintptr_t)regs) / (8 * sizeof(*regs)));

    printf("BEGIN hook=%s scenario=%s count=%u\n", hook, scenario, count);
    for (i = 0; i < count; ++i, regs += 8)
    {
        printf("  event[%u]: x0=%016llx x1=%016llx x2=%016llx x3=%016llx "
               "x4=%016llx x5=%016llx x6=%016llx x7=%016llx\n",
               i, (unsigned long long)regs[0], (unsigned long long)regs[1],
               (unsigned long long)regs[2], (unsigned long long)regs[3],
               (unsigned long long)regs[4], (unsigned long long)regs[5],
               (unsigned long long)regs[6], (unsigned long long)regs[7]);
    }
    printf("END hook=%s scenario=%s\n", hook, scenario);
    reset_results();
}

static BYTE *resolve_export_target(HMODULE module, const char *name)
{
    static const BYTE fast_forward[] = { 0x48, 0x8b, 0xc4, 0x48, 0x89, 0x58, 0x20, 0x55, 0x5d, 0xe9 };
    BYTE *ptr = NULL;
    LONG rel;

    if (pRtlFindExportedRoutineByName)
        ptr = (BYTE *)pRtlFindExportedRoutineByName(module, name);
    if (!ptr)
        ptr = (BYTE *)GetProcAddress(module, name);
    if (!ptr) return NULL;

    printf("export %s at %p", name, ptr);
    if (!memcmp(ptr, fast_forward, sizeof(fast_forward)))
    {
        ptr += sizeof(fast_forward);
        rel = *(LONG *)ptr;
        ptr += sizeof(rel) + rel;
        printf(" fast-forward target %p", ptr);
    }
    printf("\n");
    return ptr;
}

static void print_module_if_relevant(const MODULEENTRY32W *entry)
{
    WCHAR lower[MAX_PATH];
    size_t i;

    for (i = 0; i < MAX_PATH && entry->szModule[i]; ++i)
    {
        WCHAR ch = entry->szModule[i];
        lower[i] = (ch >= L'A' && ch <= L'Z') ? ch + (L'a' - L'A') : ch;
    }
    lower[i] = 0;

    if (wcsstr(lower, L"jit") || wcsstr(lower, L"wow") ||
        wcsstr(lower, L"chpe") || wcsstr(lower, L"ntdll"))
    {
        printf("module %-24ls base=%p path=%ls\n",
               entry->szModule, entry->modBaseAddr, entry->szExePath);
    }
}

static void dump_process_architecture(HMODULE ntdll)
{
    IsWow64Process2_t pIsWow64Process2 =
        (IsWow64Process2_t)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2");
    SYSTEM_INFO native_info;
    USHORT process_machine = 0, native_machine = 0;

    GetNativeSystemInfo(&native_info);
    printf("GetNativeSystemInfo processor_architecture=%u processors=%lu page_size=%lu\n",
           native_info.wProcessorArchitecture, native_info.dwNumberOfProcessors,
           native_info.dwPageSize);

    if (pIsWow64Process2 &&
        pIsWow64Process2(GetCurrentProcess(), &process_machine, &native_machine))
    {
        printf("IsWow64Process2 process_machine=0x%04x native_machine=0x%04x\n",
               process_machine, native_machine);
    }
    else
    {
        printf("IsWow64Process2 unavailable/failed gle=%lu\n", GetLastError());
    }

    pRtlFindExportedRoutineByName =
        (RtlFindExportedRoutineByName_t)GetProcAddress(ntdll, "RtlFindExportedRoutineByName");
    printf("RtlFindExportedRoutineByName=%p\n", pRtlFindExportedRoutineByName);
}

static void dump_relevant_modules(void)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                               GetCurrentProcessId());
    MODULEENTRY32W entry;

    if (snapshot == INVALID_HANDLE_VALUE)
    {
        printf("CreateToolhelp32Snapshot failed gle=%lu\n", GetLastError());
        return;
    }

    entry.dwSize = sizeof(entry);
    if (Module32FirstW(snapshot, &entry))
    {
        do
        {
            print_module_if_relevant(&entry);
            entry.dwSize = sizeof(entry);
        } while (Module32NextW(snapshot, &entry));
    }
    else
    {
        printf("Module32FirstW failed gle=%lu\n", GetLastError());
    }

    CloseHandle(snapshot);
}

static HMODULE find_or_load_xtajit(void)
{
    const WCHAR *names[] =
    {
        L"xtajit64se.dll",
        L"C:\\Windows\\System32\\xtajit64se.dll",
        L"xtajit64.dll",
        L"C:\\Windows\\System32\\xtajit64.dll",
        L"xtajitse.dll",
        L"C:\\Windows\\System32\\xtajitse.dll",
        L"xtajit.dll",
        L"C:\\Windows\\System32\\xtajit.dll",
        NULL
    };
    const WCHAR *diagnostic_names[] =
    {
        L"wow64cpu.dll",
        L"C:\\Windows\\System32\\wow64cpu.dll",
        NULL
    };
    HMODULE module;
    unsigned int i;

    for (i = 0; names[i]; ++i)
    {
        module = GetModuleHandleW(names[i]);
        printf("GetModuleHandleW(%ls)=%p gle=%lu\n", names[i], module, GetLastError());
        if (module) return module;
    }

    for (i = 0; names[i]; ++i)
    {
        SetLastError(0);
        module = LoadLibraryW(names[i]);
        printf("LoadLibraryW(%ls)=%p gle=%lu\n", names[i], module, GetLastError());
        if (module) return module;
    }

    for (i = 0; diagnostic_names[i]; ++i)
    {
        SetLastError(0);
        module = GetModuleHandleW(diagnostic_names[i]);
        printf("GetModuleHandleW(%ls)=%p gle=%lu\n", diagnostic_names[i], module, GetLastError());
        SetLastError(0);
        module = LoadLibraryW(diagnostic_names[i]);
        printf("LoadLibraryW(%ls)=%p gle=%lu\n", diagnostic_names[i], module, GetLastError());
        if (module) FreeLibrary(module);
    }

    return NULL;
}

static BOOL install_hook(HMODULE module, struct hook *hook)
{
    DWORD old_prot;
    unsigned int i;

    hook->target = NULL;
    for (i = 0; i < 4 && hook->names[i]; ++i)
    {
        hook->target = resolve_export_target(module, hook->names[i]);
        if (hook->target) break;
    }

    if (!hook->target)
    {
        printf("SKIP hook=%s no export found\n", hook->label);
        return FALSE;
    }

    memcpy(hook->old_code, hook->target, sizeof(hook->old_code));
    if (!VirtualProtect(hook->target, sizeof(hook_code), PAGE_EXECUTE_READWRITE, &old_prot))
    {
        printf("FAIL hook=%s VirtualProtect target gle=%lu\n", hook->label, GetLastError());
        return FALSE;
    }
    if (!WriteProcessMemory(GetCurrentProcess(), hook->target, hook_code, sizeof(hook_code), NULL))
    {
        printf("FAIL hook=%s WriteProcessMemory gle=%lu\n", hook->label, GetLastError());
        return FALSE;
    }
    FlushInstructionCache(GetCurrentProcess(), hook->target, sizeof(hook_code));
    VirtualProtect(hook->target, sizeof(hook_code), old_prot, &old_prot);
    return TRUE;
}

static void restore_hook(struct hook *hook)
{
    DWORD old_prot;

    if (!hook->target) return;
    VirtualProtect(hook->target, sizeof(hook->old_code), PAGE_EXECUTE_READWRITE, &old_prot);
    WriteProcessMemory(GetCurrentProcess(), hook->target, hook->old_code, sizeof(hook->old_code), NULL);
    FlushInstructionCache(GetCurrentProcess(), hook->target, sizeof(hook->old_code));
    VirtualProtect(hook->target, sizeof(hook->old_code), old_prot, &old_prot);
    hook->target = NULL;
}

static void scenario_virtualprotect(void)
{
    DWORD old_prot;
    void *addr = VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    printf("  virtualprotect addr=%p\n", addr);
    if (addr) VirtualProtect(addr, 0x1000, PAGE_EXECUTE_READ, &old_prot);
    if (addr) VirtualFree(addr, 0, MEM_RELEASE);
}

static void scenario_pagefile_map_execute(void)
{
    HANDLE mapping;
    void *addr = NULL;
    SIZE_T size = 0x1000;
    NTSTATUS status;

    mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, 0x1000, NULL);
    printf("  pagefile mapping=%p gle=%lu\n", mapping, GetLastError());
    if (!mapping) return;

    status = pNtMapViewOfSection(mapping, GetCurrentProcess(), &addr, 0, 0, NULL, &size,
                                 ViewShare, 0, PAGE_EXECUTE_READWRITE);
    printf("  pagefile NtMapViewOfSection status=%08lx addr=%p size=%llu\n",
           status, addr, (unsigned long long)size);
    if (status == STATUS_SUCCESS) pNtUnmapViewOfSection(GetCurrentProcess(), addr);
    CloseHandle(mapping);
}

static void scenario_file_map_execute(void)
{
    WCHAR path[MAX_PATH], dir[MAX_PATH];
    HANDLE file, mapping;
    DWORD written;
    BYTE page[0x1000] = {0};
    void *addr = NULL;
    SIZE_T size = 0x1000;
    NTSTATUS status;

    GetTempPathW(MAX_PATH, dir);
    GetTempFileNameW(dir, L"ecb", 0, path);
    file = CreateFileW(path, GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE, 0, NULL,
                       CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    printf("  file path=%ls file=%p gle=%lu\n", path, file, GetLastError());
    if (file == INVALID_HANDLE_VALUE) return;
    WriteFile(file, page, sizeof(page), &written, NULL);

    mapping = CreateFileMappingW(file, NULL, PAGE_EXECUTE_READWRITE, 0, sizeof(page), NULL);
    printf("  file mapping=%p gle=%lu\n", mapping, GetLastError());
    if (mapping)
    {
        status = pNtMapViewOfSection(mapping, GetCurrentProcess(), &addr, 0, 0, NULL, &size,
                                     ViewShare, 0, PAGE_EXECUTE_READWRITE);
        printf("  file NtMapViewOfSection status=%08lx addr=%p size=%llu\n",
               status, addr, (unsigned long long)size);
        if (status == STATUS_SUCCESS) pNtUnmapViewOfSection(GetCurrentProcess(), addr);
        CloseHandle(mapping);
    }
    CloseHandle(file);
}

static void scenario_image_map(BOOL loader_marker)
{
    WCHAR path[MAX_PATH];
    HANDLE file, mapping;
    void *addr = NULL;
    SIZE_T size = 0;
    NTSTATUS status;
    PVOID old_marker = NULL;

    GetSystemDirectoryW(path, MAX_PATH);
    wcscat_s(path, MAX_PATH, L"\\version.dll");
    file = CreateFileW(path, GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ, NULL,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    printf("  image path=%ls file=%p gle=%lu loader_marker=%u\n",
           path, file, GetLastError(), loader_marker);
    if (file == INVALID_HANDLE_VALUE) return;

    mapping = CreateFileMappingW(file, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    printf("  image mapping=%p gle=%lu\n", mapping, GetLastError());
    if (!mapping)
    {
        CloseHandle(file);
        return;
    }

    if (loader_marker)
    {
        old_marker = NtCurrentTeb()->ArbitraryUserPointer;
        NtCurrentTeb()->ArbitraryUserPointer = path;
    }
    status = pNtMapViewOfSection(mapping, GetCurrentProcess(), &addr, 0, 0, NULL, &size,
                                 ViewShare, 0, PAGE_READONLY);
    if (loader_marker) NtCurrentTeb()->ArbitraryUserPointer = old_marker;

    printf("  image NtMapViewOfSection status=%08lx addr=%p size=%llu loader_marker=%u\n",
           status, addr, (unsigned long long)size, loader_marker);
    if (status == STATUS_SUCCESS) pNtUnmapViewOfSection(GetCurrentProcess(), addr);
    CloseHandle(mapping);
    CloseHandle(file);
}

static void scenario_remap_same_address(void)
{
    HANDLE mapping;
    void *addr, *map_addr;
    SIZE_T size = 0x1000;
    NTSTATUS status;

    addr = VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    printf("  remap initial addr=%p\n", addr);
    if (!addr) return;
    VirtualFree(addr, 0, MEM_RELEASE);

    mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, 0x1000, NULL);
    printf("  remap mapping=%p gle=%lu\n", mapping, GetLastError());
    if (!mapping) return;

    map_addr = addr;
    status = pNtMapViewOfSection(mapping, GetCurrentProcess(), &map_addr, 0, 0, NULL, &size,
                                 ViewShare, 0, PAGE_EXECUTE_READWRITE);
    printf("  remap NtMapViewOfSection status=%08lx requested=%p addr=%p size=%llu\n",
           status, addr, map_addr, (unsigned long long)size);
    if (status == STATUS_SUCCESS) pNtUnmapViewOfSection(GetCurrentProcess(), map_addr);
    CloseHandle(mapping);
}

static void run_scenarios_for_hook(HMODULE module, struct hook *hook)
{
    if (!install_hook(module, hook)) return;

    reset_results();
    scenario_virtualprotect();
    dump_results(hook->label, "VirtualProtect RW_to_RX");

    scenario_pagefile_map_execute();
    dump_results(hook->label, "NtMapViewOfSection pagefile PAGE_EXECUTE_READWRITE");

    scenario_file_map_execute();
    dump_results(hook->label, "NtMapViewOfSection file PAGE_EXECUTE_READWRITE");

    scenario_image_map(FALSE);
    dump_results(hook->label, "NtMapViewOfSection SEC_IMAGE direct");

    scenario_image_map(TRUE);
    dump_results(hook->label, "NtMapViewOfSection SEC_IMAGE loader_marker");

    scenario_remap_same_address();
    dump_results(hook->label, "VirtualFree then NtMapViewOfSection same_address");

    restore_hook(hook);
}

int main(void)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    HMODULE xtajit;
    struct hook hooks[] =
    {
        { "memory_protect", { "NotifyMemoryProtect", "BTCpuNotifyMemoryProtect", NULL } },
        { "map_view", { "NotifyMapViewOfSection", "BTCpuNotifyMapViewOfSection", NULL } },
        { "unmap_view", { "NotifyUnmapViewOfSection", "BTCpuNotifyUnmapViewOfSection", NULL } },
    };
    unsigned int i;

    setvbuf(stdout, NULL, _IONBF, 0);

    printf("PROCESSOR_ARCHITECTURE=%s PROCESSOR_ARCHITEW6432=%s\n",
           getenv("PROCESSOR_ARCHITECTURE") ? getenv("PROCESSOR_ARCHITECTURE") : "",
           getenv("PROCESSOR_ARCHITEW6432") ? getenv("PROCESSOR_ARCHITEW6432") : "");
    printf("ntdll=%p\n", ntdll);
    if (ntdll) dump_process_architecture(ntdll);
    dump_relevant_modules();

    xtajit = find_or_load_xtajit();
    printf("selected xtajit module=%p\n", xtajit);

    if (!ntdll || !xtajit)
    {
        printf("FAIL missing ntdll or xTAJIT module; this runner/process cannot expose the callback surface\n");
        return 2;
    }

    pNtMapViewOfSection = (NtMapViewOfSection_t)GetProcAddress(ntdll, "NtMapViewOfSection");
    pNtUnmapViewOfSection = (NtUnmapViewOfSection_t)GetProcAddress(ntdll, "NtUnmapViewOfSection");
    if (!pNtMapViewOfSection || !pNtUnmapViewOfSection)
    {
        printf("FAIL missing NtMapViewOfSection/NtUnmapViewOfSection\n");
        return 3;
    }

    log_code = VirtualAlloc(NULL, 0x2000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!log_code)
    {
        printf("FAIL VirtualAlloc log_code gle=%lu\n", GetLastError());
        return 4;
    }
    memcpy(log_code, log_params_code, sizeof(log_params_code));
    *(void **)&hook_code[2] = log_code;
    results = (uint64_t *)((BYTE *)log_code + 0x1000);
    reset_results();
    {
        DWORD old_prot;
        VirtualProtect(log_code, 0x1000, PAGE_EXECUTE_READ, &old_prot);
        FlushInstructionCache(GetCurrentProcess(), log_code, 0x1000);
    }

    for (i = 0; i < sizeof(hooks) / sizeof(hooks[0]); ++i)
        run_scenarios_for_hook(xtajit, &hooks[i]);

    VirtualFree(log_code, 0, MEM_RELEASE);
    return 0;
}
