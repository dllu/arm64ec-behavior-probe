#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdint.h>

#ifndef IMAGE_DYNAMIC_RELOCATION_ARM64X
#define IMAGE_DYNAMIC_RELOCATION_ARM64X 6
#endif

#ifndef IMAGE_DVRT_ARM64X_FIXUP_TYPE_ZEROFILL
#define IMAGE_DVRT_ARM64X_FIXUP_TYPE_ZEROFILL 0
#define IMAGE_DVRT_ARM64X_FIXUP_TYPE_VALUE    1
#define IMAGE_DVRT_ARM64X_FIXUP_TYPE_DELTA    2
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0)
#endif

typedef LONG NTSTATUS;
typedef NTSTATUS (WINAPI *NtReadFile_t)(HANDLE,HANDLE,PIO_APC_ROUTINE,void*,IO_STATUS_BLOCK*,void*,ULONG,LARGE_INTEGER*,ULONG*);

struct parsed_image
{
    BYTE *base;
    size_t size;
    IMAGE_NT_HEADERS64 *nt;
    IMAGE_SECTION_HEADER *sections;
};

static NtReadFile_t pNtReadFile;

static BYTE *file_range(BYTE *base, size_t file_size, size_t offset, size_t size)
{
    if (offset > file_size || size > file_size - offset) return NULL;
    return base + offset;
}

static BOOL rva_to_raw(const struct parsed_image *image, DWORD rva, size_t size, size_t *raw)
{
    WORD i;

    if (rva < image->nt->OptionalHeader.SizeOfHeaders)
    {
        if (size > image->nt->OptionalHeader.SizeOfHeaders - rva) return FALSE;
        *raw = rva;
        return TRUE;
    }

    for (i = 0; i < image->nt->FileHeader.NumberOfSections; ++i)
    {
        const IMAGE_SECTION_HEADER *section = &image->sections[i];
        DWORD section_rva = section->VirtualAddress;
        DWORD section_size = section->SizeOfRawData;

        if (rva >= section_rva && rva - section_rva <= section_size &&
            size <= section_size - (rva - section_rva))
        {
            *raw = section->PointerToRawData + rva - section_rva;
            return TRUE;
        }
    }
    return FALSE;
}

static BYTE *raw_rva(const struct parsed_image *image, DWORD rva, size_t size)
{
    size_t raw;

    if (!rva_to_raw(image, rva, size, &raw)) return NULL;
    return file_range(image->base, image->size, raw, size);
}

static BOOL parse_image(BYTE *base, size_t file_size, struct parsed_image *image)
{
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS64 *nt;
    IMAGE_SECTION_HEADER *sections;
    size_t section_offset, section_size;

    if (!(dos = (IMAGE_DOS_HEADER *)file_range(base, file_size, 0, sizeof(*dos))) ||
        dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0)
        return FALSE;

    if (!(nt = (IMAGE_NT_HEADERS64 *)file_range(base, file_size, dos->e_lfanew, sizeof(*nt))) ||
        nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)
        return FALSE;

    section_offset = (BYTE *)IMAGE_FIRST_SECTION(nt) - base;
    section_size = nt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    if (!(sections = (IMAGE_SECTION_HEADER *)file_range(base, file_size, section_offset, section_size)))
        return FALSE;

    image->base = base;
    image->size = file_size;
    image->nt = nt;
    image->sections = sections;
    return TRUE;
}

static void dump_bytes(const char *label, const BYTE *ptr, size_t size)
{
    size_t i;

    printf("%s", label);
    for (i = 0; i < size; ++i) printf(" %02x", ptr[i]);
    printf("\n");
}

static unsigned int apply_arm64x_relocations(BYTE *fixed, const struct parsed_image *image,
                                             const IMAGE_BASE_RELOCATION *reloc, size_t size,
                                             size_t *first_change)
{
    const BYTE *reloc_bytes = (const BYTE *)reloc;
    const BYTE *reloc_end = reloc_bytes + size;
    unsigned int changed = 0;

    while ((const BYTE *)(reloc + 1) <= reloc_end && reloc->SizeOfBlock >= sizeof(*reloc) &&
           reloc->SizeOfBlock <= (size_t)(reloc_end - (const BYTE *)reloc))
    {
        const USHORT *rel = (const USHORT *)(reloc + 1);
        const USHORT *rel_end = (const USHORT *)((const BYTE *)reloc + reloc->SizeOfBlock);

        while (rel < rel_end && *rel)
        {
            USHORT offset = *rel & 0xfff;
            USHORT type = (*rel >> 12) & 3;
            USHORT arg = *rel >> 14;
            DWORD rva = reloc->VirtualAddress + offset;
            size_t raw, fixup_size;
            BYTE *target;
            int val;

            rel++;
            switch (type)
            {
            case IMAGE_DVRT_ARM64X_FIXUP_TYPE_ZEROFILL:
                fixup_size = 1u << arg;
                if (rva_to_raw(image, rva, fixup_size, &raw) &&
                    (target = file_range(fixed, image->size, raw, fixup_size)))
                {
                    if (!changed) *first_change = raw;
                    memset(target, 0, fixup_size);
                    changed++;
                }
                break;
            case IMAGE_DVRT_ARM64X_FIXUP_TYPE_VALUE:
                fixup_size = 1u << arg;
                if ((const BYTE *)rel + fixup_size > (const BYTE *)rel_end) return changed;
                if (rva_to_raw(image, rva, fixup_size, &raw) &&
                    (target = file_range(fixed, image->size, raw, fixup_size)))
                {
                    if (!changed) *first_change = raw;
                    memcpy(target, rel, fixup_size);
                    changed++;
                }
                rel += fixup_size / sizeof(USHORT);
                break;
            case IMAGE_DVRT_ARM64X_FIXUP_TYPE_DELTA:
                fixup_size = sizeof(int);
                if (rel >= rel_end) return changed;
                val = (unsigned int)*rel++ * ((arg & 2) ? 8 : 4);
                if (arg & 1) val = -val;
                if (rva_to_raw(image, rva, fixup_size, &raw) &&
                    (target = file_range(fixed, image->size, raw, fixup_size)))
                {
                    int old_val;

                    if (!changed) *first_change = raw;
                    memcpy(&old_val, target, sizeof(old_val));
                    old_val += val;
                    memcpy(target, &old_val, sizeof(old_val));
                    changed++;
                }
                break;
            }
        }
        reloc = (const IMAGE_BASE_RELOCATION *)rel_end;
    }
    return changed;
}

static unsigned int apply_arm64x_fixups_for_image(BYTE *fixed, const struct parsed_image *image,
                                                  size_t *first_change)
{
    IMAGE_DATA_DIRECTORY *dir = &image->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    IMAGE_LOAD_CONFIG_DIRECTORY64 *cfg;
    IMAGE_DYNAMIC_RELOCATION_TABLE *table;
    IMAGE_SECTION_HEADER *table_section;
    BYTE *ptr, *end;

    if (!dir->VirtualAddress ||
        dir->Size <= offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, DynamicValueRelocTableSection) ||
        !(cfg = (IMAGE_LOAD_CONFIG_DIRECTORY64 *)raw_rva(image, dir->VirtualAddress,
                 offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, DynamicValueRelocTableSection) + sizeof(cfg->DynamicValueRelocTableSection))) ||
        !cfg->DynamicValueRelocTableSection ||
        cfg->DynamicValueRelocTableSection > image->nt->FileHeader.NumberOfSections)
        return 0;

    table_section = &image->sections[cfg->DynamicValueRelocTableSection - 1];
    if (cfg->DynamicValueRelocTableOffset >= table_section->SizeOfRawData) return 0;

    table = (IMAGE_DYNAMIC_RELOCATION_TABLE *)file_range(image->base, image->size,
            table_section->PointerToRawData + cfg->DynamicValueRelocTableOffset, sizeof(*table));
    if (!table) return 0;

    ptr = file_range(image->base, image->size, (BYTE *)(table + 1) - image->base, table->Size);
    if (!ptr) return 0;
    end = ptr + table->Size;

    switch (table->Version)
    {
    case 1:
        while (ptr < end)
        {
            IMAGE_DYNAMIC_RELOCATION64 *dyn = (IMAGE_DYNAMIC_RELOCATION64 *)ptr;

            if ((size_t)(end - ptr) < sizeof(*dyn) || dyn->BaseRelocSize > (ULONGLONG)(end - ptr - sizeof(*dyn))) break;
            if (dyn->Symbol == IMAGE_DYNAMIC_RELOCATION_ARM64X)
                return apply_arm64x_relocations(fixed, image, (IMAGE_BASE_RELOCATION *)(dyn + 1),
                                                (size_t)dyn->BaseRelocSize, first_change);
            ptr += sizeof(*dyn) + (size_t)dyn->BaseRelocSize;
        }
        break;
    case 2:
        while (ptr < end)
        {
            IMAGE_DYNAMIC_RELOCATION64_V2 *dyn = (IMAGE_DYNAMIC_RELOCATION64_V2 *)ptr;

            if ((size_t)(end - ptr) < sizeof(*dyn) || dyn->HeaderSize < sizeof(*dyn) ||
                dyn->HeaderSize > (ULONGLONG)(end - ptr) ||
                dyn->FixupInfoSize > (ULONGLONG)(end - ptr - dyn->HeaderSize))
                break;
            if (dyn->Symbol == IMAGE_DYNAMIC_RELOCATION_ARM64X)
                return apply_arm64x_relocations(fixed, image, (IMAGE_BASE_RELOCATION *)(ptr + dyn->HeaderSize),
                                                (size_t)dyn->FixupInfoSize, first_change);
            ptr += (size_t)dyn->HeaderSize + (size_t)dyn->FixupInfoSize;
        }
        break;
    }
    return 0;
}

static size_t count_differences(const BYTE *a, const BYTE *b, size_t size)
{
    size_t i, count = 0;

    for (i = 0; i < size; ++i) count += a[i] != b[i];
    return count;
}

static BOOL ntread_whole_file(const WCHAR *path, BYTE *buffer, size_t size, size_t *read_size)
{
    HANDLE file = CreateFileW(path, GENERIC_READ | SYNCHRONIZE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    IO_STATUS_BLOCK io;
    LARGE_INTEGER offset;
    NTSTATUS status;

    if (file == INVALID_HANDLE_VALUE)
    {
        wprintf(L"  open for NtReadFile failed gle=%lu\n", GetLastError());
        return FALSE;
    }

    memset(&io, 0, sizeof(io));
    offset.QuadPart = 0;
    status = pNtReadFile(file, NULL, NULL, NULL, &io, buffer, (ULONG)size, &offset, NULL);
    CloseHandle(file);
    *read_size = io.Information;
    if (status != STATUS_SUCCESS)
    {
        printf("  NtReadFile status=%08lx information=%llu\n", status, (unsigned long long)io.Information);
        return FALSE;
    }
    return TRUE;
}

static BOOL probe_file(const WCHAR *path)
{
    HANDLE file, mapping;
    LARGE_INTEGER file_size;
    BYTE *raw, *fixed, *read_buffer;
    struct parsed_image image;
    size_t first_change = 0, read_size = 0;
    unsigned int fixups;
    size_t raw_vs_fixed, read_vs_raw, read_vs_fixed;
    BOOL useful = FALSE;

    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return FALSE;
    if (!GetFileSizeEx(file, &file_size) || file_size.QuadPart <= 0 || file_size.QuadPart > 64 * 1024 * 1024)
    {
        CloseHandle(file);
        return FALSE;
    }

    mapping = CreateFileMappingW(file, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!mapping)
    {
        CloseHandle(file);
        return FALSE;
    }
    raw = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    if (!raw)
    {
        CloseHandle(mapping);
        CloseHandle(file);
        return FALSE;
    }

    if (!parse_image(raw, (size_t)file_size.QuadPart, &image)) goto done;
    fixed = HeapAlloc(GetProcessHeap(), 0, (size_t)file_size.QuadPart);
    read_buffer = HeapAlloc(GetProcessHeap(), 0, (size_t)file_size.QuadPart);
    if (!fixed || !read_buffer)
    {
        if (fixed) HeapFree(GetProcessHeap(), 0, fixed);
        if (read_buffer) HeapFree(GetProcessHeap(), 0, read_buffer);
        goto done;
    }

    memcpy(fixed, raw, (size_t)file_size.QuadPart);
    fixups = apply_arm64x_fixups_for_image(fixed, &image, &first_change);
    raw_vs_fixed = count_differences(raw, fixed, (size_t)file_size.QuadPart);
    if (!fixups || !raw_vs_fixed)
    {
        HeapFree(GetProcessHeap(), 0, fixed);
        HeapFree(GetProcessHeap(), 0, read_buffer);
        goto done;
    }

    useful = TRUE;
    wprintf(L"CANDIDATE %ls size=%llu machine=%04x fixup_records=%u changed_bytes=%llu first_change=%llu\n",
            path, (unsigned long long)file_size.QuadPart, image.nt->FileHeader.Machine, fixups,
            (unsigned long long)raw_vs_fixed, (unsigned long long)first_change);

    if (ntread_whole_file(path, read_buffer, (size_t)file_size.QuadPart, &read_size) &&
        read_size == (size_t)file_size.QuadPart)
    {
        read_vs_raw = count_differences(read_buffer, raw, read_size);
        read_vs_fixed = count_differences(read_buffer, fixed, read_size);
        printf("  RESULT read_vs_raw=%llu read_vs_fixed=%llu raw_vs_fixed=%llu\n",
               (unsigned long long)read_vs_raw, (unsigned long long)read_vs_fixed,
               (unsigned long long)raw_vs_fixed);
        dump_bytes("  raw  ", raw + first_change, min((size_t)16, (size_t)file_size.QuadPart - first_change));
        dump_bytes("  fixed", fixed + first_change, min((size_t)16, (size_t)file_size.QuadPart - first_change));
        dump_bytes("  read ", read_buffer + first_change, min((size_t)16, read_size - first_change));
        if (!read_vs_fixed) printf("  OUTCOME NtReadFile returned ARM64X-fixed bytes\n");
        else if (!read_vs_raw) printf("  OUTCOME NtReadFile returned raw file bytes\n");
        else printf("  OUTCOME NtReadFile returned bytes matching neither raw nor computed fixed image\n");
    }
    else
    {
        printf("  RESULT NtReadFile could not read the full file, read_size=%llu\n",
               (unsigned long long)read_size);
    }

    HeapFree(GetProcessHeap(), 0, fixed);
    HeapFree(GetProcessHeap(), 0, read_buffer);

done:
    UnmapViewOfFile(raw);
    CloseHandle(mapping);
    CloseHandle(file);
    return useful;
}

int wmain(void)
{
    WCHAR pattern[MAX_PATH], path[MAX_PATH], system_dir[MAX_PATH];
    WIN32_FIND_DATAW data;
    HANDLE find;
    unsigned int candidates = 0;

    setvbuf(stdout, NULL, _IONBF, 0);
    pNtReadFile = (NtReadFile_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtReadFile");
    if (!pNtReadFile)
    {
        printf("missing NtReadFile\n");
        return 2;
    }

    GetSystemDirectoryW(system_dir, MAX_PATH);
    wprintf(L"SystemDirectory=%ls\n", system_dir);
    swprintf(pattern, MAX_PATH, L"%ls\\*.dll", system_dir);

    find = FindFirstFileW(pattern, &data);
    if (find == INVALID_HANDLE_VALUE)
    {
        printf("FindFirstFileW failed gle=%lu\n", GetLastError());
        return 3;
    }

    do
    {
        swprintf(path, MAX_PATH, L"%ls\\%ls", system_dir, data.cFileName);
        if (probe_file(path)) candidates++;
    } while (FindNextFileW(find, &data));
    FindClose(find);

    printf("SUMMARY candidates_with_arm64x_fixups=%u\n", candidates);
    return candidates ? 0 : 4;
}
