#pragma once
#include <phnt/phnt_windows.h>
#include <phnt/phnt.h>

#define IMAGE_RICH_SIGNATURE 0x68636952 /* Rich */
#define IMAGE_DANS_SIGNATURE 0x536E6144 /* DanS */

typedef struct SPEContext
{
    WCHAR* pFileName;

    PVOID pView;
    SIZE_T ViewSize;
    ULONG FileSize;
    ULONG Bits; /* 32/64 */

    union
    {
        ULONG Misc;
        struct
        {
            BOOLEAN Verbose : 1;
            BOOLEAN CheckSum : 1;
        };
    };

    union
    {
        ULONG Options;
        struct
        {
            BOOLEAN RichHeader : 1;
            BOOLEAN COFFHeader : 1;
            BOOLEAN OptionalHeader : 1;
            BOOLEAN SectionHeaders : 1;
            BOOLEAN ExportDirectory : 1;
            BOOLEAN ResourceDirectory : 1;
            BOOLEAN DebugDirectory : 1;
            BOOLEAN LoadConfigDirectory : 1;
        };
    };

    union
    {
        ULONG Filters;
        struct
        {
            BOOLEAN FOptionalHeaderLinkerVersion : 1;
            BOOLEAN FSectionHeadersNames : 1;
            BOOLEAN FSectionHeadersFlags : 1;
            BOOLEAN FTimeStamp : 1;
            BOOLEAN FVersion : 1;
        };
    };
} TPEContext;

/* image.c */

BOOLEAN PE_Wipe(TPEContext* pContext);

BOOLEAN PE_WipeRichHeader(TPEContext* pContext);
BOOLEAN PE_WipeCOFFHeader(TPEContext* pContext);
BOOLEAN PE_WipeOptionalHeader(TPEContext* pContext);
BOOLEAN PE_WipeSectionHeaders(TPEContext* pContext);

BOOLEAN PE_WipeExportDirectory(TPEContext* pContext);
BOOLEAN PE_WipeResourceDirectory(TPEContext* pContext);
BOOLEAN PE_WipeDebugDirectory(TPEContext* pContext);
BOOLEAN PE_WipeLoadConfigDirectory(TPEContext* pContext);

DWORD PE_ComputeCheckSum(TPEContext* pContext);
BOOLEAN PE_GenerateCheckSum(TPEContext* pContext);

ULONG PE_VirtualToRaw(TPEContext* pContext, ULONG Virtual); /* Relative */
DWORD PE_FixUpSectionFlags(DWORD Characteristics);

ULONG PE_ImageBits(TPEContext* pContext);
IMAGE_DOS_HEADER* PE_ImageDosHeader(TPEContext* pContext);
IMAGE_NT_HEADERS32* PE_ImageNtHeaders32(TPEContext* pContext);
IMAGE_NT_HEADERS64* PE_ImageNtHeaders64(TPEContext* pContext);
IMAGE_FILE_HEADER* PE_ImageCOFFHeader32(TPEContext* pContext);
IMAGE_FILE_HEADER* PE_ImageCOFFHeader64(TPEContext* pContext);
IMAGE_OPTIONAL_HEADER32* PE_ImageOptionalHeader32(TPEContext* pContext);
IMAGE_OPTIONAL_HEADER64* PE_ImageOptionalHeader64(TPEContext* pContext);

/* map.c */

NTSTATUS PE_MapView(TPEContext* pContext);
NTSTATUS PE_UnmapView(TPEContext* pContext);