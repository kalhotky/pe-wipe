#include "pe.h"

BOOLEAN PE_WipeRichHeader(PVOID pView)
{
    IMAGE_DOS_HEADER* pDosHeader = PE_ImageDosHeader(pView);

    if (!pDosHeader)
    {
        return FALSE;
    }

    BYTE* pBase = (BYTE*)pView + sizeof(*pDosHeader);
    BYTE* pEnd = (BYTE*)pView + pDosHeader->e_lfanew;

    for (BYTE* pCursor = pEnd; pCursor >= pBase; pCursor -= 1)
    {
        if (*((ULONG*)pCursor) == IMAGE_RICH_SIGNATURE)
        {
            BYTE* pRichBase = pCursor - sizeof(ULONG); /* Skip signature */
            BYTE* pRichEnd = pCursor + sizeof(ULONG); /* Move to key */

            while (pRichBase >= pBase)
            {
                ULONG Field = *((ULONG*)pRichBase);
                ULONG Key = *((ULONG*)pRichEnd);

                if ((Field ^ Key) == IMAGE_DANS_SIGNATURE)
                {
                    pRichEnd += sizeof(Key);
                    memset(pRichBase, 0, pRichEnd - pRichBase);
                    return TRUE;
                }

                pRichBase -= sizeof(Field);
            }
        }
    }

    return TRUE;
}

BOOLEAN PE_WipeCOFFHeader(PVOID pView, ULONG HeaderType)
{
    IMAGE_FILE_HEADER* pCOFFHeader;

    if (HeaderType == IMAGE_HEADER_TYPE_32)
    {
        pCOFFHeader = PE_ImageCOFFHeader32(pView);
    }
    else
    {
        pCOFFHeader = PE_ImageCOFFHeader64(pView);
    }

    if (!pCOFFHeader)
    {
        return FALSE;
    }

    pCOFFHeader->TimeDateStamp = 0;
    pCOFFHeader->PointerToSymbolTable = 0; /* Deprecated */
    pCOFFHeader->NumberOfSymbols = 0; /* Deprecated */
    pCOFFHeader->Characteristics &= ~(IMAGE_FILE_LINE_NUMS_STRIPPED | IMAGE_FILE_LOCAL_SYMS_STRIPPED); /* IMAGE_FILE_DEBUG_STRIPPED in PE_WipeDebugDirectory */
    return TRUE;
}

BOOLEAN PE_WipeOptionalHeader(PVOID pView, ULONG HeaderType)
{
    if (HeaderType == IMAGE_HEADER_TYPE_32)
    {
        IMAGE_OPTIONAL_HEADER32* pOptionalHeader = PE_ImageOptionalHeader32(pView);

        if (!pOptionalHeader)
        {
            return FALSE;
        }

        pOptionalHeader->MajorLinkerVersion = 0;
        pOptionalHeader->MinorLinkerVersion = 0;
        pOptionalHeader->SizeOfCode = 0;
        pOptionalHeader->SizeOfInitializedData = 0;
        pOptionalHeader->SizeOfUninitializedData = 0;
        pOptionalHeader->BaseOfCode = 0;
        pOptionalHeader->BaseOfData = 0;
        pOptionalHeader->MajorImageVersion = 0;
        pOptionalHeader->MinorImageVersion = 0;
        pOptionalHeader->CheckSum = 0; /* PE_ComputeCheckSum */
    }
    else
    {
        IMAGE_OPTIONAL_HEADER64* pOptionalHeader = PE_ImageOptionalHeader64(pView);

        if (!pOptionalHeader)
        {
            return FALSE;
        }

        pOptionalHeader->MajorLinkerVersion = 0;
        pOptionalHeader->MinorLinkerVersion = 0;
        pOptionalHeader->SizeOfCode = 0;
        pOptionalHeader->SizeOfInitializedData = 0;
        pOptionalHeader->SizeOfUninitializedData = 0;
        pOptionalHeader->BaseOfCode = 0;
        pOptionalHeader->MajorImageVersion = 0;
        pOptionalHeader->MinorImageVersion = 0;
        pOptionalHeader->CheckSum = 0; /* PE_ComputeCheckSum */
    }
    
    return TRUE;
}

BOOLEAN PE_WipeSectionHeaders(PVOID pView, ULONG HeaderType)
{
    IMAGE_FILE_HEADER* pCOFFHeader;

    if (HeaderType == IMAGE_HEADER_TYPE_32)
    {
        pCOFFHeader = PE_ImageCOFFHeader32(pView);
    }
    else
    {
        pCOFFHeader = PE_ImageCOFFHeader64(pView);
    }

    if (!pCOFFHeader)
    {
        return FALSE;
    }

    if (pCOFFHeader->NumberOfSections)
    {
        IMAGE_SECTION_HEADER* pSectionHeaders = (IMAGE_SECTION_HEADER*)((BYTE*)pCOFFHeader + sizeof(*pCOFFHeader) + pCOFFHeader->SizeOfOptionalHeader);
        
        for (WORD i = 0; i < pCOFFHeader->NumberOfSections; i += 1)
        {
            IMAGE_SECTION_HEADER* pSectionHeader = pSectionHeaders + i;

            memset(pSectionHeader->Name, 0, sizeof(pSectionHeader->Name));
            pSectionHeader->PointerToRelocations = 0; /* Not set for PE images */
            pSectionHeader->PointerToLinenumbers = 0; /* Deprecated */
            pSectionHeader->NumberOfRelocations = 0; /* Not set for PE images */
            pSectionHeader->NumberOfLinenumbers = 0; /* Deprecated */
            pSectionHeader->Characteristics = PE_FixUpSectionFlags(pSectionHeader->Characteristics); /* Add user option */
        }
    }

    return TRUE;
}

BOOLEAN PE_WipeExportDirectory(PVOID pView, ULONG HeaderType)
{
    IMAGE_DATA_DIRECTORY* pDataDirectory;

    if (HeaderType == IMAGE_HEADER_TYPE_32)
    {
        IMAGE_OPTIONAL_HEADER32* pOptionalHeader = PE_ImageOptionalHeader32(pView);

        if (!pOptionalHeader)
        {
            return FALSE;
        }

        if (pOptionalHeader->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT)
        {
            return TRUE; /* No export directory */
        }

        pDataDirectory = &pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    }
    else
    {
        IMAGE_OPTIONAL_HEADER64* pOptionalHeader = PE_ImageOptionalHeader64(pView);

        if (!pOptionalHeader)
        {
            return FALSE;
        }

        if (pOptionalHeader->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT)
        {
            return TRUE; /* No export directory */
        }

        pDataDirectory = &pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    }

    if (pDataDirectory->VirtualAddress && pDataDirectory->Size)
    {
        IMAGE_EXPORT_DIRECTORY* pExportDirectory = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)pView + PE_VirtualToRaw(pView, pDataDirectory->VirtualAddress, HeaderType));

        pExportDirectory->TimeDateStamp = 0;
        pExportDirectory->MajorVersion = 0;
        pExportDirectory->MinorVersion = 0;
    }

    return TRUE;
}

BOOLEAN PE_WipeResourceDirectory(PVOID pView, ULONG HeaderType)
{
    IMAGE_DATA_DIRECTORY* pDataDirectory;

    if (HeaderType == IMAGE_HEADER_TYPE_32)
    {
        IMAGE_OPTIONAL_HEADER32* pOptionalHeader = PE_ImageOptionalHeader32(pView);

        if (!pOptionalHeader)
        {
            return FALSE;
        }

        if (pOptionalHeader->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_RESOURCE)
        {
            return TRUE; /* No resource directory */
        }

        pDataDirectory = &pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    }
    else
    {
        IMAGE_OPTIONAL_HEADER64* pOptionalHeader = PE_ImageOptionalHeader64(pView);

        if (!pOptionalHeader)
        {
            return FALSE;
        }

        if (pOptionalHeader->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_RESOURCE)
        {
            return TRUE; /* No resource directory */
        }

        pDataDirectory = &pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    }

    if (pDataDirectory->VirtualAddress && pDataDirectory->Size)
    {
        IMAGE_RESOURCE_DIRECTORY* pResourceDirectory = (IMAGE_RESOURCE_DIRECTORY*)((BYTE*)pView + PE_VirtualToRaw(pView, pDataDirectory->VirtualAddress, HeaderType));

        pResourceDirectory->TimeDateStamp = 0;
        pResourceDirectory->MajorVersion = 0;
        pResourceDirectory->MinorVersion = 0;
    }

    return TRUE;
}

BOOLEAN PE_WipeDebugDirectory(PVOID pView, ULONG HeaderType)
{
    IMAGE_FILE_HEADER* pCOFFHeader;
    IMAGE_DATA_DIRECTORY* pDataDirectory;

    if (HeaderType == IMAGE_HEADER_TYPE_32)
    {
        pCOFFHeader = PE_ImageCOFFHeader32(pView);

        if (!pCOFFHeader)
        {
            return FALSE;
        }

        IMAGE_OPTIONAL_HEADER32* pOptionalHeader = PE_ImageOptionalHeader32(pView);

        if (!pOptionalHeader)
        {
            return FALSE;
        }

        if (pOptionalHeader->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_DEBUG)
        {
            pCOFFHeader->Characteristics &= ~IMAGE_FILE_DEBUG_STRIPPED;
            return TRUE; /* No debug directory */
        }

        pDataDirectory = &pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    }
    else
    {
        pCOFFHeader = PE_ImageCOFFHeader64(pView);

        if (!pCOFFHeader)
        {
            return FALSE;
        }

        IMAGE_OPTIONAL_HEADER64* pOptionalHeader = PE_ImageOptionalHeader64(pView);

        if (!pOptionalHeader)
        {
            return FALSE;
        }

        if (pOptionalHeader->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_DEBUG)
        {
            pCOFFHeader->Characteristics &= ~IMAGE_FILE_DEBUG_STRIPPED;
            return TRUE; /* No debug directory */
        }

        pDataDirectory = &pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    }

    if (pDataDirectory->VirtualAddress && pDataDirectory->Size)
    {
        ULONG DebugEntryCount = pDataDirectory->Size / sizeof(IMAGE_DEBUG_DIRECTORY);

        if (!DebugEntryCount)
        {
            return FALSE; /* Malformed data */
        }

        IMAGE_DEBUG_DIRECTORY* pDebugDirectories = (IMAGE_DEBUG_DIRECTORY*)((BYTE*)pView + PE_VirtualToRaw(pView, pDataDirectory->VirtualAddress, HeaderType));

        for (ULONG i = 0; i < DebugEntryCount; i += 1)
        {
            /* TODO: Check if debug type structs have some pointers to other data */
            IMAGE_DEBUG_DIRECTORY* pDebugDirectory = pDebugDirectories + i;

            if (pDebugDirectory->PointerToRawData && pDebugDirectory->SizeOfData)
            {
                memset((BYTE*)pView + pDebugDirectory->PointerToRawData, 0, pDebugDirectory->SizeOfData);
            }

            memset(pDebugDirectory, 0, sizeof(*pDebugDirectory));
        }

        pDataDirectory->VirtualAddress = 0;
        pDataDirectory->Size = 0;
    }

    pCOFFHeader->Characteristics &= ~IMAGE_FILE_DEBUG_STRIPPED;
    return TRUE;
}

BOOLEAN PE_WipeLoadConfigDirectory(PVOID pView, ULONG HeaderType)
{
    IMAGE_DATA_DIRECTORY* pDataDirectory;

    if (HeaderType == IMAGE_HEADER_TYPE_32)
    {
        IMAGE_OPTIONAL_HEADER32* pOptionalHeader = PE_ImageOptionalHeader32(pView);

        if (!pOptionalHeader)
        {
            return FALSE;
        }

        if (pOptionalHeader->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)
        {
            return TRUE; /* No load config directory */
        }

        pDataDirectory = &pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];

        if (pDataDirectory->VirtualAddress && pDataDirectory->Size)
        {
            DWORD MinimumSize = RTL_SIZEOF_THROUGH_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, SecurityCookie);
            IMAGE_LOAD_CONFIG_DIRECTORY32* pLoadConfigDirectory = (IMAGE_LOAD_CONFIG_DIRECTORY32*)((BYTE*)pView + PE_VirtualToRaw(pView, pDataDirectory->VirtualAddress, HeaderType));

            if (pDataDirectory->Size >= MinimumSize && pLoadConfigDirectory->Size >= MinimumSize)
            {
                pLoadConfigDirectory->TimeDateStamp = 0;
                pLoadConfigDirectory->MajorVersion = 0;
                pLoadConfigDirectory->MinorVersion = 0;
            }
        }
    }
    else
    {
        IMAGE_OPTIONAL_HEADER64* pOptionalHeader = PE_ImageOptionalHeader64(pView);

        if (!pOptionalHeader)
        {
            return FALSE;
        }

        if (pOptionalHeader->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)
        {
            return TRUE; /* No load config directory */
        }

        pDataDirectory = &pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];

        if (pDataDirectory->VirtualAddress && pDataDirectory->Size)
        {
            DWORD MinimumSize = RTL_SIZEOF_THROUGH_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, SecurityCookie);
            IMAGE_LOAD_CONFIG_DIRECTORY64* pLoadConfigDirectory = (IMAGE_LOAD_CONFIG_DIRECTORY64*)((BYTE*)pView + PE_VirtualToRaw(pView, pDataDirectory->VirtualAddress, HeaderType));

            if (pDataDirectory->Size >= MinimumSize && pLoadConfigDirectory->Size >= MinimumSize)
            {
                pLoadConfigDirectory->TimeDateStamp = 0;
                pLoadConfigDirectory->MajorVersion = 0;
                pLoadConfigDirectory->MinorVersion = 0;
            }
        }
    }

    return TRUE;
}

DWORD PE_ComputeCheckSum(PVOID pView, SIZE_T ViewSize)
{
    /* TODO: Implement */
    return 0;
}

ULONG PE_VirtualToRaw(PVOID pView, ULONG Virtual, ULONG HeaderType)
{
    IMAGE_FILE_HEADER* pCOFFHeader = NULL;

    if (HeaderType == IMAGE_HEADER_TYPE_32)
    {
        pCOFFHeader = PE_ImageCOFFHeader32(pView);
    }
    else
    {
        pCOFFHeader = PE_ImageCOFFHeader64(pView);
    }

    if (!pCOFFHeader || !pCOFFHeader->NumberOfSections)
    {
        return 0;
    }

    IMAGE_SECTION_HEADER* pSectionHeaders = (IMAGE_SECTION_HEADER*)((BYTE*)pCOFFHeader + sizeof(*pCOFFHeader) + pCOFFHeader->SizeOfOptionalHeader);

    for (WORD i = 0; i < pCOFFHeader->NumberOfSections; i += 1)
    {
        IMAGE_SECTION_HEADER* pSectionHeader = pSectionHeaders + i;

        ULONG MinimumVirtual = pSectionHeader->VirtualAddress;
        ULONG MaximumVirtual = pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData; /* Raw size, ignore virtual padding */

        if (Virtual >= MinimumVirtual && Virtual <= MaximumVirtual)
        {
            return pSectionHeader->PointerToRawData + (Virtual - MinimumVirtual);
        }
    }

    return 0;
}

DWORD PE_FixUpSectionFlags(DWORD Characteristics)
{
    /* This is what the loader does anyways */

    if (Characteristics & IMAGE_SCN_CNT_CODE)
    {
        Characteristics &= ~IMAGE_SCN_CNT_CODE;
        Characteristics |= IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
    }

    if (Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
    {
        Characteristics &= ~IMAGE_SCN_CNT_INITIALIZED_DATA;
        Characteristics |= IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    }

    if (Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
    {
        Characteristics &= ~IMAGE_SCN_CNT_UNINITIALIZED_DATA;
        Characteristics |= IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    }

    return Characteristics;
}

ULONG PE_ImageHeaderType(PVOID pView)
{
    IMAGE_DOS_HEADER* pDosHeader = PE_ImageDosHeader(pView);

    if (!pDosHeader)
    {
        return IMAGE_HEADER_TYPE_UNKNOWN;
    }

    BYTE* pNtHeaders = (BYTE*)pView + pDosHeader->e_lfanew;
    IMAGE_FILE_HEADER* pCOFFHeader = (IMAGE_FILE_HEADER*)((BYTE*)pNtHeaders + sizeof(DWORD)); /* Skip Signature field */

    if (pCOFFHeader->Machine == IMAGE_FILE_MACHINE_I386)
    {
        return IMAGE_HEADER_TYPE_32;
    }

    if (pCOFFHeader->Machine == IMAGE_FILE_MACHINE_AMD64 ||
        pCOFFHeader->Machine == IMAGE_FILE_MACHINE_ARM64)
    {
        return IMAGE_HEADER_TYPE_64;
    }

    return IMAGE_HEADER_TYPE_UNKNOWN;
}

IMAGE_DOS_HEADER* PE_ImageDosHeader(PVOID pView)
{
    IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)pView;

    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return NULL;
    }

    return pDosHeader;
}

IMAGE_NT_HEADERS32* PE_ImageNtHeaders32(PVOID pView)
{
    IMAGE_DOS_HEADER* pDosHeader = PE_ImageDosHeader(pView);
    IMAGE_NT_HEADERS32* pNtHeaders = (IMAGE_NT_HEADERS32*)((BYTE*)pView + pDosHeader->e_lfanew);

    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        return NULL;
    }

    return pNtHeaders;
}

IMAGE_NT_HEADERS64* PE_ImageNtHeaders64(PVOID pView)
{
    IMAGE_DOS_HEADER* pDosHeader = PE_ImageDosHeader(pView);
    IMAGE_NT_HEADERS64* pNtHeaders = (IMAGE_NT_HEADERS64*)((BYTE*)pView + pDosHeader->e_lfanew);

    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        return NULL;
    }

    return pNtHeaders;
}

IMAGE_FILE_HEADER* PE_ImageCOFFHeader32(PVOID pView)
{
    IMAGE_NT_HEADERS32* pNtHeaders = PE_ImageNtHeaders32(pView);

    if (!pNtHeaders)
    {
        return NULL;
    }

    if (pNtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
    {
        return NULL;
    }
    
    return &pNtHeaders->FileHeader;
}

IMAGE_FILE_HEADER* PE_ImageCOFFHeader64(PVOID pView)
{
    IMAGE_NT_HEADERS64* pNtHeaders = PE_ImageNtHeaders64(pView);

    if (!pNtHeaders)
    {
        return NULL;
    }

    if (pNtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 &&
        pNtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_ARM64)
    {
        return NULL;
    }

    return &pNtHeaders->FileHeader;
}

IMAGE_OPTIONAL_HEADER32* PE_ImageOptionalHeader32(PVOID pView)
{
    IMAGE_NT_HEADERS32* pNtHeaders = PE_ImageNtHeaders32(pView);

    if (!pNtHeaders)
    {
        return NULL;
    }

    if (pNtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        return NULL;
    }

    return &pNtHeaders->OptionalHeader;
}

IMAGE_OPTIONAL_HEADER64* PE_ImageOptionalHeader64(PVOID pView)
{
    IMAGE_NT_HEADERS64* pNtHeaders = PE_ImageNtHeaders64(pView);

    if (!pNtHeaders)
    {
        return NULL;
    }

    if (pNtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        return NULL;
    }

    return &pNtHeaders->OptionalHeader;
}