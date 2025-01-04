#include "pe.h"
#include "util.h"

BOOLEAN PE_Wipe(TPEContext* pContext)
{
    pContext->Bits = PE_ImageBits(pContext);

    if (pContext->Bits == 0)
    {
        U_Msg("[x] Invalid PE format :(\n");
        return FALSE;
    }

    if (pContext->Verbose)
    {
        U_Msg("[>] PE bitness: %lu\n", pContext->Bits);
    }

    if (!PE_WipeRichHeader(pContext))
    {
        U_Msg("[!] Could't wipe %s\n", "Rich header");
    }

    if (!PE_WipeCOFFHeader(pContext))
    {
        U_Msg("[!] Could't wipe %s\n", "File header");
    }

    if (!PE_WipeOptionalHeader(pContext))
    {
        U_Msg("[!] Could't wipe %s\n", "Optional header");
    }

    if (!PE_WipeSectionHeaders(pContext))
    {
        U_Msg("[!] Could't wipe %s\n", "Section headers");
    }

    if (!PE_WipeExportDirectory(pContext))
    {
        U_Msg("[!] Could't wipe %s\n", "Export directory");
    }

    if (!PE_WipeResourceDirectory(pContext))
    {
        U_Msg("[!] Could't wipe %s\n", "Resource directory");
    }

    if (!PE_WipeDebugDirectory(pContext))
    {
        U_Msg("[!] Could't wipe %s\n", "Debug directory");
    }

    if (!PE_WipeLoadConfigDirectory(pContext))
    {
        U_Msg("[!] Could't wipe %s\n", "LoadConfig directory");
    }

    /*
    * TODO: Fix checksum logic, for some fucking
    *       reason it's offset by -0xC00
    */

    if (!PE_GenerateCheckSum(pContext))
    {
        U_Msg("[!] Could't generate PE checksum\n");
    }

    U_Msg("[+] PE %ls has been stripped!\n", pContext->pFileName);
    return TRUE;
}

BOOLEAN PE_WipeRichHeader(TPEContext* pContext)
{
    if (!pContext->FRichHeader)
    {
        return TRUE;
    }

    IMAGE_DOS_HEADER* pDosHeader = PE_ImageDosHeader(pContext);

    if (!pDosHeader)
    {
        return FALSE;
    }

    BYTE* pBase = (BYTE*)pContext->pView + sizeof(*pDosHeader);
    BYTE* pEnd = (BYTE*)pContext->pView + pDosHeader->e_lfanew;

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
                    ULONG RichSize = (ULONG)(pRichEnd - pRichBase);

                    if (pContext->Verbose)
                    {
                        U_Msg("[>] Wiping %s...\n", "Rich header");
                        U_Msg("    Data base:   0x%zX\n", (SIZE_T)pRichBase);
                        U_Msg("    Data size:   0x%lX\n", RichSize);
                        U_Msg("    Key:         0x%lX\n", Key);
                    }

                    memset(pRichBase, 0, RichSize);

                    if (pContext->Verbose)
                    {
                        U_Msg("[>] %s done...\n", "Rich header");
                    }

                    return TRUE;
                }

                pRichBase -= sizeof(Field);
            }
        }
    }

    return TRUE;
}

BOOLEAN PE_WipeCOFFHeader(TPEContext* pContext)
{
    if (!pContext->FCOFFHeader &&
        !pContext->FCOFFHeaderTimeStamp)
    {
        return TRUE;
    }

    IMAGE_FILE_HEADER* pCOFFHeader;

    if (pContext->Bits == 32)
    {
        pCOFFHeader = PE_ImageCOFFHeader32(pContext);
    }
    else
    {
        pCOFFHeader = PE_ImageCOFFHeader64(pContext);
    }

    if (!pCOFFHeader)
    {
        return FALSE;
    }

    if (pContext->Verbose)
    {
        U_Msg("[>] Wiping %s...\n", "COFF header");
    }

    if (pContext->FCOFFHeader ||
        pContext->FCOFFHeaderTimeStamp)
    {
        pCOFFHeader->TimeDateStamp = 0;
    }

    if (pContext->FCOFFHeader)
    {
        pCOFFHeader->PointerToSymbolTable = 0; /* Deprecated */
        pCOFFHeader->NumberOfSymbols = 0; /* Deprecated */
        pCOFFHeader->Characteristics &= ~(IMAGE_FILE_LINE_NUMS_STRIPPED | IMAGE_FILE_LOCAL_SYMS_STRIPPED); /* IMAGE_FILE_DEBUG_STRIPPED in PE_WipeDebugDirectory */
    }

    if (pContext->Verbose)
    {
        U_Msg("[>] %s done...\n", "COFF header");
    }

    return TRUE;
}

BOOLEAN PE_WipeOptionalHeader(TPEContext* pContext)
{
    if (!pContext->FOptionalHeader &&
        !pContext->FOptionalHeaderLinkerVersion &&
        !pContext->FOptionalHeaderVersion)
    {
        return TRUE;
    }

    if (pContext->Bits == 32)
    {
        IMAGE_OPTIONAL_HEADER32* pOptionalHeader = PE_ImageOptionalHeader32(pContext);

        if (!pOptionalHeader)
        {
            return FALSE;
        }

        if (pContext->Verbose)
        {
            U_Msg("[>] Wiping %s...\n", "Optional header");
        }

        if (pContext->FOptionalHeader ||
            pContext->FOptionalHeaderLinkerVersion)
        {
            pOptionalHeader->MajorLinkerVersion = 0;
            pOptionalHeader->MinorLinkerVersion = 0;
        }

        if (pContext->FOptionalHeader)
        {
            pOptionalHeader->SizeOfCode = 0;
            pOptionalHeader->SizeOfInitializedData = 0;
            pOptionalHeader->SizeOfUninitializedData = 0;
            pOptionalHeader->BaseOfCode = 0;
            pOptionalHeader->BaseOfData = 0;
        }

        if (pContext->FOptionalHeader ||
            pContext->FOptionalHeaderVersion)
        {
            pOptionalHeader->MajorImageVersion = 0;
            pOptionalHeader->MinorImageVersion = 0;
        }

        pOptionalHeader->CheckSum = 0;

        if (pContext->Verbose)
        {
            U_Msg("[>] %s done...\n", "Optional header");
        }
    }
    else
    {
        IMAGE_OPTIONAL_HEADER64* pOptionalHeader = PE_ImageOptionalHeader64(pContext);

        if (!pOptionalHeader)
        {
            return FALSE;
        }

        if (pContext->Verbose)
        {
            U_Msg("[>] Wiping %s...\n", "Optional header");
        }

        if (pContext->FOptionalHeader ||
            pContext->FOptionalHeaderLinkerVersion)
        {
            pOptionalHeader->MajorLinkerVersion = 0;
            pOptionalHeader->MinorLinkerVersion = 0;
        }

        if (pContext->FOptionalHeader)
        {
            pOptionalHeader->SizeOfCode = 0;
            pOptionalHeader->SizeOfInitializedData = 0;
            pOptionalHeader->SizeOfUninitializedData = 0;
            pOptionalHeader->BaseOfCode = 0;
        }

        if (pContext->FOptionalHeader ||
            pContext->FOptionalHeaderVersion)
        {
            pOptionalHeader->MajorImageVersion = 0;
            pOptionalHeader->MinorImageVersion = 0;
        }

        pOptionalHeader->CheckSum = 0;

        if (pContext->Verbose)
        {
            U_Msg("[>] %s done...\n", "Optional header");
        }
    }
    
    return TRUE;
}

BOOLEAN PE_WipeSectionHeaders(TPEContext* pContext)
{
    if (!pContext->FSectionHeaders &&
        !pContext->FSectionHeadersNames &&
        !pContext->FSectionHeadersFlags)
    {
        return TRUE;
    }

    IMAGE_FILE_HEADER* pCOFFHeader;

    if (pContext->Bits == 32)
    {
        pCOFFHeader = PE_ImageCOFFHeader32(pContext);
    }
    else
    {
        pCOFFHeader = PE_ImageCOFFHeader64(pContext);
    }

    if (!pCOFFHeader)
    {
        return FALSE;
    }

    if (pCOFFHeader->NumberOfSections)
    {
        IMAGE_SECTION_HEADER* pSectionHeaders = (IMAGE_SECTION_HEADER*)((BYTE*)pCOFFHeader + sizeof(*pCOFFHeader) + pCOFFHeader->SizeOfOptionalHeader);
        
        if (pContext->Verbose)
        {
            U_Msg("[>] Wiping %s...\n", "Section headers");
        }

        for (WORD i = 0; i < pCOFFHeader->NumberOfSections; i += 1)
        {
            IMAGE_SECTION_HEADER* pSectionHeader = pSectionHeaders + i;

            if (pContext->Verbose)
            {
                CHAR SectionName[IMAGE_SIZEOF_SHORT_NAME + 1];
                memcpy(SectionName, pSectionHeader->Name, sizeof(pSectionHeader->Name));
                SectionName[IMAGE_SIZEOF_SHORT_NAME] = '\0';

                U_Msg("    Section header #%hu\n", i + 1);

                if (SectionName[0] != '\0')
                {
                    U_Msg("        Name: %s\n", SectionName);
                }
            }

            if (pContext->FSectionHeaders ||
                pContext->FSectionHeadersNames)
            {
                memset(pSectionHeader->Name, 0, sizeof(pSectionHeader->Name));
            }

            if (pContext->FSectionHeaders)
            {
                pSectionHeader->PointerToRelocations = 0; /* Not set for PE images */
                pSectionHeader->PointerToLinenumbers = 0; /* Deprecated */
                pSectionHeader->NumberOfRelocations = 0; /* Not set for PE images */
                pSectionHeader->NumberOfLinenumbers = 0; /* Deprecated */
            }

            if (pContext->FSectionHeaders ||
                pContext->FSectionHeadersFlags)
            {
                pSectionHeader->Characteristics = PE_FixUpSectionFlags(pSectionHeader->Characteristics);
            }
        }

        if (pContext->Verbose)
        {
            U_Msg("[>] %s done...\n", "Section headers");
        }
    }

    return TRUE;
}

BOOLEAN PE_WipeExportDirectory(TPEContext* pContext)
{
    if (!pContext->FExportDirectory &&
        !pContext->FExportDirectoryTimeStamp &&
        !pContext->FExportDirectoryVersion)
    {
        return TRUE;
    }

    IMAGE_DATA_DIRECTORY* pDataDirectory;

    if (pContext->Bits == 32)
    {
        IMAGE_OPTIONAL_HEADER32* pOptionalHeader = PE_ImageOptionalHeader32(pContext);

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
        IMAGE_OPTIONAL_HEADER64* pOptionalHeader = PE_ImageOptionalHeader64(pContext);

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
        IMAGE_EXPORT_DIRECTORY* pExportDirectory = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)pContext->pView + PE_VirtualToRaw(pContext, pDataDirectory->VirtualAddress));

        if (pContext->Verbose)
        {
            U_Msg("[>] Wiping %s...\n", "Export directory");
        }

        if (pContext->FExportDirectory ||
            pContext->FExportDirectoryTimeStamp)
        {
            pExportDirectory->TimeDateStamp = 0;
        }

        if (pContext->FExportDirectory ||
            pContext->FExportDirectoryVersion)
        {
            pExportDirectory->MajorVersion = 0;
            pExportDirectory->MinorVersion = 0;
        }

        if (pContext->Verbose)
        {
            U_Msg("[>] %s done...\n", "Export directory");
        }
    }

    return TRUE;
}

BOOLEAN PE_WipeResourceDirectory(TPEContext* pContext)
{
    if (!pContext->FResourceDirectory &&
        !pContext->FResourceDirectoryTimeStamp &&
        !pContext->FResourceDirectoryVersion)
    {
        return TRUE;
    }

    IMAGE_DATA_DIRECTORY* pDataDirectory;

    if (pContext->Bits == 32)
    {
        IMAGE_OPTIONAL_HEADER32* pOptionalHeader = PE_ImageOptionalHeader32(pContext);

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
        IMAGE_OPTIONAL_HEADER64* pOptionalHeader = PE_ImageOptionalHeader64(pContext);

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
        IMAGE_RESOURCE_DIRECTORY* pResourceDirectory = (IMAGE_RESOURCE_DIRECTORY*)((BYTE*)pContext->pView + PE_VirtualToRaw(pContext, pDataDirectory->VirtualAddress));

        if (pContext->Verbose)
        {
            U_Msg("[>] Wiping %s...\n", "Resource directory");
        }

        if (pContext->FResourceDirectory ||
            pContext->FResourceDirectoryTimeStamp)
        {
            pResourceDirectory->TimeDateStamp = 0;
        }

        if (pContext->FResourceDirectory ||
            pContext->FResourceDirectoryVersion)
        {
            pResourceDirectory->MajorVersion = 0;
            pResourceDirectory->MinorVersion = 0;
        }

        if (pContext->Verbose)
        {
            U_Msg("[>] %s done...\n", "Resource directory");
        }
    }

    return TRUE;
}

BOOLEAN PE_WipeDebugDirectory(TPEContext* pContext)
{
    if (!pContext->FDebugDirectory &&
        !pContext->FDebugDirectoryTimeStamp &&
        !pContext->FDebugDirectoryVersion)
    {
        return TRUE;
    }

    IMAGE_FILE_HEADER* pCOFFHeader;
    IMAGE_DATA_DIRECTORY* pDataDirectory;

    if (pContext->Bits == 32)
    {
        pCOFFHeader = PE_ImageCOFFHeader32(pContext);

        if (!pCOFFHeader)
        {
            return FALSE;
        }

        IMAGE_OPTIONAL_HEADER32* pOptionalHeader = PE_ImageOptionalHeader32(pContext);

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
        pCOFFHeader = PE_ImageCOFFHeader64(pContext);

        if (!pCOFFHeader)
        {
            return FALSE;
        }

        IMAGE_OPTIONAL_HEADER64* pOptionalHeader = PE_ImageOptionalHeader64(pContext);

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

        IMAGE_DEBUG_DIRECTORY* pDebugDirectories = (IMAGE_DEBUG_DIRECTORY*)((BYTE*)pContext->pView + PE_VirtualToRaw(pContext, pDataDirectory->VirtualAddress));

        if (pContext->Verbose)
        {
            U_Msg("[>] Wiping %s...\n", "Debug directory");
        }

        for (ULONG i = 0; i < DebugEntryCount; i += 1)
        {
            /* TODO: Check if debug type structs have some pointers to other data */
            IMAGE_DEBUG_DIRECTORY* pDebugDirectory = pDebugDirectories + i;

            if (pContext->Verbose)
            {
                U_Msg("    Debug directory #%lu\n", i + 1);
                U_Msg("        Type: 0x%lX\n", pDebugDirectory->Type);
            }

            if (pContext->FDebugDirectoryTimeStamp) /* Skip pContext->FDebugDirectory */
            {
                pDebugDirectory->TimeDateStamp = 0;
            }

            if (pContext->FDebugDirectoryVersion) /* Skip pContext->FDebugDirectory */
            {
                pDebugDirectory->MajorVersion = 0;
                pDebugDirectory->MinorVersion = 0;
            }

            if (pContext->FDebugDirectory)
            {
                if (pDebugDirectory->PointerToRawData && pDebugDirectory->SizeOfData)
                {
                    BYTE* pDebugData = (BYTE*)pContext->pView + pDebugDirectory->PointerToRawData;

                    if (pContext->Verbose)
                    {
                        U_Msg("            Data base: 0x%zX\n", (SIZE_T)pDebugData);
                        U_Msg("            Data size: 0x%lX\n", pDebugDirectory->SizeOfData);
                    }

                    memset(pDebugData, 0, pDebugDirectory->SizeOfData);
                }

                memset(pDebugDirectory, 0, sizeof(*pDebugDirectory));
            }
        }

        if (pContext->FDebugDirectory)
        {
            pDataDirectory->VirtualAddress = 0;
            pDataDirectory->Size = 0;
        }

        if (pContext->Verbose)
        {
            U_Msg("[>] %s done...\n", "Debug directory");
        }
    }

    pCOFFHeader->Characteristics &= ~IMAGE_FILE_DEBUG_STRIPPED;
    return TRUE;
}

BOOLEAN PE_WipeLoadConfigDirectory(TPEContext* pContext)
{
    if (!pContext->FLoadConfigDirectory &&
        !pContext->FLoadConfigDirectoryTimeStamp &&
        !pContext->FLoadConfigDirectoryVersion)
    {
        return TRUE;
    }

    IMAGE_DATA_DIRECTORY* pDataDirectory;

    if (pContext->Bits == 32)
    {
        IMAGE_OPTIONAL_HEADER32* pOptionalHeader = PE_ImageOptionalHeader32(pContext);

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
            IMAGE_LOAD_CONFIG_DIRECTORY32* pLoadConfigDirectory = (IMAGE_LOAD_CONFIG_DIRECTORY32*)((BYTE*)pContext->pView + PE_VirtualToRaw(pContext, pDataDirectory->VirtualAddress));

            if (pDataDirectory->Size >= MinimumSize && pLoadConfigDirectory->Size >= MinimumSize)
            {
                if (pContext->Verbose)
                {
                    U_Msg("[>] Wiping %s...\n", "LoadConfig directory");
                }

                if (pContext->FLoadConfigDirectory ||
                    pContext->FLoadConfigDirectoryTimeStamp)
                {
                    pLoadConfigDirectory->TimeDateStamp = 0;
                }

                if (pContext->FLoadConfigDirectory ||
                    pContext->FLoadConfigDirectoryVersion)
                {
                    pLoadConfigDirectory->MajorVersion = 0;
                    pLoadConfigDirectory->MinorVersion = 0;
                }

                if (pContext->Verbose)
                {
                    U_Msg("[>] %s done...\n", "LoadConfig directory");
                }
            }
        }
    }
    else
    {
        IMAGE_OPTIONAL_HEADER64* pOptionalHeader = PE_ImageOptionalHeader64(pContext);

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
            IMAGE_LOAD_CONFIG_DIRECTORY64* pLoadConfigDirectory = (IMAGE_LOAD_CONFIG_DIRECTORY64*)((BYTE*)pContext->pView + PE_VirtualToRaw(pContext, pDataDirectory->VirtualAddress));

            if (pDataDirectory->Size >= MinimumSize && pLoadConfigDirectory->Size >= MinimumSize)
            {
                if (pContext->Verbose)
                {
                    U_Msg("[>] Wiping %s...\n", "LoadConfig directory");
                }

                if (pContext->FLoadConfigDirectory ||
                    pContext->FLoadConfigDirectoryTimeStamp)
                {
                    pLoadConfigDirectory->TimeDateStamp = 0;
                }

                if (pContext->FLoadConfigDirectory ||
                    pContext->FLoadConfigDirectoryVersion)
                {
                    pLoadConfigDirectory->MajorVersion = 0;
                    pLoadConfigDirectory->MinorVersion = 0;
                }

                if (pContext->Verbose)
                {
                    U_Msg("[>] %s done...\n", "LoadConfig directory");
                }
            }
        }
    }

    return TRUE;
}

DWORD PE_ComputeCheckSum(TPEContext* pContext)
{
    ULONG IgnoreRaw;

    if (pContext->Bits == 32)
    {
        IMAGE_OPTIONAL_HEADER32* pOptionalHeader = PE_ImageOptionalHeader32(pContext);

        if (!pOptionalHeader)
        {
            return 0;
        }

        IgnoreRaw = (ULONG)((BYTE*)&pOptionalHeader->CheckSum - (BYTE*)pContext->pView);
    }
    else
    {
        IMAGE_OPTIONAL_HEADER64* pOptionalHeader = PE_ImageOptionalHeader64(pContext);

        if (!pOptionalHeader)
        {
            return 0;
        }

        IgnoreRaw = (ULONG)((BYTE*)&pOptionalHeader->CheckSum - (BYTE*)pContext->pView);
    }

    ULONG64 CheckSum = 0;

    for (ULONG i = 0; i < pContext->FileSize; i += sizeof(USHORT))
    {
        if (i >= IgnoreRaw && i < (IgnoreRaw + sizeof(IgnoreRaw)))
        {
            continue; /* Ignore checksum field */
        }

        CheckSum += *((USHORT*)((BYTE*)pContext->pView + i));

        if (CheckSum > 0xFFFFFFFF)
        {
            CheckSum = (CheckSum & 0xFFFFFFFF) + (CheckSum >> 32);
        }
    }

    CheckSum = (CheckSum & 0xFFFF) + (CheckSum >> 16);
    CheckSum += CheckSum >> 16;
    CheckSum &= 0xFFFF;
    CheckSum += pContext->FileSize;

    return (CheckSum & 0xFFFFFFFF);
}

BOOLEAN PE_GenerateCheckSum(TPEContext* pContext)
{
    if (pContext->CheckSum)
    {
        if (pContext->Bits == 32)
        {
            IMAGE_OPTIONAL_HEADER32* pOptionalHeader = PE_ImageOptionalHeader32(pContext);

            if (!pOptionalHeader)
            {
                return FALSE;
            }

            if (pContext->Verbose)
            {
                U_Msg("[>] Generating checksum...\n");
            }

            pOptionalHeader->CheckSum = PE_ComputeCheckSum(pContext);

            if (pContext->Verbose)
            {
                U_Msg("[>] Checksum: 0x%lX\n", pOptionalHeader->CheckSum);
            }
        }
        else
        {
            IMAGE_OPTIONAL_HEADER64* pOptionalHeader = PE_ImageOptionalHeader64(pContext);

            if (!pOptionalHeader)
            {
                return FALSE;
            }

            if (pContext->Verbose)
            {
                U_Msg("[>] Generating checksum...\n");
            }

            pOptionalHeader->CheckSum = PE_ComputeCheckSum(pContext);

            if (pContext->Verbose)
            {
                U_Msg("[>] Checksum: 0x%lX\n", pOptionalHeader->CheckSum);
            }
        }
    }

    return TRUE;
}

ULONG PE_VirtualToRaw(TPEContext* pContext, ULONG Virtual)
{
    IMAGE_FILE_HEADER* pCOFFHeader = NULL;

    if (pContext->Bits == 32)
    {
        pCOFFHeader = PE_ImageCOFFHeader32(pContext);
    }
    else
    {
        pCOFFHeader = PE_ImageCOFFHeader64(pContext);
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

ULONG PE_ImageBits(TPEContext* pContext)
{
    IMAGE_DOS_HEADER* pDosHeader = PE_ImageDosHeader(pContext);

    if (!pDosHeader)
    {
        return 0;
    }

    BYTE* pNtHeaders = (BYTE*)pContext->pView + pDosHeader->e_lfanew;
    IMAGE_FILE_HEADER* pCOFFHeader = (IMAGE_FILE_HEADER*)((BYTE*)pNtHeaders + sizeof(DWORD)); /* Skip Signature field */

    if (pCOFFHeader->Machine == IMAGE_FILE_MACHINE_I386)
    {
        return 32;
    }

    if (pCOFFHeader->Machine == IMAGE_FILE_MACHINE_AMD64 ||
        pCOFFHeader->Machine == IMAGE_FILE_MACHINE_ARM64)
    {
        return 64;
    }

    return 0;
}

IMAGE_DOS_HEADER* PE_ImageDosHeader(TPEContext* pContext)
{
    IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)pContext->pView;

    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return NULL;
    }

    return pDosHeader;
}

IMAGE_NT_HEADERS32* PE_ImageNtHeaders32(TPEContext* pContext)
{
    IMAGE_DOS_HEADER* pDosHeader = PE_ImageDosHeader(pContext);
    IMAGE_NT_HEADERS32* pNtHeaders = (IMAGE_NT_HEADERS32*)((BYTE*)pContext->pView + pDosHeader->e_lfanew);

    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        return NULL;
    }

    return pNtHeaders;
}

IMAGE_NT_HEADERS64* PE_ImageNtHeaders64(TPEContext* pContext)
{
    IMAGE_DOS_HEADER* pDosHeader = PE_ImageDosHeader(pContext);
    IMAGE_NT_HEADERS64* pNtHeaders = (IMAGE_NT_HEADERS64*)((BYTE*)pContext->pView + pDosHeader->e_lfanew);

    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        return NULL;
    }

    return pNtHeaders;
}

IMAGE_FILE_HEADER* PE_ImageCOFFHeader32(TPEContext* pContext)
{
    IMAGE_NT_HEADERS32* pNtHeaders = PE_ImageNtHeaders32(pContext);

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

IMAGE_FILE_HEADER* PE_ImageCOFFHeader64(TPEContext* pContext)
{
    IMAGE_NT_HEADERS64* pNtHeaders = PE_ImageNtHeaders64(pContext);

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

IMAGE_OPTIONAL_HEADER32* PE_ImageOptionalHeader32(TPEContext* pContext)
{
    IMAGE_NT_HEADERS32* pNtHeaders = PE_ImageNtHeaders32(pContext);

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

IMAGE_OPTIONAL_HEADER64* PE_ImageOptionalHeader64(TPEContext* pContext)
{
    IMAGE_NT_HEADERS64* pNtHeaders = PE_ImageNtHeaders64(pContext);

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