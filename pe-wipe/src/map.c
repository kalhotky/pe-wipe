#include "pe.h"
#include "util.h"

NTSTATUS PE_MapView(TPEContext* pContext)
{
    UNICODE_STRING NtPathName;
    if (!RtlDosPathNameToNtPathName_U(pContext->pFileName, &NtPathName, NULL, NULL))
    {
        return STATUS_OBJECT_PATH_SYNTAX_BAD;
    }

    if (pContext->Verbose)
    {
        U_Msg("[>] NT path name: %ls\n", NtPathName.Buffer);
    }

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes,
                               &NtPathName,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    HANDLE FileHandle;
    IO_STATUS_BLOCK IoStatusBlock;
    NTSTATUS Status = NtCreateFile(&FileHandle,
                                   SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA,
                                   &ObjectAttributes,
                                   &IoStatusBlock,
                                   NULL,
                                   FILE_ATTRIBUTE_NORMAL,
                                   0,
                                   FILE_OPEN,
                                   FILE_NON_DIRECTORY_FILE,
                                   NULL,
                                   0);

    RtlFreeUnicodeString(&NtPathName);

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    if (pContext->Verbose)
    {
        U_Msg("[>] File handle: 0x%zX\n", (SIZE_T)FileHandle);
    }

    FILE_STANDARD_INFORMATION FileInfo;
    Status = NtQueryInformationFile(FileHandle, &IoStatusBlock, &FileInfo, sizeof(FileInfo), FileStandardInformation);

    if (!NT_SUCCESS(Status))
    {
        NtClose(FileHandle);
        return Status;
    }

    if (FileInfo.EndOfFile.HighPart > 0)
    {
        NtClose(FileHandle);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    pContext->FileSize = FileInfo.EndOfFile.LowPart;

    HANDLE SectionHandle;
    Status = NtCreateSection(&SectionHandle,
                             SECTION_MAP_READ | SECTION_MAP_WRITE,
                             NULL,
                             NULL,
                             PAGE_READWRITE,
                             SEC_COMMIT,
                             FileHandle);

    NtClose(FileHandle);

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    if (pContext->Verbose)
    {
        U_Msg("[>] Section handle: 0x%zX\n", (SIZE_T)SectionHandle);
    }

    pContext->pView = NULL;
    pContext->ViewSize = 0;
    Status = NtMapViewOfSection(SectionHandle,
                                NtCurrentProcess(),
                                &pContext->pView,
                                0,
                                0,
                                NULL,
                                &pContext->ViewSize,
                                ViewUnmap,
                                0,
                                PAGE_READWRITE);

    if (NT_SUCCESS(Status) && pContext->Verbose)
    {
        U_Msg("[>] PE has been mapped!\n");
        U_Msg("    View base: 0x%zX\n", (SIZE_T)pContext->pView);
        U_Msg("    View size: 0x%zX\n", pContext->ViewSize);
        U_Msg("    File size: 0x%lX\n", pContext->FileSize);
    }

    NtClose(SectionHandle);
    return Status;
}

NTSTATUS PE_UnmapView(TPEContext* pContext)
{
    NTSTATUS Status = NtUnmapViewOfSection(NtCurrentProcess(), pContext->pView);

    if (NT_SUCCESS(Status))
    {
        pContext->pView = NULL;
        pContext->ViewSize = 0;

        if (pContext->Verbose)
        {
            U_Msg("[>] PE has been unmapped!\n");
        }
    }

    return Status;
}