#include "pe.h"

NTSTATUS PE_MapView(UNICODE_STRING* pFullName, PVOID* ppView, SIZE_T* pViewSize)
{
    UNICODE_STRING NtPathName;
    if (!RtlDosPathNameToNtPathName_U(pFullName->Buffer, &NtPathName, NULL, NULL))
    {
        return STATUS_OBJECT_PATH_SYNTAX_BAD;
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

    HANDLE SectionHandle;
    Status = NtCreateSection(&SectionHandle,
                             SECTION_MAP_READ | SECTION_MAP_WRITE,
                             NULL,
                             NULL,
                             PAGE_READWRITE,
                             SEC_COMMIT,
                             FileHandle);

    if (!NT_SUCCESS(Status))
    {
        NtClose(FileHandle);
        return Status;
    }

    NtClose(FileHandle);

    *ppView = NULL;
    *pViewSize = 0;
    Status = NtMapViewOfSection(SectionHandle,
                                NtCurrentProcess(),
                                &(*ppView),
                                0,
                                0,
                                NULL,
                                pViewSize,
                                ViewUnmap,
                                0,
                                PAGE_READWRITE);

    NtClose(SectionHandle);
    return Status;
}

NTSTATUS PE_UnmapView(PVOID pView)
{
    return NtUnmapViewOfSection(NtCurrentProcess(), pView);
}