#pragma once
#include <phnt/phnt_windows.h>
#include <phnt/phnt.h>

/* image.c */

#define IMAGE_HEADER_TYPE_32        0x00000000
#define IMAGE_HEADER_TYPE_64        0x00000001
#define IMAGE_HEADER_TYPE_UNKNOWN   0xFFFFFFFF

#define IMAGE_RICH_SIGNATURE        0x68636952 /* Rich */
#define IMAGE_DANS_SIGNATURE        0x536E6144 /* DanS */

BOOLEAN PE_WipeRichHeader(PVOID pView);
BOOLEAN PE_WipeCOFFHeader(PVOID pView, ULONG HeaderType);
BOOLEAN PE_WipeOptionalHeader(PVOID pView, ULONG HeaderType);
BOOLEAN PE_WipeSectionHeaders(PVOID pView, ULONG HeaderType);
BOOLEAN PE_WipeExportDirectory(PVOID pView, ULONG HeaderType);
BOOLEAN PE_WipeResourceDirectory(PVOID pView, ULONG HeaderType);
BOOLEAN PE_WipeDebugDirectory(PVOID pView, ULONG HeaderType);
BOOLEAN PE_WipeLoadConfigDirectory(PVOID pView, ULONG HeaderType);
DWORD PE_ComputeCheckSum(PVOID pView, SIZE_T ViewSize);

ULONG PE_VirtualToRaw(PVOID pView, ULONG Virtual, ULONG HeaderType); /* Relative */
DWORD PE_FixUpSectionFlags(DWORD Characteristics);

ULONG PE_ImageHeaderType(PVOID pView);
IMAGE_DOS_HEADER* PE_ImageDosHeader(PVOID pView);
IMAGE_NT_HEADERS32* PE_ImageNtHeaders32(PVOID pView);
IMAGE_NT_HEADERS64* PE_ImageNtHeaders64(PVOID pView);
IMAGE_FILE_HEADER* PE_ImageCOFFHeader32(PVOID pView);
IMAGE_FILE_HEADER* PE_ImageCOFFHeader64(PVOID pView);
IMAGE_OPTIONAL_HEADER32* PE_ImageOptionalHeader32(PVOID pView);
IMAGE_OPTIONAL_HEADER64* PE_ImageOptionalHeader64(PVOID pView);

/* map.c */

NTSTATUS PE_MapView(UNICODE_STRING* pFullName, PVOID* ppView, SIZE_T* pViewSize);
NTSTATUS PE_UnmapView(PVOID pView);