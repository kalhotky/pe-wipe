#pragma comment(lib, "ntdll.lib")

#include <phnt/phnt_windows.h>
#include <phnt/phnt.h>

#include "pe.h"
#include "util.h"

INT wmain(INT argc, WCHAR** argv)
{
    if (argc != 2)
    {
#ifdef _WIN64
        const CHAR ArchName[] = "x64";
#else
        const CHAR ArchName[] = "x86";
#endif
        U_Msg(
            "PE Wipe %s by https://github.com/kalhotky\n"
            "\n"
            "Usage: %ls <filename>\n"
            "",
            ArchName,
            argv[0]
        );
        return EXIT_SUCCESS;
    }

    UNICODE_STRING FileName;
    RtlInitUnicodeString(&FileName, argv[1]);

    PVOID pView;
    SIZE_T ViewSize;
    NTSTATUS Status = PE_MapView(&FileName, &pView, &ViewSize);

    if (!NT_SUCCESS(Status))
    {
        U_Msg("[x] Couldn't map view: 0x%X\n", Status);
        return EXIT_FAILURE;
    }

    INT ExitCode;
    ULONG HeaderType = PE_ImageHeaderType(pView);

    if (HeaderType != IMAGE_HEADER_TYPE_UNKNOWN)
    {
        if (!PE_WipeRichHeader(pView))
        {
            U_Msg("[!] Could't wipe %s", "Rich header");
        }

        if (!PE_WipeFileHeader(pView, HeaderType))
        {
            U_Msg("[!] Could't wipe %s", "File header");
        }

        if (!PE_WipeOptionalHeader(pView, HeaderType))
        {
            U_Msg("[!] Could't wipe %s", "Optional header");
        }

        if (!PE_WipeSectionHeaders(pView, HeaderType))
        {
            U_Msg("[!] Could't wipe %s", "Section headers");
        }

        if (!PE_WipeExportDirectory(pView, HeaderType))
        {
            U_Msg("[!] Could't wipe %s", "Export directory");
        }

        if (!PE_WipeResourceDirectory(pView, HeaderType))
        {
            U_Msg("[!] Could't wipe %s", "Resource directory");
        }

        if (!PE_WipeDebugDirectory(pView, HeaderType))
        {
            U_Msg("[!] Could't wipe %s", "Debug directory");
        }

        if (!PE_WipeLoadConfigDirectory(pView, HeaderType))
        {
            U_Msg("[!] Could't wipe %s", "LoadConfig directory");
        }

        U_Msg("[+] Successfully stripped data from %ls\n", FileName.Buffer);
        ExitCode = EXIT_SUCCESS;
    }
    else
    {
        U_Msg("[x] Invalid PE format :(\n");
        ExitCode = EXIT_FAILURE;
    }

    PE_UnmapView(pView);
    return ExitCode;
}