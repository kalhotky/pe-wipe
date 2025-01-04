#pragma comment(lib, "ntdll.lib")

#include <phnt/phnt_windows.h>
#include <phnt/phnt.h>

#include "pe.h"
#include "cli.h"
#include "util.h"

INT wmain(INT argc, WCHAR** argv)
{
    TPEContext Context;
    INT ExitCode = CLI_ProcessCmdLine(&Context, argc, argv);

    if (ExitCode != CLI_STATUS_CONTINUE)
    {
        return ExitCode;
    }

    NTSTATUS Status = PE_MapView(&Context);

    if (!NT_SUCCESS(Status))
    {
        U_Msg("[x] Couldn't map view: 0x%lX\n", Status);
        return EXIT_FAILURE;
    }

    ExitCode = PE_Wipe(&Context) ? EXIT_SUCCESS : EXIT_FAILURE;
    Status = PE_UnmapView(&Context);
    return ExitCode;
}