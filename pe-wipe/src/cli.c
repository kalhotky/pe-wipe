#include <stdio.h>
#include "cli.h"
#include "util.h"
#include "version.h"

INT CLI_ProcessCmdLine(TPEContext* pContext, INT argc, WCHAR** argv)
{
    memset(pContext, 0, sizeof(*pContext));

    if (argc <= 1)
    {
        /*
        * TODO:
        *   -o          Create output file.
        *   -dos        Wipe DOS header.
        *   -stub       Wipe DOS stub.
        */

        U_Msg("PE Wipe %lu.%lu.%lu (%s) by %s\n\n", PEWIPE_MAJOR, PEWIPE_MINOR, PEWIPE_PATCH, PEWIPE_ARCH, PEWIPE_AUTHOR);
        U_Msg(
            "Usage: pe-wipe <filename> [options]\n"
            "Options:\n"
            "   -v              Display verbose processing information.\n"
            "   -cs             Generate PE checksum.\n"
            "\n"
            "   -rich           Wipe Rich header.\n"
            "   -coff           Wipe COFF header.\n"
            "   -opt            Wipe Optional header.\n"
            "   -sec            Wipe Section header(s).\n"
            "   -exp            Wipe Export directory.\n"
            "   -res            Wipe Resource directory.\n"
            "   -dbg            Wipe Debug directory.\n"
            "   -cfg            Wipe LoadConfig directory.\n"
            "\n"
            "   -fopt-lv        Keep Optional header linker version.\n"
            "   -fsec-n         Keep Section header(s) name(s).\n"
            "   -fsec-f         Keep Section header(s) descriptive flags.\n"
            "   -fts            Keep all timestamp fields.\n"
            "   -fv             Keep all version fields.\n"
        );

        return CLI_STATUS_SUCCESS;
    }

#define CLI_OPTION(name) !wcscmp(argv[i], L##name)

    for (INT i = 1; i < argc; i += 1)
    {
        if (CLI_OPTION("-v"))
        {
            pContext->Verbose = TRUE;
        }
        else if (CLI_OPTION("-cs"))
        {
            pContext->CheckSum = TRUE;
        }
        else if (CLI_OPTION("-coff"))
        {
            pContext->COFFHeader = TRUE;
        }
        else if (CLI_OPTION("-opt"))
        {
            pContext->OptionalHeader = TRUE;
        }
        else if (CLI_OPTION("-sec"))
        {
            pContext->SectionHeaders = TRUE;
        }
        else if (CLI_OPTION("-exp"))
        {
            pContext->ExportDirectory = TRUE;
        }
        else if (CLI_OPTION("-res"))
        {
            pContext->ResourceDirectory = TRUE;
        }
        else if (CLI_OPTION("-dbg"))
        {
            pContext->DebugDirectory = TRUE;
        }
        else if (CLI_OPTION("-cfg"))
        {
            pContext->LoadConfigDirectory = TRUE;
        }
        else if (CLI_OPTION("-fopt-lv"))
        {
            pContext->FOptionalHeaderLinkerVersion = TRUE;
        }
        else if (CLI_OPTION("-fsec-n"))
        {
            pContext->FSectionHeadersNames = TRUE;
        }
        else if (CLI_OPTION("-fsec-f"))
        {
            pContext->FSectionHeadersFlags = TRUE;
        }
        else if (CLI_OPTION("-fts"))
        {
            pContext->FTimeStamp = TRUE;
        }
        else if (CLI_OPTION("-fv"))
        {
            pContext->FVersion = TRUE;
        }
        else if (!pContext->pFileName)
        {
            pContext->pFileName = argv[i];
        }
    }

#undef CLI_OPTION

    if (!pContext->pFileName)
    {
        U_Msg("[x] Filename not specified\n");
        return CLI_STATUS_FAILURE;
    }

    if (!pContext->Options)
    {
        pContext->Options = 0xFFFFFFFF;

        if (pContext->Verbose)
        {
            U_Msg("[>] Enabled all options\n");
        }
    }

    return CLI_STATUS_CONTINUE;
}