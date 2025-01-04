#include <stdio.h>
#include "cli.h"
#include "util.h"

INT CLI_ProcessCmdLine(TPEContext* pContext, INT argc, WCHAR** argv)
{
    memset(pContext, 0, sizeof(*pContext));

    if (argc <= 1)
    {
        /*
        * TODO:
        *   -o          <filename> Create a new file.
        *   -fstub      Don't wipe DOS stub.
        */

#ifndef _WIN64
        const CHAR ArchName[] = "x86";
#else
        const CHAR ArchName[] = "x64";
#endif

        U_Msg("PE Wipe " PEWIPE_VERSION " (%s) by " PEWIPE_AUTHOR "\n\n", ArchName);
        U_Msg(
            "Usage: pe-wipe <filename> [options]\n"
            "Options:\n"
            "   -v              Display verbose processing information.\n"

            "   -frich          Don't wipe Rich header.\n"
            "   -fcoff          Don't wipe COFF header.\n"
            "   -fopt           Don't wipe Optional header.\n"
            "   -fsec           Don't wipe Section headers.\n"
            "   -fsec-n         Don't wipe Section headers names.\n"

            "   -fexp           Don't wipe Export directory.\n"
            "   -fres           Don't wipe Resource directory.\n"
            "   -fdbg           Don't wipe Debug directory.\n"
            "   -fcfg           Don't wipe LoadConfig directory.\n"

            "   -fts            Don't wipe timestamp fields.\n"
            "   -fuv            Don't wipe user version fields.\n"
            "   -flv            Don't wipe linker version fields.\n"

            /*"   -cs         Generate PE checksum.\n"*/
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
        else if (CLI_OPTION("-frich"))
        {
            pContext->FRichHeader = TRUE;
        }
        else if (CLI_OPTION("-fcoff"))
        {
            pContext->FCOFFHeader = TRUE;
        }
        else if (CLI_OPTION("-fopt"))
        {
            pContext->FOptionalHeader = TRUE;
        }
        else if (CLI_OPTION("-fsec"))
        {
            pContext->FSectionHeaders = TRUE;
        }
        else if (CLI_OPTION("-fsec-n"))
        {
            pContext->FSectionHeadersNames = TRUE;
        }
        else if (CLI_OPTION("-fexp"))
        {
            pContext->FExportDirectory = TRUE;
        }
        else if (CLI_OPTION("-fres"))
        {
            pContext->FResourceDirectory = TRUE;
        }
        else if (CLI_OPTION("-fdbg"))
        {
            pContext->FDebugDirectory = TRUE;
        }
        else if (CLI_OPTION("-fcfg"))
        {
            pContext->FLoadConfigDirectory = TRUE;
        }
        else if (CLI_OPTION("-fts"))
        {
            pContext->FTimeStamp = TRUE;
        }
        else if (CLI_OPTION("-fuv"))
        {
            pContext->FUserVersion = TRUE;
        }
        else if (CLI_OPTION("-flv"))
        {
            pContext->FLinkerVersion = TRUE;
        }
        /*else if (CLI_OPTION("-cs"))
        {
            pContext->CheckSum = TRUE;
        }*/
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

    return CLI_STATUS_CONTINUE;
}