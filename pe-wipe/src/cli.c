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
        *   -o          <filename> Create a new file.
        *   -fstub      Don't wipe DOS stub.
        */

        /* F stands for filter(s) */

        U_Msg("PE Wipe %lu.%lu.%lu (%s) by %s\n\n", PEWIPE_MAJOR, PEWIPE_MINOR, PEWIPE_PATCH, PEWIPE_ARCH, PEWIPE_AUTHOR);
        U_Msg(
            "Usage: pe-wipe <filename> [options]\n"
            "Options:\n"
            "   -v              Display verbose processing information.\n"

            "   -frich          Wipe Rich header.\n"

            "   -fcoff          Wipe COFF header.\n"
            "   -fcoff-ts       Wipe COFF header timestamp only.\n"

            "   -fopt           Wipe Optional header.\n"
            "   -fopt-lv        Wipe Optional header linker version only.\n"
            "   -fopt-v         Wipe Optional header version only.\n"

            "   -fsec           Wipe Section headers.\n"
            "   -fsec-n         Wipe Section headers names only.\n"
            "   -fsec-f         Wipe Section headers unused flags only.\n"

            "   -fexp           Wipe Export directory.\n"
            "   -fexp-ts        Wipe Export directory timestamp only.\n"
            "   -fexp-v         Wipe Export directory version only.\n"

            "   -fres           Wipe Resource directory.\n"
            "   -fres-ts        Wipe Resource directory timestamp only.\n"
            "   -fres-v         Wipe Resource directory version only.\n"

            "   -fdbg           Wipe Debug directory.\n"
            "   -fdbg-ts        Wipe Debug directory timestamp only.\n"
            "   -fdbg-v         Wipe Debug directory version only.\n"

            "   -fcfg           Wipe LoadConfig directory.\n"
            "   -fcfg-ts        Wipe LoadConfig directory timestamp only.\n"
            "   -fcfg-v         Wipe LoadConfig directory version only.\n"

            "   -fts            Wipe all timestamp fields only.\n"
            "   -fv             Wipe all version fields only.\n"

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
        else if (CLI_OPTION("-fcoff-ts"))
        {
            pContext->FCOFFHeaderTimeStamp = TRUE;
        }
        else if (CLI_OPTION("-fopt"))
        {
            pContext->FOptionalHeader = TRUE;
        }
        else if (CLI_OPTION("-fopt-lv"))
        {
            pContext->FOptionalHeaderLinkerVersion = TRUE;
        }
        else if (CLI_OPTION("-fopt-v"))
        {
            pContext->FOptionalHeaderVersion = TRUE;
        }
        else if (CLI_OPTION("-fsec"))
        {
            pContext->FSectionHeaders = TRUE;
        }
        else if (CLI_OPTION("-fsec-n"))
        {
            pContext->FSectionHeadersNames = TRUE;
        }
        else if (CLI_OPTION("-fsec-f"))
        {
            pContext->FSectionHeadersFlags = TRUE;
        }
        else if (CLI_OPTION("-fexp"))
        {
            pContext->FExportDirectory = TRUE;
        }
        else if (CLI_OPTION("-fexp-ts"))
        {
            pContext->FExportDirectoryTimeStamp = TRUE;
        }
        else if (CLI_OPTION("-fexp-v"))
        {
            pContext->FExportDirectoryVersion = TRUE;
        }
        else if (CLI_OPTION("-fres"))
        {
            pContext->FResourceDirectory = TRUE;
        }
        else if (CLI_OPTION("-fres-ts"))
        {
            pContext->FResourceDirectoryTimeStamp = TRUE;
        }
        else if (CLI_OPTION("-fres-v"))
        {
            pContext->FResourceDirectoryVersion = TRUE;
        }
        else if (CLI_OPTION("-fdbg"))
        {
            pContext->FDebugDirectory = TRUE;
        }
        else if (CLI_OPTION("-fdbg-ts"))
        {
            pContext->FDebugDirectoryTimeStamp = TRUE;
        }
        else if (CLI_OPTION("-fdbg-v"))
        {
            pContext->FDebugDirectoryVersion = TRUE;
        }
        else if (CLI_OPTION("-fcfg"))
        {
            pContext->FLoadConfigDirectory = TRUE;
        }
        else if (CLI_OPTION("-fcfg-ts"))
        {
            pContext->FLoadConfigDirectoryTimeStamp = TRUE;
        }
        else if (CLI_OPTION("-fcfg-v"))
        {
            pContext->FLoadConfigDirectoryVersion = TRUE;
        }
        else if (CLI_OPTION("-fts"))
        {
            pContext->FCOFFHeaderTimeStamp = TRUE;
            pContext->FExportDirectoryTimeStamp = TRUE;
            pContext->FResourceDirectoryTimeStamp = TRUE;
            pContext->FDebugDirectoryTimeStamp = TRUE;
            pContext->FLoadConfigDirectoryTimeStamp = TRUE;
        }
        else if (CLI_OPTION("-fv"))
        {
            pContext->FOptionalHeaderVersion = TRUE;
            pContext->FExportDirectoryVersion = TRUE;
            pContext->FResourceDirectoryVersion = TRUE;
            pContext->FDebugDirectoryVersion = TRUE;
            pContext->FLoadConfigDirectoryVersion = TRUE;
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

    ULONG HasFilters = pContext->Filters & ~pContext->Verbose;

    if (!HasFilters)
    {
        pContext->FRichHeader = TRUE;
        pContext->FCOFFHeader = TRUE;
        pContext->FOptionalHeader = TRUE;
        pContext->FSectionHeaders = TRUE;
        pContext->FExportDirectory = TRUE;
        pContext->FResourceDirectory = TRUE;
        pContext->FDebugDirectory = TRUE;
        pContext->FLoadConfigDirectory = TRUE;
        /*pContext->CheckSum = TRUE;*/
    }

    return CLI_STATUS_CONTINUE;
}