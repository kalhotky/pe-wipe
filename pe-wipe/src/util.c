#include "util.h"
#include <stdio.h>

void U_Msg(const CHAR* pFormat, ...)
{
    if (!pFormat)
    {
        return;
    }

    CHAR Buffer[0x1000];
    va_list ArgList;

    va_start(ArgList, pFormat);
    vsnprintf(Buffer, sizeof(Buffer), pFormat, ArgList);

    ULONG_PTR Arguments[] = {
        (ULONG_PTR)strlen(Buffer) + 1,
        (ULONG_PTR)Buffer
    };

    __try
    {
        EXCEPTION_RECORD ExceptionRecord = {
            .ExceptionCode = DBG_PRINTEXCEPTION_C
        };

        ExceptionRecord.NumberParameters = ARRAYSIZE(Arguments);

        for (DWORD i = 0; i < ExceptionRecord.NumberParameters; i += 1)
        {
            ExceptionRecord.ExceptionInformation[i] = Arguments[i];
        }

        RtlRaiseException(&ExceptionRecord);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        /* Debugger not attached */
    }

    if (NtCurrentPeb()->ProcessParameters->ConsoleHandle)
    {
        IO_STATUS_BLOCK IoStatusBlock;
        NtWriteFile(NtCurrentPeb()->ProcessParameters->StandardOutput,
                    NULL,
                    NULL,
                    NULL,
                    &IoStatusBlock,
                    Buffer,
                    (ULONG)Arguments[0] - 1,
                    NULL,
                    NULL);
    }
}