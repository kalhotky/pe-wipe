#pragma once
#include <phnt/phnt_windows.h>
#include <phnt/phnt.h>
#include "pe.h"

#define CLI_STATUS_SUCCESS     EXIT_SUCCESS
#define CLI_STATUS_FAILURE     EXIT_FAILURE
#define CLI_STATUS_CONTINUE    -1

INT CLI_ProcessCmdLine(TPEContext* pContext, INT argc, WCHAR** argv);