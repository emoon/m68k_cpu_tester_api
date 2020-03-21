#pragma once

#ifndef _WIN32
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#define _tcsicmp strcasecmp
#define stricmp strncasecmp
#define _tcsncmp strncmp
#define _tcscmp strcmp
#define strnicmp strncasecmp
#define _istspace isspace
#define _tcslen strlen
#define _tcscspn strcspn
#define _stprintf sprintf
#define _tstol atol
#define _tcstol strtol
#define _tcscpy strcpy
#define _tcscat strcat
#define _tfopen fopen
#define fgetws fgets
#define fputws fputs
#define _tcschr strchr
#define _totupper toupper
#define wprintf printf
#define _tunlink unlink
#define _wmkdir(name) mkdir(name, 0700)
#define _totlower tolower
#define _tcsnicmp stricmp
#define _tcstoul strtoul
#define _tcsstr strstr
#define _tcsncpy strncpy
char* strupr(char*);
#endif

