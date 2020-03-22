#pragma once

#ifdef _WIN32
#include <direct.h>
#endif

//#ifndef _WIN32
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#define strcasecmp stricmp
#define strncasecmp strnicmp
#else
#define stricmp strncasecmp
#define strnicmp strncasecmp
#endif

#define _tcsncmp strncmp
#define _tcscmp strcmp
#define _tcsicmp strcasecmp
#define _istspace isspace
#define _tcslen strlen
#define _tcstrlen strlen
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
#ifndef _WIN32
#define _wmkdir(name) mkdir(name, 0700)
#else
#define _wmkdir(name) mkdir(name)
#endif
#define _totlower tolower
#define _tcsnicmp strnicmp
#define _tcstoul strtoul
#define _tcsstr strstr
#define _tcsncpy strncpy
#define _vsntprintf vsnprintf
//#endif

