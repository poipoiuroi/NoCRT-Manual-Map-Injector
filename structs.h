#pragma once
#ifndef _STRUCTS_H_
#define _STRUCTS_H_

#include "globals.h"

typedef struct _FILE_BASIC_INFORMATION
{
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	ULONG FileAttributes;
} FILE_BASIC_INFORMATION, * PFILE_BASIC_INFORMATION;

typedef struct _FILE_STANDARD_INFORMATION {
	LARGE_INTEGER AllocationSize;
	LARGE_INTEGER EndOfFile;
	ULONG NumberOfLinks;
	ULONG DeletePending;
	ULONG Directory;
} FILE_STANDARD_INFORMATION;

typedef struct _PROCESS_BASIC_INFORMATION_T {
	NTSTATUS ExitStatus;
	PPEB PebBaseAddress;
	KAFFINITY AffinityMask;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION_T;

#endif