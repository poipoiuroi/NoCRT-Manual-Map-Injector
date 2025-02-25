#include "globals.h"

int mini_atoi(const char* str)
{
	if (!str || !*str) return 0;

	int result = 0, sign = 1;
	while (*str == ' ' || *str == '\t') str++;

	if (*str == '-' || *str == '+') sign = (*str++ == '-') ? -1 : 1;

	while (*str >= '0' && *str <= '9') {
		int digit = *str - '0';
		if (result > (INT_MAX - digit) / 10) return sign == 1 ? INT_MAX : INT_MIN;
		result = result * 10 + digit;
		str++;
	}

	return sign * result;
}

const wchar_t* s2w(const char* str)
{
	if (!str) return 0;
	int len = api::MultiByteToWideChar(CP_UTF8, 0, str, -1, 0, 0);
	wchar_t* wstr = (wchar_t*)api::malloc(len * sizeof(wchar_t));
	if (wstr) api::MultiByteToWideChar(CP_UTF8, 0, str, -1, wstr, len);
	return wstr;
}

DWORD fnGetFileAttributes(const char* path)
{
	OBJECT_ATTRIBUTES objattr{};
	FILE_BASIC_INFORMATION info{};

	auto wstr = s2w(path);
	if (!wstr) return false;

	wchar_t* fullPath = (wchar_t*)api::malloc((4 + wcslen(wstr) + 1) * sizeof(wchar_t));
	if (!fullPath) {
		api::free((PVOID)wstr);
		return false;
	}

	wcscpy(fullPath, zxc(L"\\??\\"));
	wcscat(fullPath, wstr);
	api::free((PVOID)wstr);

	UNICODE_STRING ustr = { (USHORT)(wcslen(fullPath) * sizeof(wchar_t)),
							(USHORT)((wcslen(fullPath) + 1) * sizeof(wchar_t)),
							fullPath };

	objattr.Length = sizeof(OBJECT_ATTRIBUTES);
	objattr.ObjectName = &ustr;
	objattr.Attributes = OBJ_CASE_INSENSITIVE;

	if (NT_SUCCESS(fnNtQueryAttributesFile(&objattr, &info)))
	{
		api::free(fullPath);
		return info.FileAttributes;
	}

	api::free(fullPath);
	return INVALID_FILE_ATTRIBUTES;
}

bool object_exist(const char* path)
{
	return fnGetFileAttributes(path) != INVALID_FILE_ATTRIBUTES;
}

DWORD fnGetFileSize(HANDLE hFile)
{
	IO_STATUS_BLOCK io;
	FILE_STANDARD_INFORMATION info;

	if (!NT_SUCCESS(fnNtQueryInformationFile(hFile, &io, &info, sizeof(info), 0x5/*FileStandardInformation*/)))
		return INVALID_FILE_SIZE;

	return info.EndOfFile.LowPart;
}

HANDLE fnOpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)
{
	CLIENT_ID clientId{ (HANDLE)dwProcessId, 0 };
	OBJECT_ATTRIBUTES objattr{ };
	HANDLE hProcess{};
	NTSTATUS status;

	objattr.Length = sizeof(OBJECT_ATTRIBUTES);
	objattr.Attributes = bInheritHandle ? OBJ_INHERIT : 0;

	if (!NT_SUCCESS(fnNtOpenProcess(&hProcess, dwDesiredAccess, &objattr, &clientId)))
		return INVALID_HANDLE_VALUE;

	return hProcess;
}

BOOL fnGetExitCodeProcess(HANDLE hProcess, LPDWORD lpExitCode)
{
	PROCESS_BASIC_INFORMATION_T pbi{};

	ULONG len{};
	if(!NT_SUCCESS(fnNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &len)))
		return FALSE;

	*lpExitCode = pbi.ExitStatus;

	return TRUE;
}

struct MANUAL_MAPPING_DATA
{
	decltype(GetProcAddress)* pGetProcAddress;
	decltype(LoadLibraryA)* pLoadLibraryA;
	decltype(RtlAddFunctionTable)* pRtlAddFunctionTable;
	BYTE* pbase;
	HINSTANCE hMod;
	DWORD fdwReasonParam;
	LPVOID reservedParam;
	BOOL SEHSupport;
};

#pragma runtime_checks("", off)
#pragma optimize("", off)
void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData)
{
	if (!pData) {
		pData->hMod = (HINSTANCE)0x404040;
		return;
	}

	BYTE* pBase = pData->pbase;
	auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)pBase)->e_lfanew)->OptionalHeader;

	auto _LoadLibraryA = pData->pLoadLibraryA;
	auto _GetProcAddress = pData->pGetProcAddress;
	auto _RtlAddFunctionTable = pData->pRtlAddFunctionTable;
	auto _DllMain = reinterpret_cast<BOOL(__stdcall*)(void*, DWORD, void*)>(pBase + pOpt->AddressOfEntryPoint);

	BYTE* LocationDelta = pBase - pOpt->ImageBase;
	if (LocationDelta) {
		if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			const auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
			while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
				UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

				for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
					if (((*pRelativeInfo >> 0x0C) == 10)) {
						UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
						*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
					}
				}
				pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
			}
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name) {
			char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
			HINSTANCE hDll = _LoadLibraryA(szMod);

			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

			if (!pThunkRef)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
				}
				else {
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
				}
			}
			++pImportDescr;
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallback && *pCallback; ++pCallback)
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, 0);
	}

	bool ExceptionSupportFailed = false;

	if (pData->SEHSupport) {
		auto excep = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
		if (excep.Size) {
			if (!_RtlAddFunctionTable(
				reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(pBase + excep.VirtualAddress),
				excep.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (DWORD64)pBase)) {
				ExceptionSupportFailed = true;
			}
		}
	}

	_DllMain(pBase, pData->fdwReasonParam, pData->reservedParam);

	if (ExceptionSupportFailed) pData->hMod = reinterpret_cast<HINSTANCE>(0x505050);
	else pData->hMod = reinterpret_cast<HINSTANCE>(pBase);
}
#pragma runtime_checks("", on)
#pragma optimize("", restore)

bool manual_map_dll(HANDLE hProc, BYTE* pSrcData)
{
	IMAGE_DOS_HEADER* pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData);
	if (pDosHeader->e_magic != 0x5A4D) return false;

	IMAGE_NT_HEADERS* pNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + pDosHeader->e_lfanew);
	IMAGE_OPTIONAL_HEADER* pOptHeader = &pNtHeader->OptionalHeader;
	IMAGE_FILE_HEADER* pFileHeader = &pNtHeader->FileHeader;

	if (pFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64) return false;

	PVOID v1 = 0;
	SIZE_T size = pOptHeader->SizeOfImage;
	if (!NT_SUCCESS(fnNtAllocateVirtualMemory(hProc, &v1, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) return false;

	BYTE* pTargetBase = (BYTE*)v1;
	if (!pTargetBase) return false;

	DWORD oldp = 0;
	if (!NT_SUCCESS(fnNtProtectVirtualMemory(hProc, &v1, &size, PAGE_EXECUTE_READWRITE, &oldp))) return false;

	MANUAL_MAPPING_DATA data = { 0 };
	data.pGetProcAddress = (decltype(GetProcAddress)*)api::func_get_addr(zxc("GetProcAddress"), api::peb_get_module(zxc(L"kernel32.dll")));
	data.pLoadLibraryA = (decltype(LoadLibraryA)*)api::func_get_addr(zxc("LoadLibraryA"), api::peb_get_module(zxc(L"kernel32.dll")));
	data.pRtlAddFunctionTable = (decltype(RtlAddFunctionTable)*)api::func_get_addr(zxc("RtlAddFunctionTable"), api::peb_get_module(zxc(L"ntdll.dll")));
	data.pbase = pTargetBase;
	data.fdwReasonParam = DLL_PROCESS_ATTACH;
	data.reservedParam = FALSE;
	data.SEHSupport = TRUE;

	if (!NT_SUCCESS(fnNtWriteVirtualMemory(hProc, pTargetBase, pSrcData, 0x1000, 0)))
	{
		fnNtFreeVirtualMemory(hProc, &v1, 0, MEM_RELEASE);
		return false;
	}

	IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	for (UINT i = 0; i < pFileHeader->NumberOfSections; ++i, ++pSectionHeader)
	{
		if (pSectionHeader->SizeOfRawData && !NT_SUCCESS(fnNtWriteVirtualMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress,
			pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, 0)))
		{
			fnNtFreeVirtualMemory(hProc, &v1, 0, MEM_RELEASE);
			return false;
		}
	}

	BYTE* MappingDataAlloc = 0;
	size = sizeof(MANUAL_MAPPING_DATA);
	if (!NT_SUCCESS(fnNtAllocateVirtualMemory(hProc, (PVOID*)&MappingDataAlloc, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))
		return false;

	if (!MappingDataAlloc || !NT_SUCCESS(fnNtWriteVirtualMemory(hProc, MappingDataAlloc, &data, sizeof(MANUAL_MAPPING_DATA), 0)))
	{
		fnNtFreeVirtualMemory(hProc, &v1, 0, MEM_RELEASE);
		fnNtFreeVirtualMemory(hProc, (PVOID*)&MappingDataAlloc, 0, MEM_RELEASE);
		return false;
	}

	PVOID pShellcode = 0;
	size = 0x1000;
	if (!NT_SUCCESS(fnNtAllocateVirtualMemory(hProc, &pShellcode, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
		return false;

	if (!pShellcode || !NT_SUCCESS(fnNtWriteVirtualMemory(hProc, pShellcode, Shellcode, 0x1000, 0)))
	{
		fnNtFreeVirtualMemory(hProc, &v1, 0, MEM_RELEASE);
		fnNtFreeVirtualMemory(hProc, (PVOID*)&MappingDataAlloc, 0, MEM_RELEASE);
		fnNtFreeVirtualMemory(hProc, (PVOID*)&pShellcode, 0, MEM_RELEASE);
		return false;
	}

	HANDLE hThread = api::CreateRemoteThread(hProc, 0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), MappingDataAlloc, 0, 0);
	if (!hThread)
	{
		fnNtFreeVirtualMemory(hProc, &v1, 0, MEM_RELEASE);
		fnNtFreeVirtualMemory(hProc, (PVOID*)&MappingDataAlloc, 0, MEM_RELEASE);
		fnNtFreeVirtualMemory(hProc, (PVOID*)&pShellcode, 0, MEM_RELEASE);
		return false;
	}
	fnNtClose(hThread);

	HINSTANCE hCheck = 0;
	while (!hCheck)
	{
		DWORD exitcode = 0;
		fnGetExitCodeProcess(hProc, &exitcode);
		if (exitcode != STILL_ACTIVE) return false;

		MANUAL_MAPPING_DATA data_checked = { 0 };
		fnNtReadVirtualMemory(hProc, MappingDataAlloc, &data_checked, sizeof(data_checked), 0);
		hCheck = data_checked.hMod;

		if (hCheck == (HINSTANCE)0x404040)
		{
			fnNtFreeVirtualMemory(hProc, &v1, 0, MEM_RELEASE);
			fnNtFreeVirtualMemory(hProc, (PVOID*)&MappingDataAlloc, 0, MEM_RELEASE);
			fnNtFreeVirtualMemory(hProc, (PVOID*)&pShellcode, 0, MEM_RELEASE);
			return false;
		}
	}

	BYTE* emptyBuffer = (BYTE*)api::malloc(1024 * 1024 * 20);
	if (!emptyBuffer) return false;

	memset(emptyBuffer, 0, 1024 * 1024 * 20);
	fnNtWriteVirtualMemory(hProc, pTargetBase, emptyBuffer, 0x1000, 0);

	pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	for (UINT i = 0; i < pFileHeader->NumberOfSections; ++i, ++pSectionHeader)
	{
		if (pSectionHeader->Misc.VirtualSize)
		{
			if (strcmp((char*)pSectionHeader->Name, zxc(".pdata")) == 0 ||
				strcmp((char*)pSectionHeader->Name, zxc(".rsrc")) == 0 ||
				strcmp((char*)pSectionHeader->Name, zxc(".reloc")) == 0)
			{
				fnNtWriteVirtualMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, emptyBuffer, pSectionHeader->Misc.VirtualSize, 0);
			}
		}
	}

	pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	for (UINT i = 0; i < pFileHeader->NumberOfSections; ++i, ++pSectionHeader)
	{
		if (pSectionHeader->Misc.VirtualSize)
		{
			DWORD old = 0;
			DWORD newP = (pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE :
				((pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) ? PAGE_EXECUTE_READ : PAGE_READONLY);
			fnNtProtectVirtualMemory(hProc, (PVOID*)(pTargetBase + pSectionHeader->VirtualAddress),
				(SIZE_T*)&pSectionHeader->Misc.VirtualSize, newP, &old);
		}
	}

	DWORD old = 0;
	fnNtProtectVirtualMemory(hProc, (PVOID*)&pTargetBase, (SIZE_T*)&IMAGE_FIRST_SECTION(pNtHeader)->VirtualAddress, PAGE_READONLY, &old);
	fnNtWriteVirtualMemory(hProc, pShellcode, emptyBuffer, 0x1000, 0);
	fnNtFreeVirtualMemory(hProc, (PVOID*)&pShellcode, 0, MEM_RELEASE);
	fnNtFreeVirtualMemory(hProc, (PVOID*)&MappingDataAlloc, 0, MEM_RELEASE);
	return true;
}

#pragma comment(linker, "/ENTRY:dreamrealm")

int dreamrealm() // entry point
{
	// windows 22H2 19045.5487
	ASSIGN_API(LoadLibraryW, L"kernel32.dll"); // complex
	ASSIGN_API(RtlFreeHeap, L"ntdll.dll"); // error if use HeapFree
	ASSIGN_API(RtlCreateHeap, L"ntdll.dll"); // error if use HeapCreate
	ASSIGN_API(RtlAllocateHeap, L"ntdll.dll"); // error if use HeapAlloc
	ASSIGN_API(CreateFileA, L"kernel32.dll"); // complex, NtCreateFile solo doesn`t work
	ASSIGN_API(MultiByteToWideChar, L"kernel32.dll"); // complex
	ASSIGN_API(CreateRemoteThread, L"kernel32.dll"); // complex
	
#ifndef PRINT_COOL
	ASSIGN_API(__stdio_common_vfprintf, L"api-ms-win-crt-stdio-l1-1-0.dll");
	ASSIGN_API(__acrt_iob_func, L"api-ms-win-crt-stdio-l1-1-0.dll");
#endif

	int argc{};
	char** argv{};

	{
		auto base = api::peb_get_module(zxc(L"kernelbase.dll"));
		auto pArg = (STRING*)((UINT64)base + 0x2BFF50); // address that GetCommandLineA return

		char* token = pArg->Buffer;
		while (token && *token != '\0')
		{
			while (*token == ' ') token++;
			if (*token == '\0') break;
			argc++;
			while (*token != '\0' && *token != ' ') token++;
		}

		argv = (char**)api::malloc((argc + 1) * sizeof(char*));
		if (argv == 0) return 1;

		token = pArg->Buffer;
		int i = 0;
		while (token && *token != '\0')
		{
			while (*token == ' ') token++;
			if (*token == '\0') break;
			argv[i] = token;
			while (*token != '\0' && *token != ' ') token++;
			if (*token != '\0')
			{
				*token = '\0';
				token++;
			}
			i++;
		}

		argv[argc] = 0;
	}

	if (argc < 3) return 2;

	const char* file_path = argv[2];
	if (!object_exist(file_path)) return 3;

	UINT32 pid = mini_atoi(argv[1]);
	if (!pid) return 4;

	HANDLE hFile = api::CreateFileA(file_path, GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE) return 5;

	DWORD fileSize = fnGetFileSize(hFile);
	if (fileSize == INVALID_FILE_SIZE) return 6;

	BYTE* buffer = (BYTE*)api::malloc(fileSize);
	if (!buffer) return 7;

	IO_STATUS_BLOCK io{};
	if (!NT_SUCCESS(fnNtReadFile(hFile, 0, 0, 0, &io, buffer, fileSize, 0, 0))) return 8;
	fnNtClose(hFile);

	HANDLE hProc = fnOpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (!hProc) return 9;

	if (!manual_map_dll(hProc, buffer))
		api::printf(zxc("proebali\n"));

	fnNtClose(hProc);
	api::free(buffer);
	api::free(argv);
	// no need to free after each "error" return;
	// it will be overwritten/wiped from memory after process ends;
	return 0;
}