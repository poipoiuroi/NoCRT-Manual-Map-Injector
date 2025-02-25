#pragma once
#ifndef _API_H_
#define _API_H_

#include "globals.h"

extern "C"
{
	NTSTATUS fnNtClose(HANDLE h);

	NTSTATUS fnNtOpenProcess(
		PHANDLE ProcessHandle,
		ACCESS_MASK DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes,
		CLIENT_ID* ClientId
	);

	NTSTATUS fnNtQueryInformationFile(
		HANDLE FileHandle,
		PIO_STATUS_BLOCK IoStatusBlock,
		PVOID FileInformation,
		ULONG Length,
		UINT32 FileInformationClass
	);

	NTSTATUS fnNtReadFile(
		HANDLE FileHandle,
		HANDLE Event,
		PIO_APC_ROUTINE ApcRoutine,
		PVOID ApcContext,
		PIO_STATUS_BLOCK IoStatusBlock,
		PVOID Buffer,
		ULONG Length,
		PLARGE_INTEGER ByteOffset,
		PULONG Key
	);

	NTSTATUS fnNtQueryInformationProcess(
		HANDLE ProcessHandle,
		PROCESSINFOCLASS ProcessInformationClass,
		PVOID ProcessInformation,
		ULONG ProcessInformationLength,
		PULONG ReturnLength
	);

	NTSTATUS fnNtFreeVirtualMemory(
		HANDLE ProcessHandle,
		PVOID* BaseAddress,
		PSIZE_T RegionSize,
		ULONG FreeType
	);

	NTSTATUS fnNtProtectVirtualMemory(
		HANDLE ProcessHandle,
		PVOID* BaseAddress,
		SIZE_T* NumberOfBytesToProtect,
		ULONG NewAccessProtection,
		PULONG OldAccessProtection
	);

	NTSTATUS fnNtWriteVirtualMemory(
		HANDLE ProcessHandle,
		PVOID BaseAddress,
		PVOID Buffer,
		SIZE_T NumberOfBytesToWrite,
		PSIZE_T NumberOfBytesWritten
	);

	NTSTATUS fnNtReadVirtualMemory(
		HANDLE ProcessHandle,
		PVOID BaseAddress,
		PVOID Buffer,
		SIZE_T NumberOfBytesToRead,
		PSIZE_T NumberOfBytesRead
	);

	NTSTATUS fnNtAllocateVirtualMemory(
		HANDLE ProcessHandle,
		PVOID* BaseAddress,
		ULONG_PTR ZeroBits,
		PSIZE_T RegionSize,
		ULONG AllocationType,
		ULONG Protect
	);

	NTSTATUS fnNtQueryAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes, PFILE_BASIC_INFORMATION FileInformation);
}

#define CREATE_API(func) typedef decltype(func) *func##_t; func##_t func
#define ASSIGN_API(func, dll) if(!(api::func = reinterpret_cast<api::func##_t>(api::func_get_addr(zxc(#func), api::peb_get_module(zxc(dll)))))) return 1

PVOID RtlAllocateHeap(PVOID HeapHandle, ULONG Flags, SIZE_T Size) { return 0; }
BOOLEAN RtlFreeHeap(HANDLE HeapHandle, ULONG Flags, PVOID P) { return 0; }
PVOID RtlCreateHeap(ULONG Flags, PVOID BaseAddress, SIZE_T SizeToReserve, SIZE_T SizeToCommit, PVOID Lock, /*PRTL_HEAP_PARAMETERS*/ PVOID Parameters) { return 0; }

namespace api
{
	CREATE_API(LoadLibraryW);
	CREATE_API(RtlFreeHeap);
	CREATE_API(RtlCreateHeap);
	CREATE_API(RtlAllocateHeap);
	CREATE_API(CreateFileA);
	CREATE_API(MultiByteToWideChar);
	CREATE_API(CreateRemoteThread);

	void* func_get_addr(const char* fname, PVOID base)
	{
		unsigned char shellcode[] = {
			/*00007FF6344F1000*/  0x48, 0x89, 0x5C, 0x24, 0x08,                         // mov qword ptr [rsp+8],rbx
			/*00007FF6344F1005*/  0x48, 0x89, 0x6C, 0x24, 0x10,                         // mov qword ptr [rsp+10h],rbp
			/*00007FF6344F100A*/  0x48, 0x89, 0x74, 0x24, 0x18,                         // mov qword ptr [rsp+18h],rsi
			/*00007FF6344F100F*/  0x48, 0x89, 0x7C, 0x24, 0x20,                         // mov qword ptr [rsp+20h],rdi
			/*00007FF6344F1014*/  0x4C, 0x8B, 0xDA,                                     // mov r11,rdx
			/*00007FF6344F1017*/  0x48, 0x8B, 0xD9,                                     // mov rbx,rcx
			/*00007FF6344F101A*/  0x48, 0x85, 0xD2,                                     // test rdx,rdx
			/*00007FF6344F101D*/  0x74, 0x7B,                                           // je 00007FF6344F109A
			/*00007FF6344F101F*/  0x48, 0x85, 0xC9,                                     // test rcx,rcx
			/*00007FF6344F1022*/  0x74, 0x76,                                           // je 00007FF6344F109A
			/*00007FF6344F1024*/  0x48, 0x63, 0x42, 0x3C,                               // movsxd rax,dword ptr [rdx+3Ch]
			/*00007FF6344F1028*/  0x45, 0x33, 0xC9,                                     // xor r9d,r9d
			/*00007FF6344F102B*/  0x44, 0x8B, 0x84, 0x10, 0x88, 0x00, 0x00, 0x00,       // mov r8d,dword ptr [rax+rdx+0000000000000088h]
			/*00007FF6344F1033*/  0x4C, 0x03, 0xC2,                                     // add r8,rdx
			/*00007FF6344F1036*/  0x41, 0x8B, 0x70, 0x1C,                               // mov esi,dword ptr [r8+1Ch]
			/*00007FF6344F103A*/  0x45, 0x8B, 0x50, 0x20,                               // mov r10d,dword ptr [r8+20h]
			/*00007FF6344F103E*/  0x48, 0x03, 0xF2,                                     // add rsi,rdx
			/*00007FF6344F1041*/  0x41, 0x8B, 0x68, 0x24,                               // mov ebp,dword ptr [r8+24h]
			/*00007FF6344F1045*/  0x4C, 0x03, 0xD2,                                     // add r10,rdx
			/*00007FF6344F1048*/  0x41, 0x8B, 0x78, 0x18,                               // mov edi,dword ptr [r8+18h]
			/*00007FF6344F104C*/  0x48, 0x03, 0xEA,                                     // add rbp,rdx
			/*00007FF6344F104F*/  0x85, 0xFF,                                           // test edi,edi
			/*00007FF6344F1051*/  0x74, 0x47,                                           // je 00007FF6344F109A
			/*00007FF6344F1053*/  0x44, 0x0F, 0xB6, 0x01,                               // movzx r8d,byte ptr [rcx]
			/*00007FF6344F1057*/  0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, // nop word ptr [rax+rax+0000000000000000h]
			/*00007FF6344F1060*/  0x41, 0x8B, 0x02,                                     // mov eax,dword ptr [r10]
			/*00007FF6344F1063*/  0x48, 0x8B, 0xD3,                                     // mov rdx,rbx
			/*00007FF6344F1066*/  0x49, 0x03, 0xC3,                                     // add rax,r11
			/*00007FF6344F1069*/  0x45, 0x84, 0xC0,                                     // test r8b,r8b
			/*00007FF6344F106C*/  0x74, 0x16,                                           // je 00007FF6344F1084
			/*00007FF6344F106E*/  0x41, 0x0F, 0xB6, 0xC8,                               // movzx ecx,r8b
			/*00007FF6344F1072*/  0x3A, 0x08,                                           // cmp cl,byte ptr [rax]
			/*00007FF6344F1074*/  0x75, 0x0E,                                           // jne 00007FF6344F1084
			/*00007FF6344F1076*/  0x0F, 0xB6, 0x4A, 0x01,                               // movzx ecx,byte ptr [rdx+1]
			/*00007FF6344F107A*/  0x48, 0xFF, 0xC2,                                     // inc rdx
			/*00007FF6344F107D*/  0x48, 0xFF, 0xC0,                                     // inc rax
			/*00007FF6344F1080*/  0x84, 0xC9,                                           // test cl,cl
			/*00007FF6344F1082*/  0x75, 0xEE,                                           // jne 00007FF6344F1072
			/*00007FF6344F1084*/  0x0F, 0xB6, 0x12,                                     // movzx edx,byte ptr [rdx]
			/*00007FF6344F1087*/  0x0F, 0xB6, 0x08,                                     // movzx ecx,byte ptr [rax]
			/*00007FF6344F108A*/  0x3B, 0xD1,                                           // cmp edx,ecx
			/*00007FF6344F108C*/  0x74, 0x23,                                           // je 00007FF6344F10B1
			/*00007FF6344F108E*/  0x41, 0xFF, 0xC1,                                     // inc r9d
			/*00007FF6344F1091*/  0x49, 0x83, 0xC2, 0x04,                               // add r10,4
			/*00007FF6344F1095*/  0x44, 0x3B, 0xCF,                                     // cmp r9d,edi
			/*00007FF6344F1098*/  0x72, 0xC6,                                           // jb 00007FF6344F1060
			/*00007FF6344F109A*/  0x33, 0xC0,                                           // xor eax,eax
			/*00007FF6344F109C*/  0x48, 0x8B, 0x5C, 0x24, 0x08,                         // mov rbx,qword ptr [rsp+8]
			/*00007FF6344F10A1*/  0x48, 0x8B, 0x6C, 0x24, 0x10,                         // mov rbp,qword ptr [rsp+10h]
			/*00007FF6344F10A6*/  0x48, 0x8B, 0x74, 0x24, 0x18,                         // mov rsi,qword ptr [rsp+18h]
			/*00007FF6344F10AB*/  0x48, 0x8B, 0x7C, 0x24, 0x20,                         // mov rdi,qword ptr [rsp+20h]
			/*00007FF6344F10B0*/  0xC3,                                                 // ret
			/*00007FF6344F10B1*/  0x42, 0x0F, 0xB7, 0x4C, 0x4D, 0x00,                   // movzx ecx,word ptr [rbp+r9*2]
			/*00007FF6344F10B7*/  0x8B, 0x04, 0x8E,                                     // mov eax,dword ptr [rsi+rcx*4]
			/*00007FF6344F10BA*/  0x49, 0x03, 0xC3,                                     // add rax,r11
			/*00007FF6344F10BD*/  0xEB, 0xDD,                                           // jmp 00007FF6344F109C
		};

		if (!fname || !base)
			return 0;

		SIZE_T size = sizeof(shellcode);

		PVOID exec_mem{};
		SIZE_T psize = size;
		if (!NT_SUCCESS(fnNtAllocateVirtualMemory((HANDLE)-1LL, &exec_mem, 0, &psize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
			return nullptr;

		memcpy(exec_mem, shellcode, size);

		void* result = reinterpret_cast<void* (__fastcall*)(const char*, void*)>(exec_mem)(fname, base);

		memset(shellcode, 0, size);
		memset(exec_mem, 0, size);

		fnNtFreeVirtualMemory((HANDLE)-1LL, &exec_mem, &psize, MEM_RELEASE);

		return result;
	}

	static void* peb_get_module(const wchar_t* dname)
	{
		unsigned char shellcode[] = {
			/*00007FF7C3EF1220*/  0x40, 0x53,                                           // push rbx
			/*00007FF7C3EF1222*/  0x48, 0x83, 0xEC, 0x20,                               // sub rsp,20h
			/*00007FF7C3EF1226*/  0x48, 0x8B, 0xD9,                                     // mov rbx,rcx
			/*00007FF7C3EF1229*/  0x48, 0x85, 0xC9,                                     // test rcx,rcx
			/*00007FF7C3EF122C*/  0x0F, 0x84, 0x40, 0x01, 0x00, 0x00,                   // je peb_get_module+152h (07FF7C3EF1372h)
			/*00007FF7C3EF1232*/  0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, // mov rax,qword ptr gs:[60h]
			/*00007FF7C3EF123B*/  0x48, 0x85, 0xC0,                                     // test rax,rax
			/*00007FF7C3EF123E*/  0x0F, 0x84, 0x2E, 0x01, 0x00, 0x00,                   // je peb_get_module+152h (07FF7C3EF1372h)
			/*00007FF7C3EF1244*/  0x48, 0x8B, 0x48, 0x18,                               // mov rcx,qword ptr [rax+18h]
			/*00007FF7C3EF1248*/  0x48, 0x85, 0xC9,                                     // test rcx,rcx
			/*00007FF7C3EF124B*/  0x0F, 0x84, 0x21, 0x01, 0x00, 0x00,                   // je peb_get_module+152h (07FF7C3EF1372h)
			/*00007FF7C3EF1251*/  0x48, 0x89, 0x74, 0x24, 0x30,                         // mov qword ptr [rsp+30h],rsi
			/*00007FF7C3EF1256*/  0x48, 0x8D, 0x71, 0x20,                               // lea rsi,[rcx+20h]
			/*00007FF7C3EF125A*/  0x48, 0x89, 0x7C, 0x24, 0x38,                         // mov qword ptr [rsp+38h],rdi
			/*00007FF7C3EF125F*/  0x48, 0x8B, 0x3E,                                     // mov rdi,qword ptr [rsi]
			/*00007FF7C3EF1262*/  0x48, 0x3B, 0xFE,                                     // cmp rdi,rsi
			/*00007FF7C3EF1265*/  0x0F, 0x84, 0xC3, 0x00, 0x00, 0x00,                   // je peb_get_module+10Eh (07FF7C3EF132Eh)
			/*00007FF7C3EF126B*/  0x0F, 0x1F, 0x44, 0x00, 0x00,                         // nop dword ptr [rax+rax]
			/*00007FF7C3EF1270*/  0x4C, 0x8B, 0x4F, 0x40,                               // mov r9,qword ptr [rdi+40h]
			/*00007FF7C3EF1274*/  0x4D, 0x85, 0xC9,                                     // test r9,r9
			/*00007FF7C3EF1277*/  0x0F, 0x84, 0xA5, 0x00, 0x00, 0x00,                   // je peb_get_module+102h (07FF7C3EF1322h)
			/*00007FF7C3EF127D*/  0x41, 0x0F, 0xB7, 0x09,                               // movzx ecx,word ptr [r9]
			/*00007FF7C3EF1281*/  0x45, 0x33, 0xD2,                                     // xor r10d,r10d
			/*00007FF7C3EF1284*/  0x66, 0x85, 0xC9,                                     // test cx,cx
			/*00007FF7C3EF1287*/  0x74, 0x38,                                           // je peb_get_module+0A1h (07FF7C3EF12C1h)
			/*00007FF7C3EF1289*/  0x4D, 0x8B, 0xD9,                                     // mov r11,r9
			/*00007FF7C3EF128C*/  0x0F, 0x1F, 0x40, 0x00,                               // nop dword ptr [rax]
			/*00007FF7C3EF1290*/  0x44, 0x0F, 0xB6, 0xC1,                               // movzx r8d,cl
			/*00007FF7C3EF1294*/  0x4D, 0x8D, 0x52, 0x01,                               // lea r10,[r10+1]
			/*00007FF7C3EF1298*/  0x41, 0x8D, 0x40, 0x20,                               // lea eax,[r8+20h]
			/*00007FF7C3EF129C*/  0x0F, 0xB6, 0xC8,                                     // movzx ecx,al
			/*00007FF7C3EF129F*/  0x41, 0x8D, 0x50, 0xBF,                               // lea edx,[r8-41h]
			/*00007FF7C3EF12A3*/  0x80, 0xFA, 0x19,                                     // cmp dl,19h
			/*00007FF7C3EF12A6*/  0x41, 0x0F, 0x47, 0xC8,                               // cmova ecx,r8d
			/*00007FF7C3EF12AA*/  0x0F, 0xBE, 0xC1,                                     // movsx eax,cl
			/*00007FF7C3EF12AD*/  0x66, 0x41, 0x89, 0x03,                               // mov word ptr [r11],ax
			/*00007FF7C3EF12B1*/  0x4F, 0x8D, 0x1C, 0x51,                               // lea r11,[r9+r10*2]
			/*00007FF7C3EF12B5*/  0x41, 0x0F, 0xB7, 0x03,                               // movzx eax,word ptr [r11]
			/*00007FF7C3EF12B9*/  0x0F, 0xB6, 0xC8,                                     // movzx ecx,al
			/*00007FF7C3EF12BC*/  0x66, 0x85, 0xC0,                                     // test ax,ax
			/*00007FF7C3EF12BF*/  0x75, 0xCF,                                           // jne peb_get_module+70h (07FF7C3EF1290h)
			/*00007FF7C3EF12C1*/  0x44, 0x0F, 0xB7, 0x03,                               // movzx r8d,word ptr [rbx]
			/*00007FF7C3EF12C5*/  0x66, 0x45, 0x85, 0xC0,                               // test r8w,r8w
			/*00007FF7C3EF12C9*/  0x0F, 0x84, 0x8F, 0x00, 0x00, 0x00,                   // je peb_get_module+13Eh (07FF7C3EF135Eh)
			/*00007FF7C3EF12CF*/  0x41, 0x0F, 0xB7, 0x01,                               // movzx eax,word ptr [r9]
			/*00007FF7C3EF12D3*/  0x66, 0x85, 0xC0,                                     // test ax,ax
			/*00007FF7C3EF12D6*/  0x74, 0x4A,                                           // je peb_get_module+102h (07FF7C3EF1322h)
			/*00007FF7C3EF12D8*/  0x66, 0x41, 0x3B, 0xC0,                               // cmp ax,r8w
			/*00007FF7C3EF12DC*/  0x75, 0x2F,                                           // jne peb_get_module+0EDh (07FF7C3EF130Dh)
			/*00007FF7C3EF12DE*/  0x66, 0x41, 0x83, 0x39, 0x00,                         // cmp word ptr [r9],0
			/*00007FF7C3EF12E3*/  0x48, 0x8B, 0xC3,                                     // mov rax,rbx
			/*00007FF7C3EF12E6*/  0x74, 0x1F,                                           // je peb_get_module+0E7h (07FF7C3EF1307h)
			/*00007FF7C3EF12E8*/  0x0F, 0xB7, 0x10,                                     // movzx edx,word ptr [rax]
			/*00007FF7C3EF12EB*/  0x66, 0x85, 0xD2,                                     // test dx,dx
			/*00007FF7C3EF12EE*/  0x74, 0x2D,                                           // je peb_get_module+0FDh (07FF7C3EF131Dh)
			/*00007FF7C3EF12F0*/  0x49, 0x8B, 0xC9,                                     // mov rcx,r9
			/*00007FF7C3EF12F3*/  0x48, 0x2B, 0xCB,                                     // sub rcx,rbx
			/*00007FF7C3EF12F6*/  0x66, 0x39, 0x14, 0x01,                               // cmp word ptr [rcx+rax],dx
			/*00007FF7C3EF12FA*/  0x75, 0x0B,                                           // jne peb_get_module+0E7h (07FF7C3EF1307h)
			/*00007FF7C3EF12FC*/  0x48, 0x83, 0xC0, 0x02,                               // add rax,2
			/*00007FF7C3EF1300*/  0x66, 0x83, 0x3C, 0x01, 0x00,                         // cmp word ptr [rcx+rax],0
			/*00007FF7C3EF1305*/  0x75, 0xE1,                                           // jne peb_get_module+0C8h (07FF7C3EF12E8h)
			/*00007FF7C3EF1307*/  0x66, 0x83, 0x38, 0x00,                               // cmp word ptr [rax],0
			/*00007FF7C3EF130B*/  0x74, 0x10,                                           // je peb_get_module+0FDh (07FF7C3EF131Dh)
			/*00007FF7C3EF130D*/  0x41, 0x0F, 0xB7, 0x41, 0x02,                         // movzx eax,word ptr [r9+2]
			/*00007FF7C3EF1312*/  0x49, 0x83, 0xC1, 0x02,                               // add r9,2
			/*00007FF7C3EF1316*/  0x66, 0x85, 0xC0,                                     // test ax,ax
			/*00007FF7C3EF1319*/  0x75, 0xBD,                                           // jne peb_get_module+0B8h (07FF7C3EF12D8h)
			/*00007FF7C3EF131B*/  0xEB, 0x05,                                           // jmp peb_get_module+102h (07FF7C3EF1322h)
			/*00007FF7C3EF131D*/  0x4D, 0x85, 0xC9,                                     // test r9,r9
			/*00007FF7C3EF1320*/  0x75, 0x3C,                                           // jne peb_get_module+13Eh (07FF7C3EF135Eh)
			/*00007FF7C3EF1322*/  0x48, 0x8B, 0x3F,                                     // mov rdi,qword ptr [rdi]
			/*00007FF7C3EF1325*/  0x48, 0x3B, 0xFE,                                     // cmp rdi,rsi
			/*00007FF7C3EF1328*/  0x0F, 0x85, 0x42, 0xFF, 0xFF, 0xFF,                   // jne peb_get_module+50h (07FF7C3EF1270h)
			/*00007FF7C3EF132E*/  0x48, 0x8D, 0x0D, 0xE3, 0x0C, 0x00, 0x00,             // lea rcx,[string L"kernel32.dll" (07FF7C3EF2018h)]
			/*00007FF7C3EF1335*/  0xE8, 0xE6, 0xFE, 0xFF, 0xFF,                         // call peb_get_module (07FF7C3EF1220h)
			/*00007FF7C3EF133A*/  0x48, 0x8B, 0xD0,                                     // mov rdx,rax
			/*00007FF7C3EF133D*/  0x48, 0x8D, 0x0D, 0xF4, 0x0C, 0x00, 0x00,             // lea rcx,[string "LoadLibraryW" (07FF7C3EF2038h)]
			/*00007FF7C3EF1344*/  0xE8, 0xB7, 0xFC, 0xFF, 0xFF,                         // call func_get_addr (07FF7C3EF1000h)
			/*00007FF7C3EF1349*/  0x48, 0x8B, 0xCB,                                     // mov rcx,rbx
			/*00007FF7C3EF134C*/  0x48, 0x8B, 0x74, 0x24, 0x30,                         // mov rsi,qword ptr [rsp+30h]
			/*00007FF7C3EF1351*/  0x48, 0x8B, 0x7C, 0x24, 0x38,                         // mov rdi,qword ptr [rsp+38h]
			/*00007FF7C3EF1356*/  0x48, 0x83, 0xC4, 0x20,                               // add rsp,20h
			/*00007FF7C3EF135A*/  0x5B,                                                 // pop rbx
			/*00007FF7C3EF135B*/  0x48, 0xFF, 0xE0,                                     // jmp rax
			/*00007FF7C3EF135E*/  0x48, 0x8B, 0x47, 0x20,                               // mov rax,qword ptr [rdi+20h]
			/*00007FF7C3EF1362*/  0x48, 0x8B, 0x7C, 0x24, 0x38,                         // mov rdi,qword ptr [rsp+38h]
			/*00007FF7C3EF1367*/  0x48, 0x8B, 0x74, 0x24, 0x30,                         // mov rsi,qword ptr [rsp+30h]
			/*00007FF7C3EF136C*/  0x48, 0x83, 0xC4, 0x20,                               // add rsp,20h
			/*00007FF7C3EF1370*/  0x5B,                                                 // pop rbx
			/*00007FF7C3EF1371*/  0xC3,                                                 // ret
			/*00007FF7C3EF1372*/  0x33, 0xC0,                                           // xor eax,eax
			/*00007FF7C3EF1374*/  0x48, 0x83, 0xC4, 0x20,                               // add rsp,20h
			/*00007FF7C3EF1378*/  0x5B,                                                 // pop rbx
			/*00007FF7C3EF1379*/  0xC3,                                                 // ret
		};

		if (!dname) return nullptr;

		const char str1[] = {
			0x6B, 0x00, 0x65, 0x00, 0x72, 0x00, 0x6E, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x33,
			0x00, 0x32, 0x00, 0x2E, 0x00, 0x64, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x00, 0x00
		}; // L"kernel32.dll"

		const char str2[] = {
			0x4C, 0x6F, 0x61, 0x64, 0x4C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x57, 0x00
		}; // "LoadLibraryW"

		unsigned char trampolinecode[] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };

		size_t total_size = sizeof(trampolinecode) * 2 + sizeof(str1) + sizeof(str2) + sizeof(shellcode);

		PVOID exec_mem{};
		SIZE_T psize = total_size;
		if (!NT_SUCCESS(fnNtAllocateVirtualMemory((HANDLE)-1LL, &exec_mem, 0, &psize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
			return nullptr;

		memset(exec_mem, 0, total_size);

		uint64_t base_addr = (uint64_t)exec_mem;
		unsigned char* ptr = (unsigned char*)exec_mem;
		uint64_t addr_str1 = 0, addr_str2 = 0, tmp_pos1 = 0, tmp_pos2 = 0;

		memcpy(ptr, str1, sizeof(str1)); addr_str1 = (uint64_t)ptr; ptr += sizeof(str1);
		memcpy(ptr, str2, sizeof(str2)); addr_str2 = (uint64_t)ptr; ptr += sizeof(str2);

		void* pfunc = &peb_get_module;
		memcpy(&trampolinecode[2], &pfunc, sizeof(pfunc));
		memcpy(ptr, trampolinecode, sizeof(trampolinecode)); tmp_pos1 = (uint64_t)ptr; ptr += sizeof(trampolinecode);

		pfunc = &func_get_addr;
		memcpy(&trampolinecode[2], &pfunc, sizeof(pfunc));
		memcpy(ptr, trampolinecode, sizeof(trampolinecode)); tmp_pos2 = (uint64_t)ptr; ptr += sizeof(trampolinecode);

		uint64_t tmp_size = sizeof(trampolinecode) * 2 + sizeof(str1) + sizeof(str2);
		uint64_t rva1 = tmp_pos1 - base_addr - (tmp_size + 277 + 5);
		uint64_t rva2 = tmp_pos2 - base_addr - (tmp_size + 292 + 5);
		memcpy(&shellcode[277 + 1], &rva1, 4);
		memcpy(&shellcode[292 + 1], &rva2, 4);

		uint64_t offset_str1 = addr_str1 - (base_addr + tmp_size + 270) - 7;
		uint64_t offset_str2 = addr_str2 - (base_addr + tmp_size + 285) - 7;
		memcpy(&shellcode[273], &offset_str1, sizeof(uint32_t));
		memcpy(&shellcode[288], &offset_str2, sizeof(uint32_t));

		memcpy(ptr, shellcode, sizeof(shellcode));

		void* result = reinterpret_cast<void* (__fastcall*)(const wchar_t*)>((uint64_t)exec_mem + (total_size - sizeof(shellcode)))(dname);

		memset(shellcode, 0, sizeof(shellcode));
		memset(exec_mem, 0, total_size);

		fnNtFreeVirtualMemory((HANDLE)-1LL, &exec_mem, &psize, MEM_RELEASE);

		return result;
	}

	static HANDLE g_heap;

#pragma function(free)
	void free(void* _Block)
	{
		if (_Block && g_heap) api::RtlFreeHeap(g_heap, 0, _Block);
	}

#pragma function(malloc)
	void* malloc(size_t _Size)
	{
		if (!g_heap) if (!(g_heap = api::RtlCreateHeap(HEAP_CREATE_ENABLE_EXECUTE, 0, 0, 0, 0, 0))) { g_heap = 0; return 0; }

		void* ptr = RtlAllocateHeap(g_heap, 0, _Size);
		return ptr ? ptr : 0;
	}

	//#define PRINT_COOL
#ifndef PRINT_COOL
	CREATE_API(__stdio_common_vfprintf);
	CREATE_API(__acrt_iob_func);
#endif
	__declspec(noinline) [[maybe_unused]] void printf(char const* _Format, ...)
	{
#ifndef PRINT_COOL
		if (api::__stdio_common_vfprintf && api::__acrt_iob_func)
		{
			char* _ArgList = (char*)(&_Format + ((sizeof(_Format) + sizeof(int) - 1) & ~(sizeof(int) - 1))); // va_start
			api::__stdio_common_vfprintf(0, api::__acrt_iob_func(1), _Format, 0, _ArgList);
		}
#endif
	}
}

#endif