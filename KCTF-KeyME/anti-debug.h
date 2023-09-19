#pragma once

#include "stdafx.h"
#include <windows.h>
#include <process.h>
#include <TlHelp32.h>
#include <winternl.h>

#pragma comment(lib,"ntdll.lib")

/*
bool CheckDebug_API() {
PBYTE pCC = (PBYTE)MessageBoxW;
if (*pCC == 0xCC)
{
return true;
}
return false;
}



bool CheckDebug() {
bool bDebugged = false;
__asm {
MOV EAX, DWORD PTR FS : [0x30]
MOV AL, BYTE PTR DS : [EAX + 2]
MOV bDebugged, AL
}
return bDebugged;
}
*/


bool CheckDebug_EnumProcess() {
	PROCESSENTRY32 pe32 = { sizeof(pe32) };
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	Process32First(hProcessSnap, &pe32);
	do
	{
		// 这里只比较了OllyDbg,也可以添加其他的调试分析工具名
		if (_tcsicmp(pe32.szExeFile, TEXT("OllyDbg.exe")) == 0)
		{
			CloseHandle(hProcessSnap);
			return TRUE;
		}

		if (_tcsicmp(pe32.szExeFile, TEXT("x32dbg.exe")) == 0)
		{
			CloseHandle(hProcessSnap);
			return TRUE;
		}

		if (_tcsicmp(pe32.szExeFile, TEXT("x64dbg.exe")) == 0)
		{
			CloseHandle(hProcessSnap);
			return TRUE;
		}

		if (_tcsicmp(pe32.szExeFile, TEXT("ida.exe")) == 0)
		{
			CloseHandle(hProcessSnap);
			return TRUE;
		}

		if (_tcsicmp(pe32.szExeFile, TEXT("ida64.exe")) == 0)
		{
			CloseHandle(hProcessSnap);
			return TRUE;
		}
	} while (Process32Next(hProcessSnap, &pe32));
	CloseHandle(hProcessSnap);
	return FALSE;
}



bool CheckDebug_Explorer() {
	struct PROCESS_BASIC_INFORMATION
	{
		DWORD ExitStatus;
		DWORD PebBaseAddress;
		DWORD AffinityMask;
		DWORD BasePriority;
		ULONG UniqueProcessId;
		ULONG InheritedFromUniqueProcessId;
	}pbi = {};
	NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, (PVOID)&pbi, sizeof(pbi), NULL);
	PROCESSENTRY32 pe32 = { sizeof(pe32) };
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	Process32First(hProcessSnap, &pe32);
	do
	{
		if (pbi.InheritedFromUniqueProcessId == pe32.th32ProcessID)
		{
			if (_tcsicmp(pe32.szExeFile, TEXT("explorer.exe")) == 0)
			{
				CloseHandle(hProcessSnap);
				return FALSE;
			}
			else
			{
				CloseHandle(hProcessSnap);
				return TRUE;
			}
		}
	} while (Process32Next(hProcessSnap, &pe32));
	CloseHandle(hProcessSnap);
	return FALSE;
}

/*
bool CheckDebug_HB()
{
CONTEXT context;
HANDLE hThread = GetCurrentThread();
context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
GetThreadContext(hThread, &context);
if (context.Dr0 != 0 || context.Dr1 != 0 || context.Dr2 != 0 || context.Dr3 != 0)
{
return TRUE;
}
return FALSE;
}
*/

bool CheckDebug_INT_2D() {
	BOOL bDebugging = FALSE;
	__asm {
		// install SEH
		push handler
		push DWORD ptr fs : [0]
		mov DWORD ptr fs : [0], esp
		// OD会忽略0x2d和nop，继续向后执行
		// 这时候可以选择只是检测调试器还是跑飞
		int 0x2d
		nop
		mov bDebugging, 1
		jmp normal_code
		handler :
		mov eax, dword ptr ss : [esp + 0xc]
			mov dword ptr ds : [eax + 0xb8], offset normal_code
			mov bDebugging, 0
			xor eax, eax
			retn
			normal_code :
		//   remove SEH
		pop dword ptr fs : [0]
			add esp, 4
	}
	return bDebugging;
}

/*
bool CheckDebug_DebugHandle() {
DWORD dwDebugHandle = 0;
NtQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)0x1E, &dwDebugHandle, 4, 0);
return dwDebugHandle != 0;
}


bool CheckDebug_DebugPort() {
DWORD dwDebugPort = 0;
NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &dwDebugPort, 4, 0);
return dwDebugPort == -1;
}


// 时间检测
bool CheckDebug_QueryPerformanceCounter() {
LARGE_INTEGER startTime, endTime;
QueryPerformanceCounter(&startTime);
printf("我是核心代码\n也可以是核心代码前的反调试时间检测代码\n");
QueryPerformanceCounter(&endTime);
printf("%llx\n", endTime.QuadPart - startTime.QuadPart);
return endTime.QuadPart - startTime.QuadPart > 0x500;
}
*/