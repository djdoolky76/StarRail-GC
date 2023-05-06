#define _CRT_SECURE_NO_WARNINGS

#include "core.hpp"

namespace anti_cheat {
	typedef HANDLE(WINAPI* CREATE_FILE_W)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
	CREATE_FILE_W p_CreateFileW = nullptr;
	CREATE_FILE_W t_CreateFileW;

	HANDLE WINAPI h_CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
	{
		if (memcmp(lpFileName, L"\\\\.\\ACE-BASE", 24) == 0) {
			wprintf(L"Thread (%i) Attempting to communicate with ACE Anti-Cheat driver -> %s\n", GetCurrentThreadId(), lpFileName);

			SuspendThread(GetCurrentThread()); // 200iq bypass for memory protection
		}

		return p_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	}

	void Setup(uint64_t srbase) {
		if (MH_Initialize() != MH_OK)
		{
			puts("Error initializing MinHook library, Probaly game was updated.");

			return;
		}

		if (MH_CreateHookApiEx(L"kernelbase", "CreateFileW", &anti_cheat::h_CreateFileW, reinterpret_cast<void**>(&p_CreateFileW), reinterpret_cast<void**>(&t_CreateFileW)) != MH_OK)
		{
			puts("Error creating hook for CreateFileW function");

			return;
		}

		if (MH_EnableHook(t_CreateFileW) != MH_OK)
		{
			puts("Error enabling hook for CreateFileW function");

			return;
		}

		Utils::Write<uint32_t>(srbase + 0xFCDC0, 0xCCC3C031);
		Utils::Write<uint8_t>(srbase + 0xF9940, 0xC3);
		Utils::Write<uint16_t>(srbase + 0x1BCBA0, 0xFEEB);
	}
}

void Setup()
{
	system("cls");

	auto base_address = reinterpret_cast<uint64_t>(GetModuleHandleA("starrailbase.dll"));

	

	if (Utils::GetTextSectionChecksum(base_address) != 0x1434A1A0) {

		GlobalSetting::ChinaVersion = true;

		puts("[>] China game version detected\n[>] If you don't have the Chinese game version, Contact, djdoolky76#2023 @Discord ");
	}

	anti_cheat::Setup(base_address);

	Sleep(15000);

	if (!Direct3D.Initialization())
		puts("[-] Failed to initiate Direct3D!");
	else
	{
		puts("[+] DirectX 3D setup Initiated!");
		printf("[>] Direct3D Present: %p\n[>] Direct3D ResizeBuffers: %p\n", Direct3D.Present, Direct3D.ResizeBuffers);
	}
	if (!Device::Setup())
		puts("[-] Failed to Initiate Hooks setup!");
	else
		puts("[+] Hooks setup successfully, Happy Hacking!");
	    puts("[+] StarRail-GC Beta 1.0");
		puts("[+] Discord: https://discord.gg/anjocally");
		puts("[+] Credits: https://github.com/Z4ee/StarRail-S-GC");

	return Cheat::Main();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		AllocConsole();
		freopen("CONOUT$", "w", stdout);
		freopen("CONOUT$", "w", stderr);
		freopen("CONIN$", "r", stdin);
		CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Setup, 0, 0, 0);
	}
	return TRUE;
}