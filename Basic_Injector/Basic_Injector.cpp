#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

/* Get process ID of process
*  MSDN Tutorial - https://docs.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes
*/
DWORD GetProcId(const wchar_t* procName) {

	DWORD procId = 0;

	/* CreateToolhelp32Snapshot - Takes snapshot of specified processes.
	*  TH32CS_SNAPPROCESS - Include all processes in the system snapshot
	*/
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	// INVALID_HANDLE_VALUE - Error code for CreateToolhelp32Snapshot.
	if (hSnap != INVALID_HANDLE_VALUE) {

		// PROCESSENTRY32 - Describes entry in system process snapshot list (hSnap).
		PROCESSENTRY32 procEntry{};

		// Must set dwSize before calling Process32First.
		procEntry.dwSize = sizeof(procEntry);

		// Process32First - Retrieves information about frist process in system snapshot (hSnap).
		if (Process32First(hSnap, &procEntry)) {
			do {

				/* _wcsicmp - Lexicographical wide string case-insensitive compare.
				*  szExeFile - Name of executable file for the process.
				*/
				if (!_wcsicmp(procEntry.szExeFile, procName)) {

					// the32ProcessID - Process ID of process entry.
					procId = procEntry.th32ProcessID;
					break;
				}

				// Process32Next - Retrieves information about next process in system snapshot (hSnap).
			} while (Process32Next(hSnap, &procEntry));
		}
	}

	CloseHandle(hSnap);
	return procId;
}

int main() {

	const char* dllPath = "C:\\Users\\uttervitriol\\source\\repos\\AC_Internal_Hack_1_Follow_Along\\Debug\\AC_Internal_Hack_1.dll";
	const wchar_t* procName = L"ac_client.exe";
	DWORD procId = 0;

	while (!procId) {
		procId = GetProcId(procName);
		Sleep(30);
	}

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, procId);

	if (hProc && (hProc != INVALID_HANDLE_VALUE)) {

		void* loc = VirtualAllocEx(hProc, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		WriteProcessMemory(hProc, loc, dllPath, strlen(dllPath) + 1, 0);

		HANDLE hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, loc, 0, 0);

		if (hThread) {
			CloseHandle(hThread);
		}
	}

	if (hProc) {
		CloseHandle(hProc);
	}

	return 0;
}
