#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

/* Get process ID of process
*  MSDN Tutorial - https://docs.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes
*/
DWORD GetProcId(const wchar_t* procName) {

	DWORD procId = 0;

	/*	CreateToolhelp32Snapshot	- Takes snapshot of specified processes.
	*	TH32CS_SNAPPROCESS			- Include all processes in the system snapshot
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

				/*	_wcsicmp	- Lexicographical wide string case-insensitive compare.
				*	szExeFile	- Name of executable file for the process.
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
	// My understanding:

	/*	1. Get process ID.
	*	2. Get handle to process.
	*	3. Allocate space for path to hack DLL.
	*	4. Write hack DLL path to memory.
	*	5. Create thread in process that calls LoadLibraryA.
	*	6. LoadLibraryA loads DLL into memory.
	*	7. The system calls DLL's DllMain function.
	*	8. Profit.
	*/

	const char* dllPath = "C:\\Users\\uttervitriol\\source\\repos\\vagante\\vagante\\Release\\vagante.dll";
	const wchar_t* procName = L"vagante.exe";
	DWORD procId = 0;

	while (!procId) {
		procId = GetProcId(procName);
		Sleep(30);
	}

	// OpenProcess - Get handle to open process.
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, procId);

	if (hProc && (hProc != INVALID_HANDLE_VALUE)) {

		/*	VirtualAllocEx	- Reserves, commits or changes the state of a region of memory within address space of specified process.
		*	MEM_COMMIT		- Allocates memory charges? Physical pages are not actually allocated until the addresses are accessed. 
		*	MEM_RESERVE		- Reserves a range pof process's virtual address space without allocating any physical storage. 
		*
		*	PAGE_READWRITE	- Enables execution, read-only or read/write access to the committed region of pages.
		*/
		void* loc = VirtualAllocEx(hProc, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		SIZE_T bWritten = 0;
		WriteProcessMemory(hProc, loc, dllPath, strlen(dllPath) + 1, &bWritten);

		/*	CreateRemoteThread	- Creates thread that runs in the virtual address space of another process
		*	LoadLibraryA		- Loads the specified module into the address space of the calling process. 
		* 
		*	loc					- Address of memory where DLL path resides.
		*/
		HANDLE hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, loc, 0, 0);

		// Close handle to thread if success.
		if (hThread) {
			CloseHandle(hThread);
		}
	}

	// Close handle to process if success.
	if (hProc) {
		CloseHandle(hProc);
	}

	return 0;
}
