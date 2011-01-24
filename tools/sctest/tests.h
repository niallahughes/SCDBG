#include <stdint.h>

struct instr_test
{
	const char *instr;

	char  *code;
	uint16_t codesize;

	struct 
	{
		uint32_t reg[8];
		uint32_t        mem_state[2];
		uint32_t    eflags;
	} in_state;

	struct 
	{
		uint32_t reg[8];
		uint32_t        mem_state[2];
		uint32_t    eflags;
		uint32_t eip;
	} out_state;
};

#define FLAG(fl) (1 << (fl))

struct export_addresses
{
	char 		*fnname;
	uint32_t 	virtualaddr;
};

struct export_addresses dll_exports[] = 
{
	{"", 0},
	{"kernel32 base", 0x7C800000},
	{"ws2_32 base", 0x71A10000},
	{"urlmon base", 0x7DF20000},
	{"CopyFileA", 0x7C8286EE},
	{"CopyFileExA", 0x7C85E3C4},
	{"CopyFileExW", 0x7C827B32},
	{"CopyFileW", 0x7C82F873},
	{"CreateDirectoryA", 0x7C8217AC},
	{"CreateDirectoryExA", 0x7C85B23B},
	{"CreateDirectoryExW", 0x7C85A5F2},
	{"CreateDirectoryW", 0x7C8323D2},
	{"CreateFileA", 0x7C801A24},
	{"CreateFileW", 0x7C810760},
	{"CreateProcessA", 0x7C802367},
	{"CreateProcessInternalA", 0x7C81DDD6},
	{"CreateProcessInternalW", 0x7C819513},
	{"CreateProcessW", 0x7C802332},
	{"CreateRemoteThread", 0x7C81042C},
	{"CreateToolhelp32Snapshot", 0x7C864B47},
	{"DeleteFileA", 0x7C831EAB },
	{"DeleteFileW", 0x7C831F31},
	{"ExitProcess", 0x7C81CDDA},
	{"ExitThread", 0x7C80C058},
	{"FindFirstFileA", 0x7C8137D9},
	{"FindFirstFileExA", 0x7C85C512},
	{"FindFirstFileExW", 0x7C80EA7D},
	{"FindFirstFileW", 0x7C80EEE1},
	{"FindNextFileA", 0x7C834EB1},
	{"FindNextFileW", 0x7C80EF3A},
	{"GetProcAddress", 0x7C80ADA0},
	{"LoadLibraryA", 0x7C801D77},
	{"LoadLibraryExA", 0x7C801D4F},
	{"LoadLibraryExW", 0x7C801AF1},
	{"LoadLibraryW", 0x7C80AE4B},
	{"OpenFile", 0x7C821982},
	{"ReadFile", 0x7C80180E},
	{"ReadFileEx", 0x7C82BCFB},
	{"ReadProcessMemory", 0x7C8021CC},
	{"WinExec", 0x7C86136D},
	{"WriteFile", 0x7C810D87},
	{"WriteFileEx", 0x7C85C701},
	{"_hwrite", 0x7C838AE7},
	{"_lclose", 0x7C834E64},
	{"_lcreat", 0x7C8365A5},
	{"_lopen", 0x7C85E830},
	{"_lread", 0x7C8353CE},
	{"_lwrite", 0x7C838AE7},
	{"lstrcat", 0x7C834D41},
	{"lstrcatA", 0x7C834D41},
	{"lstrcpy", 0x7C80BE01},
	{"lstrcpyA", 0x7C80BE01},
	{"lstrcpyW", 0x7C80BA64},
	{"accept", 0x71A21028},
	{"bind", 0x71A13E00},
	{"closesocket", 0x71A19639},
	{"connect", 0x71A1406A},
	{"inet_addr", 0x71A12BF4},
	{"inet_ntoa", 0x71A13F41},
	{"listen", 0x71A188D3},
	{"recv", 0x71A1615A},
	{"send", 0x71A1428A},
	{"sendto", 0x71A12C69},
	{"socket", 0x71A13B91},
	{"WSAConnect", 0x71A20C69},
	{"gethostbyaddr", 0x71A1E479},
	{"gethostbyname", 0x71A14FD4},
	{"gethostname", 0x71A150C8},
	{"WSARecv", 0x71A14318},
	{"WSASend", 0x71A16233},
	{"WSASocketA", 0x71A18769},
	{ "URLDownloadA", 0x7DF4F0DD},
	{ "URLDownloadToCacheFileA", 0x7DF7B1C1},
	{ "URLDownloadToCacheFileW", 0x7DF7ADA4},
	{ "URLDownloadToFileA", 0x7DF7B0BB},
	{ "URLDownloadToFileW", 0x7DF7AD3E},
	{ "", 0},
};
