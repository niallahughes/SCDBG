
#define POP_DWORD(cpu, dst_p) \
{ int32_t ret = emu_memory_read_dword(cpu->mem, cpu->reg[esp], dst_p); \
if( ret != 0 ) \
	return ret; \
else \
	cpu->reg[esp] += 4; }


uint32_t user_hook_ExitProcess(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_ExitThread(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_CreateProcess(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_WaitForSingleObject(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_exit(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_accept(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_bind(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_closesocket(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_connect(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_fclose(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_fopen(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_fwrite(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_listen(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_recv(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_send(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_socket(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_WSASocket(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_CreateFile(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_WriteFile(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_CloseHandle(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_URLDownloadToFile(struct emu_env *env, struct emu_env_hook *hook, ...);

//added 1-20-11 - dzzie (req'd dll mod)
uint32_t user_hook_GetProcAddress(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_GetSystemDirectoryA(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_GetTickCount(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_LoadLibraryA(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook__lcreat(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook__lwrite(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook__lclose(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_malloc(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_memset(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_SetUnhandledExceptionFilter(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_WinExec(struct emu_env *env, struct emu_env_hook *hook, ...); //did not req dll mod

//added 1-21-11 dzzie when moved to latest dll
uint32_t user_hook_DeleteFileA(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_GetVersion(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_GetTempPath(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_Sleep(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_VirtualProtect(struct emu_env *env, struct emu_env_hook *hook, ...);

//1-22-11 - another dll mod to allow for user hooking of arbitrary functions
//int32_t	new_user_hook_closesocket(struct emu_env *env, struct emu_env_hook *hook);

int32_t	new_user_hook_GetModuleHandleA(struct emu_env *env, struct emu_env_hook *hook);
int32_t	new_user_hook_MessageBoxA(struct emu_env *env, struct emu_env_hook *hook);
int32_t	new_user_hook_ShellExecuteA(struct emu_env *env, struct emu_env_hook *hook);
int32_t	new_user_hook_SHGetSpecialFolderPathA(struct emu_env *env, struct emu_env_hook *hook);


