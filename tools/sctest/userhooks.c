/********************************************************************************
 *                               libemu
 *
 *                    - x86 shellcode emulation -
 *
 *
 * Copyright (C) 2007  Paul Baecher & Markus Koetter
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 * 
 * 
 *             contact nepenthesdev@users.sourceforge.net  
 *
 *******************************************************************************/


#include "../config.h"

#define HAVE_GETOPT_H
#ifdef HAVE_GETOPT_H
# include <getopt.h>
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif


#include <stdint.h>

#define HAVE_UNISTD
#ifdef HAVE_UNISTD
# include <unistd.h>
#endif
#include <stdio.h>

#include <stdarg.h>


#include <errno.h>
#include <sys/select.h>

#include <sys/wait.h>

#ifdef HAVE_LIBCARGOS
#include <cargos-lib.h>
#endif


#include <sys/types.h>
#include <sys/socket.h>  

#include "emu/emu.h"
#include "emu/emu_memory.h"
#include "emu/emu_cpu.h"
#include "emu/emu_log.h"
#include "emu/emu_cpu_data.h"
#include "emu/emu_cpu_stack.h"
#include "emu/environment/emu_profile.h"
#include "emu/environment/emu_env.h"
#include "emu/environment/win32/emu_env_w32.h"
#include "emu/environment/win32/emu_env_w32_dll.h"
#include "emu/environment/win32/emu_env_w32_dll_export.h"
#include "emu/environment/win32/env_w32_dll_export_kernel32_hooks.h"
#include "emu/environment/linux/emu_env_linux.h"
#include "emu/emu_getpc.h"
#include "emu/emu_graph.h"
#include "emu/emu_string.h"
#include "emu/emu_hashtable.h"
#include "emu/emu_shellcode.h"
#include "userhooks.h"
#include "options.h"
#include "nanny.h"

#include <stdint.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>

extern int CODE_OFFSET;
extern uint32_t FS_SEGMENT_DEFAULT_OFFSET;
extern void hexdump(unsigned char*, int);
extern int file_length(FILE *f);
extern void add_malloc(uint32_t, uint32_t);
extern struct emu_memory *mem;
extern struct emu_cpu *cpu;    //these two are global in main code
extern bool disable_mm_logging;
int last_GetSizeFHand = -44;
int rep_count=0;

uint32_t next_alloc = 0x60000; //these increment so we dont walk on old allocs

//by the time our user call is called, the args have already been popped off the stack.
//in r/t that just means that esp has been adjusted and cleaned up for function to 
//return, since there hasnt been any memory writes, we can still grab the return address
//off the stack if we know the arg sizes and calculate it with teh adjustment.
//little bit more work, but safe and doesnt require any otherwise sweeping changes
//to the dll - dzzie

uint32_t get_ret(struct emu_env *env, int arg_adjust){

	struct emu_memory *m = emu_memory_get(env->emu);
	uint32_t reg_esp = emu_cpu_reg32_get( emu_cpu_get(env->emu), esp);
	uint32_t ret_val = 0;
	
	emu_memory_read_dword( m, reg_esp+arg_adjust, &ret_val);
	
	if(opts.adjust_offsets){
		if( (ret_val > CODE_OFFSET) &&  (ret_val <= (CODE_OFFSET + opts.size)) ){
			return ret_val - CODE_OFFSET; //adjusted to file offset of input file
		}else{
			return ret_val; //return the raw value from stack
		}
	}else{
		return ret_val; //return the raw value from stack
	}

}

char* get_client_ip(struct sockaddr *clientInformation)
{	
	if (clientInformation->sa_family == AF_INET) {
		struct sockaddr_in *ipv4 = (struct sockaddr_in *)clientInformation;
		return inet_ntoa(ipv4->sin_addr);
	}
	return 0;
}

unsigned int get_client_port(struct sockaddr *clientInformation)
{
	unsigned int portNumber;
	if (clientInformation->sa_family == AF_INET) {
		struct sockaddr_in *ipv4 = (struct sockaddr_in *)clientInformation;
		portNumber = ntohs(ipv4->sin_port);
		return portNumber;
	}
	return 0;
}

void set_next_alloc(int size){  //space allocs at 0x1000 bytes for easy offset recgonition..
	add_malloc(next_alloc, size); //record current one for dumping if need be..
	if(size % 1000 == 0){
		size += 0x1000;
	}else{
		while( size % 0x1000 != 0) size++;
	}
	next_alloc += size;
	//printf("next_alloc=%x\n", next_alloc);
}

void GetSHFolderName(int id, char* buf255){
	
	switch(id){
		case 0:      strcpy(buf255, "./DESKTOP"); break;
		case 1:      strcpy(buf255, "./INTERNET");break;
		case 2:      strcpy(buf255, "./PROGRAMS");break;
		case 3:      strcpy(buf255, "./CONTROLS");break;
		case 4:      strcpy(buf255, "./PRINTERS");break;
		case 5:      strcpy(buf255, "./PERSONAL");break;
		case 6:      strcpy(buf255, "./FAVORITES");break;
		case 7:      strcpy(buf255, "./STARTUP");break;
		case 8:      strcpy(buf255, "./RECENT");break;
		case 9:      strcpy(buf255, "./SENDTO");break;
		case 0xA:    strcpy(buf255, "./BITBUCKET");break;
		case 0xB:    strcpy(buf255, "./STARTMENU");break;
		case 0x0010: strcpy(buf255, "./DESKTOPDIRECTORY");break;
		case 0x0011: strcpy(buf255, "./DRIVES"); break;
		case 0x0012: strcpy(buf255, "./NETWORK"); break;
		case 0x0013: strcpy(buf255, "./NETHOOD");break;
		case 0x0014: strcpy(buf255, "./FONTS");break;
		case 0x0015: strcpy(buf255, "./TEMPLATES");break;
		case 0x0016: strcpy(buf255, "./COMMON_STARTMENU");break;
		case 0x0017: strcpy(buf255, "./COMMON_PROGRAMS");break;
		case 0x0018: strcpy(buf255, "./COMMON_STARTUP");break;
		case 0x0019: strcpy(buf255, "./COMMON_DESKTOPDIRECTORY");break;
		case 0x001a: strcpy(buf255, "./APPDATA");break;
		case 0x001b: strcpy(buf255, "./PRINTHOOD");break;
		case 0x001d: strcpy(buf255, "./ALTSTARTUP");break;
		case 0x001e: strcpy(buf255, "./COMMON_ALTSTARTUP");break;
		case 0x001f: strcpy(buf255, "./COMMON_FAVORITES");break;
		case 0x0020: strcpy(buf255, "./INTERNET_CACHE");break;
		case 0x0021: strcpy(buf255, "./COOKIES");break;
		case 0x0022: strcpy(buf255, "./HISTORY");break;
		default: sprintf(buf255,"Unknown CSIDL: %x",id);
	}

}


// ------------------------ HOOKS BELOW HERE -------------------------------

uint32_t user_hook_ExitProcess(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	
	//printf("%s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);

	uint32_t retaddr = get_ret(env, -8);

/*
VOID WINAPI ExitProcess(
  UINT uExitCode
);
*/

	va_list vl;
	va_start(vl, hook);
	int exitcode = va_arg(vl,  int);
	va_end(vl);

	printf("%x\t%s(%i)\n", retaddr, hook->hook.win->fnname, exitcode);


	opts.steps = 0;
	return 0;
}


uint32_t user_hook_ExitThread(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	
	//printf("%s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);

	uint32_t retaddr = get_ret(env, -8);

	/* VOID ExitThread( DWORD dwExitCode ); */

	va_list vl;
	va_start(vl, hook);
	int exitcode = va_arg(vl,  int);
	va_end(vl);

	printf("%x\t%s(%i)\n",retaddr, hook->hook.win->fnname, exitcode);

	opts.steps = 0;
	return 0;

}

uint32_t user_hook_CreateProcess(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	
	//printf("%s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);

	uint32_t retaddr = get_ret(env, -44);

/*BOOL CreateProcess( 
  LPCWSTR pszImageName, 
  LPCWSTR pszCmdLine, 
  LPSECURITY_ATTRIBUTES psaProcess, 
  LPSECURITY_ATTRIBUTES psaThread, 
  BOOL fInheritHandles, 
  DWORD fdwCreate, 
  LPVOID pvEnvironment, 
  LPWSTR pszCurDir, 
  LPSTARTUPINFOW psiStartInfo, 
  LPPROCESS_INFORMATION pProcInfo
);*/

	va_list vl;
	va_start(vl, hook);

	char *pszImageName				      = va_arg(vl, char *);  //now filled in - dz
	char *pszCmdLine                      = va_arg(vl, char *);               

	//STARTUPINFO *psiStartInfo             = va_arg(vl, STARTUPINFO *);
	//PROCESS_INFORMATION *pProcInfo        = va_arg(vl, PROCESS_INFORMATION *); 

	va_end(vl);

	struct emu_string *cmd = emu_string_new();

	if(pszImageName == 0 && pszCmdLine[0] == 0){
		//some shellcode uses the function prolog of CreateProcess to put stack inline..
		//printf("adjusting to use ebp..\n");
		emu_memory_read_string(mem, cpu->reg[ebp] , cmd, 255);
		pszCmdLine = (char*)cmd->data; 
		printf("%x\tCreateProcessA( %s ) (ebp)\n",retaddr, pszCmdLine); 
	}else{
		printf("%x\tCreateProcessA( %s, %s )\n",retaddr, pszCmdLine, pszImageName );
	}

	if(opts.interactive_hooks == 0) return 1;

	if ( pszCmdLine != NULL && strncasecmp(pszCmdLine, "cmd", 3) == 0 )
	{
		//todo possibly do stuff here to capture command line sent to cmd...
	}

	
	emu_string_free(cmd);

	return 1;
}

uint32_t user_hook_WaitForSingleObject(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	
	//printf("%s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);

	uint32_t retaddr = get_ret(env,-12);


	/*
	DWORD WINAPI WaitForSingleObject(
	  HANDLE hHandle,
	  DWORD dwMilliseconds
	);
	*/

	va_list vl;
	va_start(vl, hook);

	int32_t hHandle = va_arg(vl, int32_t);
	/*int32_t dwMilliseconds = */ (void)va_arg(vl, int32_t);
	va_end(vl);

	printf("%x\tWaitForSingleObject(h=%x)\n",retaddr, (int)hHandle);

	if(opts.interactive_hooks){
		int status;
		while(1)
		{
			if (waitpid(hHandle, &status, WNOHANG) != 0) break;
			sleep(1);
		}
	}

	return 0;
}


uint32_t user_hook_exit(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	
	//printf("%s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);

	uint32_t retaddr = get_ret(env,-8);

	va_list vl;
	va_start(vl, hook);
	int code = va_arg(vl,  int);
	va_end(vl);

	printf("%x\texit(%x)\n",retaddr,code );

	opts.steps = 0;
	return 0;
}

uint32_t user_hook_accept(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	
	//printf("%s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);

	uint32_t retaddr = get_ret(env,-16);

	va_list vl;
	va_start(vl, hook);

	int s 					= va_arg(vl,  int);
	/*struct sockaddr* addr 	= */(void)va_arg(vl,  struct sockaddr *);
	/*socklen_t* addrlen 		= */(void)va_arg(vl,  socklen_t *);
	va_end(vl);

	struct sockaddr sa;
	socklen_t st = sizeof(struct sockaddr);

	printf("%x\taccept(h=%x)\n",retaddr, (int)s);

    return accept(s, &sa, &st);
}

uint32_t user_hook_bind(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	
	//printf("%s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);

	uint32_t retaddr = get_ret(env,-16);

	va_list vl;
	va_start(vl, hook);

	int s 					= va_arg(vl,  int);
	struct sockaddr* addr 	= va_arg(vl,  struct sockaddr *);
	socklen_t addrlen = va_arg(vl,  socklen_t );

	/*
	if (opts.override.bind.host != NULL )
	{
		struct sockaddr_in *si = (struct sockaddr_in *)addr;
		si->sin_addr.s_addr = inet_addr(opts.override.bind.host);
	}

	if (opts.override.bind.port > 0)
	{
		struct sockaddr_in *si = (struct sockaddr_in *)addr;;
		si->sin_port = htons(opts.override.bind.port);
	}
	*/
	va_end(vl);

	printf("%x\tbind(port: %d )\n",retaddr, get_client_port(addr) );

    return bind(s, addr, addrlen);
}

uint32_t user_hook_closesocket(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	
	//printf("%s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);

	uint32_t retaddr = get_ret(env,-8);

	va_list vl;
	va_start(vl, hook);
	int s 					= va_arg(vl,  int);
	va_end(vl);

	printf("%x\tclosesocket(h=%x)\n",retaddr,(int)s );

    return close(s);
}

uint32_t user_hook_connect(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	
	//printf("%s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);

	uint32_t retaddr = get_ret(env,-16);

	va_list vl;
	va_start(vl, hook);

	int s 					= va_arg(vl,  int);
	struct sockaddr* addr 	= va_arg(vl,  struct sockaddr *);


	if (opts.override.connect.host != NULL )
	{
		struct sockaddr_in *si = (struct sockaddr_in *)addr;
		si->sin_addr.s_addr = inet_addr(opts.override.connect.host);
	}

	if (opts.override.connect.port > 0)
	{
		struct sockaddr_in *si = (struct sockaddr_in *)addr;;
		si->sin_port = htons(opts.override.connect.port);
	}

	socklen_t addrlen = va_arg(vl,  socklen_t);

	if (addrlen != sizeof(struct sockaddr))
	{
		addrlen = sizeof(struct sockaddr);
	}

	va_end(vl);

	printf("%x\tconnect(h=%x, host: %s , port: %d )\n",retaddr,s, get_client_ip(addr), get_client_port(addr) );

	if( opts.interactive_hooks == 0 ) return 0x4711;

	return connect(s, addr, addrlen);
	
}

uint32_t user_hook_fclose(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	
	//printf("%s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);
	//int fclose(FILE *fp);

	uint32_t retaddr = get_ret(env,-8);

	va_list vl;
	va_start(vl, hook);
	FILE *f = va_arg(vl, FILE *);
	va_end(vl);

	printf("%x\tfclose(h=%x)\n",retaddr, (int)f);

	if( opts.interactive_hooks == 0 )  return 0x4711;

	struct nanny_file *nf = nanny_get_file(hook->hook.win->userdata, (uint32_t)(uintptr_t)f);

	if (nf != NULL)
	{
		FILE *ef = nf->real_file;
		nanny_del_file(hook->hook.win->userdata, (uint32_t)(uintptr_t)f);
    	return fclose(ef);
	}
	else 
		return 0;
	

}


uint32_t user_hook_fopen(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	
	//printf("%s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);

	char *localfile;
	uint32_t retaddr = get_ret(env,-16);

	va_list vl;
	va_start(vl, hook);
	char *filename			= va_arg(vl,  char *);
	char *mode 				= va_arg(vl,  char *);
	va_end(vl);

	if( opts.interactive_hooks == 0){
		printf("%x\tfopen(%s, %s) = %x\n", retaddr, filename, mode, 0x4711);
		return 0x4711;
	}

	if ( asprintf(&localfile, "/tmp/XXXXXXXX") == -1) return -1;
	int fd = mkstemp(localfile);
	close(fd);

	FILE *f = fopen(localfile,"w");
	printf("%x\tfopen(%s) = %x\n", retaddr, filename, (int)f);
	printf("\tInteractive mode local file: %s\n", localfile);

	uint32_t file;
	nanny_add_file(hook->hook.win->userdata, localfile, &file, f);

	return file;
}

uint32_t user_hook_fwrite(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	
	//printf("%s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);

	uint32_t retaddr = get_ret(env,-24);
	uint32_t real_buf = get_ret(env,-4);

/*       size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);  */

	va_list vl;
	va_start(vl, hook);
	void *data = va_arg(vl, void *);   //libemu buffer address 
	size_t size = va_arg(vl, size_t);
	size_t nmemb = va_arg(vl, size_t);
	FILE *f = va_arg(vl, FILE *);
	va_end(vl);
	
	printf("%x\tfwrite(h=%x, sz=%x, buf=%x)\n", retaddr, (int)f, size*nmemb, real_buf);
	
	if(opts.show_hexdumps && data != 0 && size > 0 && nmemb > 0){
		int display_size = size*nmemb;
		if(display_size > 300){ 
			printf("Showing first 300 bytes...\n");
			display_size = 300;
		}
		hexdump(data, display_size );
	}

	if(opts.interactive_hooks == 0 ) return size*nmemb;

	struct nanny_file *nf = nanny_get_file(hook->hook.win->userdata, (uint32_t)(uintptr_t)f);

	if (nf != NULL)
		return fwrite(data, size, nmemb, nf->real_file);
	else 
		return size*nmemb;

}



uint32_t user_hook_listen(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	
	//printf("%s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);

	uint32_t retaddr = get_ret(env,-12);

	va_list vl;
	va_start(vl, hook);

	int s 					= va_arg(vl,  int);
	int backlog			 	= va_arg(vl,  int);
	va_end(vl);
	
	printf("%x\tlisten(h=%x)\n",retaddr,s);

	if(opts.interactive_hooks == 0 ) return 0; //ok

    return listen(s, backlog);
}

uint32_t user_hook_recv(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	
	//printf("%s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);

	uint32_t retaddr = get_ret(env,-20);
	uint32_t real_buf = get_ret(env,-12); //grab the real buf addr off of stack..

	va_list vl;
	va_start(vl, hook);

	int s = va_arg(vl,  int);
	char* buf = va_arg(vl,  char *); //not org buffer, libemu malloced
	int len = va_arg(vl,  int);
	int flags = va_arg(vl,  int);
	va_end(vl);
	 
	printf("%x\trecv(h=%x, buf=%x, len=%x, fl=%x)\n", retaddr, s, real_buf, len, flags);
	
	if(opts.interactive_hooks == 0 ) return 0; //no data

	int ret_val=0;

	ret_val = recv(s, buf, len,  flags); //libemu malloced buf
	
	if(opts.show_hexdumps && ret_val > 0){
		printf("%d bytes received:\n", ret_val);
		hexdump(buf, ret_val);
	}

	return ret_val; //if we return > 0 dll will write it to mem at real emu addr for us..

}

uint32_t user_hook_send(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	
	//printf("%s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);

	uint32_t retaddr = get_ret(env,-16);

	va_list vl;
	va_start(vl, hook);

	int s = va_arg(vl,  int);
	char* buf = va_arg(vl,  char *);
	int len = va_arg(vl,  int);
	int flags = va_arg(vl,  int);
	va_end(vl);

	printf("%x\tsend(h=%x, buf=%x, len=%x)\n",retaddr, s, (int)buf, len);

	if(opts.show_hexdumps && len > 0 && buf > 0){
		hexdump(buf,len);
	}

	if(opts.interactive_hooks == 0 ) return len; //success

	return send(s, buf, len,  flags);
}


uint32_t user_hook_socket(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	
	//printf("%s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);

	uint32_t retaddr = get_ret(env,-16);

	va_list vl;
	va_start(vl, hook);
	/* int socket(int domain, int type, int protocol); */
	int domain = va_arg(vl,  int);
	int type = va_arg(vl,  int);
	int protocol = va_arg(vl, int);
	va_end(vl);

	printf("%x\tsocket(%i, %i, %i)\n",retaddr, domain, type, protocol);

	if(opts.interactive_hooks == 0 ) return 0x4711;

	return socket(domain, type, protocol);
}

uint32_t user_hook_WSASocket(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	
	//printf("%s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);

	uint32_t retaddr = get_ret(env, -1*((6*4)+4) );

	va_list vl;
	va_start(vl, hook);
	/* int socket(int domain, int type, int protocol); */
	int domain = va_arg(vl,  int);
	int type = va_arg(vl,  int);
	int protocol = va_arg(vl, int);
	(void)va_arg(vl, int);
	(void)va_arg(vl, int);
	(void)va_arg(vl, int);

	va_end(vl);

	printf("%x\tWSASocket(%i, %i, %i)\n",retaddr, domain, type, protocol);

	if(opts.interactive_hooks == 0 ) return 0x4711;

	return socket(domain, type, protocol);
}


uint32_t user_hook_CreateFile(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	
	//printf("%s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);

	uint32_t retaddr = get_ret(env, -32);

/*
HANDLE CreateFile(
  LPCTSTR lpFileName,
  DWORD dwDesiredAccess,
  DWORD dwShareMode,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  DWORD dwCreationDisposition,
  DWORD dwFlagsAndAttributes,
  HANDLE hTemplateFile
);
*/

	va_list vl;
	va_start(vl, hook);
	char *lpFileName			= va_arg(vl, char *);
	/*int dwDesiredAccess		=*/(void)va_arg(vl, int);
	/*int dwShareMode			=*/(void)va_arg(vl, int);
	/*int lpSecurityAttributes	=*/(void)va_arg(vl, int);
	/*int dwCreationDisposition	=*/(void)va_arg(vl, int);
	/*int dwFlagsAndAttributes	=*/(void)va_arg(vl, int);
	/*int hTemplateFile			=*/(void)va_arg(vl, int);
	va_end(vl);

	char *localfile;
	printf("%x\tCreateFile(%s)\n",retaddr,lpFileName);

	if(opts.interactive_hooks == 0 ) return 0x4444;

	if ( asprintf(&localfile, "/tmp/XXXXXXXX") == -1) return -1; //exit(-1);
	int fd = mkstemp(localfile);
	close(fd);

	FILE *f = fopen(localfile,"w");

	printf("\tInteractive mode local file: %s\n", localfile);

	uint32_t handle;
	nanny_add_file(hook->hook.win->userdata, localfile, &handle, f);

	return (uint32_t)handle;
}

uint32_t user_hook_WriteFile(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	
	//printf("%s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);

	uint32_t retaddr = get_ret(env, -1*((5*4)+4));

/*
BOOL WriteFile(
  HANDLE hFile,
  LPCVOID lpBuffer,
  DWORD nNumberOfBytesToWrite,
  LPDWORD lpNumberOfBytesWritten,
  LPOVERLAPPED lpOverlapped
);
*/

	int written = -1;
	va_list vl;
	va_start(vl, hook);
	FILE *hFile 					= va_arg(vl, FILE *);
	void *lpBuffer 					= va_arg(vl, void *);
	int   nNumberOfBytesToWrite 	= va_arg(vl, int);
	/* int *lpNumberOfBytesWritten  =*/(void)va_arg(vl, int*);
	/* int *lpOverlapped 		    =*/(void)va_arg(vl, int*);
	va_end(vl);

	printf("%x\tWriteFile(h=%x, buf=%x)\n",retaddr,(int)hFile,(int)lpBuffer);

	if(opts.show_hexdumps && nNumberOfBytesToWrite > 0){
		int display_size = nNumberOfBytesToWrite;
		if(display_size > 500){
			printf("Showing first 500 bytes...\n");
			display_size = 500;
		}
		hexdump(lpBuffer, display_size);
	}

	if(opts.interactive_hooks == 0 ) return 1; //success

	struct nanny_file *nf = nanny_get_file(hook->hook.win->userdata, (uint32_t)(uintptr_t)hFile);

	if (nf != NULL){
		written = fwrite(lpBuffer, nNumberOfBytesToWrite, 1, nf->real_file);
	}else{
		//printf("shellcode tried to write data to not existing handle\n");
	}

	return 1;

}


uint32_t user_hook_CloseHandle(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	
	//printf("%s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);

	uint32_t retaddr = get_ret(env,-8);

/*
BOOL CloseHandle(
  HANDLE hObject
);
*/

	va_list vl;
	va_start(vl, hook);
	FILE *hObject = va_arg(vl, FILE *);
	va_end(vl);

	printf("%x\tCloseHandle(%x)\n",retaddr,(int)hObject);

	if(opts.interactive_hooks == 0 ) return 1; //success

	struct nanny_file *nf = nanny_get_file(hook->hook.win->userdata, (uint32_t)(uintptr_t)hObject);

	if (nf != NULL)
	{
		FILE *f = nf->real_file;
		nanny_del_file(hook->hook.win->userdata, (uint32_t)(uintptr_t)hObject);
		fclose(f);
	}
	else 
	{
		//printf("shellcode tried to close not existing handle (maybe closed it already?)\n");
	}


	return 1;
}



uint32_t user_hook_URLDownloadToFile(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	
	//printf("%s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);

	uint32_t retaddr = get_ret(env,-24);

	va_list vl;
	va_start(vl, hook);

	/*void * pCaller    = */(void)va_arg(vl, void *);
	char * szURL      = va_arg(vl, char *);
	char * szFileName = va_arg(vl, char *);
	/*int    dwReserved = */(void)va_arg(vl, int   );
	/*void * lpfnCB     = */(void)va_arg(vl, void *);

	va_end(vl);

	printf("%x\tURLDownloadToFile(%s, %s)\n",retaddr, szURL, szFileName);

	return 0;
}




// ---------------- added 1-20-11 dzzie (not all have been tested live! ) ---------------

uint32_t user_hook_GetProcAddress(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	
	//printf("%s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);

	uint32_t retaddr =  get_ret(env,-12);

/*
h GetProcAddress(hModule, proc)
);
*/

	va_list vl;
	va_start(vl, hook);
	/*int hMod  = */ va_arg(vl,  int);
	char* api = va_arg(vl, char *); 
	va_end(vl);

	printf("%x\tGetProcAddress(%s)\n",retaddr, api);

	return 0;

}


uint32_t user_hook_GetSystemDirectoryA(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	
	//printf("%s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);

	uint32_t retaddr =  get_ret(env,-12);

/*
UINT GetSystemDirectory(
  LPTSTR lpBuffer,
  UINT uSize
);
*/
	//buffer filled in by dll hook
	printf("%x\tGetSystemDirectoryA( c:\\windows\\system32\\ )\n",retaddr);
 
	return 0;

}


uint32_t user_hook_GetTickCount(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	
	//printf("%s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);

	uint32_t retaddr =  get_ret(env,-4);

	printf("%x\tGetTickCount()\n",retaddr);

	return 0;

}

 
uint32_t user_hook_LoadLibraryA(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	
	//printf("%s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);

	uint32_t retaddr =  get_ret(env,-8);

	va_list vl;
	va_start(vl, hook);
	char* lib = va_arg(vl, char *); 
	va_end(vl);

	//printf("%x\tLoadLibrary(%s) = %x\n",retaddr,lib, emu_cpu_reg32_get(cpu,eax));
	printf("%x\tLoadLibrary(%s)\n",retaddr,lib);

	return 0;

}



uint32_t user_hook__lcreat(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	
	//printf("%s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);

	uint32_t retaddr =  get_ret(env,-12);

/*
LONG _lcreat(
  LPCSTR lpszFileName,
  int fnAttribute
);
*/
	va_list vl;
	va_start(vl, hook);
	char* fname = va_arg(vl, char *); 
	/*int fnAttribute  = */ va_arg(vl,  int);
	va_end(vl);

	printf("%x\t_lcreate(%s)\n",retaddr,fname);
	
	if(opts.interactive_hooks == 0) return 1;

	
	char *localfile;
	if ( asprintf(&localfile, "/tmp/XXXXXXXX") == -1) return -1; //exit(-1);
	int fd = mkstemp(localfile);
	close(fd);

	FILE *f = fopen(localfile,"w");

	printf("\tInteractive mode local file: %s\n", localfile);

	uint32_t handle;
	nanny_add_file(hook->hook.win->userdata, localfile, &handle, f);

	return (uint32_t)handle;

}


uint32_t user_hook__lwrite(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	
	//printf("%s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);

	uint32_t retaddr =  get_ret(env,-16);

/*
LONG _lwrite(
  HFile hFile,
  LPCSTR lpBuffer,
  UINT cbWrite
);
*/
	uint32_t real_buf = get_ret(env,-8);

	va_list vl;
	va_start(vl, hook);
	int hFile    = va_arg(vl,  int);
	int lpBuffer = va_arg(vl,  int); //this is the libemu buffer not real address...
	int cbWrite  = va_arg(vl,  int);
	va_end(vl);

	printf("%x\t_lwrite(h=%x, buf=%x)\n",retaddr, hFile, real_buf);

	if(opts.show_hexdumps && lpBuffer != 0 && cbWrite > 0) hexdump((char*)lpBuffer, cbWrite);

	if(opts.interactive_hooks == 0 ) return cbWrite;

	struct nanny_file *nf = nanny_get_file(hook->hook.win->userdata, (uint32_t)(uintptr_t)hFile);

	if (nf != NULL)
		return fwrite((void*)lpBuffer, 1, cbWrite, nf->real_file);
	else 
		return cbWrite;

}


uint32_t user_hook__lclose(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	
	//printf("%s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);

	uint32_t retaddr =  get_ret(env,-8);

	va_list vl;
	va_start(vl, hook);
	int hFile  =  va_arg(vl,  int); 
	va_end(vl);

	printf("%x\t_lclose(h=%x)\n",retaddr,hFile);

	if( opts.interactive_hooks == 0 )  return 0;

	struct nanny_file *nf = nanny_get_file(hook->hook.win->userdata, (uint32_t)(uintptr_t)hFile);

	if (nf != NULL)
	{
		FILE *ef = nf->real_file;
		nanny_del_file(hook->hook.win->userdata, (uint32_t)(uintptr_t)hFile);
    	return fclose(ef);
	}
	else 
		return 0;

}


uint32_t user_hook_malloc(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	
	//printf("%s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);

	uint32_t retaddr =  get_ret(env,-8);

/*
void *malloc( 
   size_t size 
);
*/

	va_list vl;
	va_start(vl, hook);
	int sz  =  va_arg(vl,  int);
	va_end(vl);

	printf("%x\tmalloc(%x)\n",retaddr,sz);

	return 0;

}


uint32_t user_hook_memset(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	
	//printf("%s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);

	uint32_t retaddr =  get_ret(env,-16);

/*
void *memset(
   void* dest, 
   int c, 
   size_t count 
);
*/

	va_list vl;
	va_start(vl, hook);
	int dest  =   va_arg(vl,  int);
	int c  =   va_arg(vl,  int);
	int sz  =   va_arg(vl,  int);
	va_end(vl);

	printf("%x\tmemset(buf=%x, c=%x, sz=%x)\n",retaddr,dest,c,sz);

	return 0;

}


uint32_t user_hook_SetUnhandledExceptionFilter(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	
	//printf("%s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);

	uint32_t retaddr =  get_ret(env,-8);

/*
lpFilter
);
*/

	va_list vl;
	va_start(vl, hook);
	int lpfilter  =  va_arg(vl,  int);
	va_end(vl);

	printf("%x\tSetUnhandledExceptionFilter(%x)\n",retaddr,lpfilter);

	uint32_t seh = 0;
	disable_mm_logging = true;
	if(emu_memory_read_dword( mem, FS_SEGMENT_DEFAULT_OFFSET, &seh) != -1){
		emu_memory_write_dword( mem, seh+4, lpfilter);
	}
	disable_mm_logging = false;

	return 0;

}


uint32_t user_hook_WinExec(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	
	//printf("%s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);

	uint32_t retaddr =  get_ret(env,-12);

/*
UINT WINAPI WinExec(
  LPCSTR lpCmdLine,
  UINT uCmdShow
);
*/

	va_list vl;
	va_start(vl, hook);
	char* cmd = va_arg(vl, char *); 
	/*int uCmdShow  = */ va_arg(vl,  int);
	va_end(vl);

	printf("%x\tWinExec(%s)\n",retaddr,cmd);

	return 0;

}


//---------------------------------- added with newest dll ---------------

uint32_t user_hook_DeleteFileA(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	
	//printf("%s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);

	uint32_t retaddr = get_ret(env,-8);

	/*
	BOOL DeleteFile(
	  LPCTSTR lpFileName
	);
	*/

	va_list vl;
	va_start(vl, hook);

	char* fpath = va_arg(vl, char*);
	va_end(vl);

	printf("%x\tDeleteFileA(%s)\n",retaddr, fpath );

	return 0;
}

uint32_t user_hook_GetVersion(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	
	//printf("%s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);

	uint32_t retaddr = get_ret(env,-4);

/*
DWORD WINAPI GetVersion(void);
*/
	printf("%x\tGetVersion()\n",retaddr);

	return 0;
}

uint32_t user_hook_GetTempPath(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	
	//printf("%s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);

	uint32_t retaddr = get_ret(env,-12);

/*
DWORD WINAPI GetTempPath(
  __in   DWORD nBufferLength,
  __out  LPTSTR lpBuffer
);
*/
	printf("%x\tGetTempPath()\n",retaddr);

	return 0;
}

uint32_t user_hook_Sleep(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	
	//printf("%s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);

	uint32_t retaddr = get_ret(env,-8);

/*VOID WINAPI Sleep(
  __in  DWORD dwMilliseconds
);
*/
	va_list vl;
	va_start(vl, hook);
	int32_t dwMilliseconds = va_arg(vl, int32_t);
	va_end(vl);

	printf("%x\tSleep(0x%x)\n",retaddr, dwMilliseconds);

	return 0;
}

uint32_t user_hook_VirtualProtect(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	
	//printf("%s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);

	uint32_t retaddr = get_ret(env, -20);

/*
  BOOL VirtualProtect( 
 	LPVOID lpAddress, 
 	DWORD  dwSize, 
       DWORD  flNewProtect, 
       PDWORD lpflOldProtect 
 ); 
*/
	va_list vl;
	va_start(vl, hook);
	int32_t addr = va_arg(vl, int32_t);
	int32_t size = va_arg(vl, int32_t);
	int32_t protect = va_arg(vl, int32_t);
	va_arg(vl, int32_t); //old protect
	va_end(vl);

	printf("%x\tVirtualProtect(adr=%x, sz=%x, flags=%x)\n",retaddr, addr, size ,protect);

	return 0;
}


/*
-------------------	new user hook format stubs below here ----------------------------
*/

int32_t	new_user_hook_GetModuleHandleA(struct emu_env *env, struct emu_env_hook *hook)
{

	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);
 
	//HMODULE WINAPI GetModuleHandle( __in_opt  LPCTSTR lpModuleName);

	uint32_t filename;
	POP_DWORD(c, &filename);

	struct emu_memory *mem = emu_memory_get(env->emu);
	struct emu_string *s_filename = emu_string_new();
	emu_memory_read_string(mem, filename, s_filename, 256);

	char *dllname = emu_string_char(s_filename);


	int i=0;
	int found_dll = 0;
	for (i=0; env->env.win->loaded_dlls[i] != NULL; i++)
	{
		if (strncasecmp(env->env.win->loaded_dlls[i]->dllname, dllname, strlen(env->env.win->loaded_dlls[i]->dllname)) == 0)
		{
			//logDebug(env->emu, "found dll %s, baseaddr is %08x \n",env->env.win->loaded_dlls[i]->dllname,env->env.win->loaded_dlls[i]->baseaddr);
			emu_cpu_reg32_set(c, eax, env->env.win->loaded_dlls[i]->baseaddr);
			found_dll = 1;
			break;
		}
	}
	 
	if (found_dll == 0)
	{
        if (emu_env_w32_load_dll(env->env.win, dllname) == 0)
        {
            emu_cpu_reg32_set(c, eax, env->env.win->loaded_dlls[i]->baseaddr);
			found_dll = 1;
        }
        else
        {
            //logDebug(env->emu, "error could not find %s\n", dllname);
            emu_cpu_reg32_set(c, eax, 0x0);
        }
	}

	//printf("%x\tGetModuleHandleA(%s) = %x\n",eip_save,  dllname, emu_cpu_reg32_get(c,eax) );
	printf("%x\tGetModuleHandleA(%s)\n",eip_save,  dllname);

	emu_string_free(s_filename);

	emu_cpu_reg32_set(c, eax, 0);
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	new_user_hook_MessageBoxA(struct emu_env *env, struct emu_env_hook *hook)
{

	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*
int WINAPI MessageBox(
  __in_opt  HWND hWnd,
  __in_opt  LPCTSTR lpText,
  __in_opt  LPCTSTR lpCaption,
  __in      UINT uType
);
*/
	uint32_t hwnd;
	POP_DWORD(c, &hwnd);

	uint32_t p_text;
	POP_DWORD(c, &p_text);

	uint32_t p_caption;
	POP_DWORD(c, &p_caption);

	uint32_t utype;
	POP_DWORD(c, &utype);

	struct emu_memory *mem = emu_memory_get(env->emu);
	struct emu_string *s_text = emu_string_new();
	emu_memory_read_string(mem, p_text, s_text, 256);

	char *stext = emu_string_char(s_text);
	printf("%x\tMessageBoxA(%s)\n",eip_save,  stext );
	
	emu_string_free(s_text);

	emu_cpu_reg32_set(c, eax, 0);
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	new_user_hook_ShellExecuteA(struct emu_env *env, struct emu_env_hook *hook)
{

	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*
HINSTANCE ShellExecute(
  __in_opt  HWND hwnd,
  __in_opt  LPCTSTR lpOperation,
  __in      LPCTSTR lpFile,
  __in_opt  LPCTSTR lpParameters,
  __in_opt  LPCTSTR lpDirectory,
  __in      INT nShowCmd
);

*/
	uint32_t hwnd;
	POP_DWORD(c, &hwnd);

	uint32_t lpOperation;
	POP_DWORD(c, &lpOperation);

	uint32_t p_file;
	POP_DWORD(c, &p_file);

	uint32_t lpParameters;
	POP_DWORD(c, &lpParameters);

	uint32_t lpDirectory;
	POP_DWORD(c, &lpDirectory);

	uint32_t nShowCmd;
	POP_DWORD(c, &nShowCmd);

	struct emu_string *s_text = emu_string_new();
	emu_memory_read_string(mem, p_file, s_text, 254);

	char *stext = emu_string_char(s_text);
	printf("%x\tShellExecuteA(%s)\n",eip_save,  stext );
	
	emu_string_free(s_text);

	emu_cpu_reg32_set(c, eax, 33);
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	new_user_hook_SHGetSpecialFolderPathA(struct emu_env *env, struct emu_env_hook *hook)
{

	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*
CopyBOOL SHGetSpecialFolderPath(
         HWND hwndOwner,
  __out  LPTSTR lpszPath,
  __in   int csidl,
  __in   BOOL fCreate
);

*/
	uint32_t hwnd;
	POP_DWORD(c, &hwnd);

	uint32_t buf;
	POP_DWORD(c, &buf);

	uint32_t csidl;
	POP_DWORD(c, &csidl);

	uint32_t fCreate;
	POP_DWORD(c, &fCreate);

	char buf255[255];
	memset(buf255,0,254);
	GetSHFolderName(csidl, (char*)&buf255);

	printf("%x\tSHGetSpecialFolderPathA(buf=%x, %s)\n",eip_save, buf, buf255 );
	
	emu_memory_write_block(mem,buf,buf255,strlen(buf255));

	emu_cpu_reg32_set(c, eax, 0);
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	new_user_hook_GenericStub(struct emu_env *env, struct emu_env_hook *hook)
{

	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*
	HANDLE WINAPI CreateFileMapping(
	  __in      HANDLE hFile,
	  __in_opt  LPSECURITY_ATTRIBUTES lpAttributes,
	  __in      DWORD flProtect,
	  __in      DWORD dwMaximumSizeHigh,
	  __in      DWORD dwMaximumSizeLow,
	  __in_opt  LPCTSTR lpName
	);

	BOOL InternetReadFile(
	  __in   HINTERNET hFile,
	  __out  LPVOID lpBuffer,
	  __in   DWORD dwNumberOfBytesToRead,
	  __out  LPDWORD lpdwNumberOfBytesRead
	);

    ZwTerminateProcess, ZwTerminateThread, each 2 args
    BOOL WINAPI TerminateThread(inout HANDLE hThread, DWORD dwExitCode)
	FreeLibrary(hMod)
	handle GetCurrentProcess(void)
);


*/

	int arg_count = -1 ;
	int ret_val   =  1 ;
    int log_val   = -1 ; //stub support optional logging of one int arg

	char* func = hook->hook.win->fnname;

	if(strcmp(func, "CreateFileMappingA") ==0 ){
		log_val = get_ret(env,-16);  //sizelow
		arg_count = 6;
	}

	if(strcmp(func, "GetCurrentProcess") ==0 ){
		arg_count = 0;
	}

	if(strcmp(func, "FreeLibrary") ==0 ){
		log_val = get_ret(env,0);  //hmodule
		arg_count = 1;
	}

	if(strcmp(func, "GlobalFree") ==0 ){
		log_val = get_ret(env,0);  //hmem
		arg_count = 1;
	}

	if(strcmp(func, "GetFileSize") == 0){
		log_val = get_ret(env,0); //handle
		ret_val = -1;
		if((int)opts.fopen > 0){
			if( log_val == (int)opts.fopen || log_val == 4 || log_val == 1){ //scanners start at 1 or 4 so no spam this way..
				ret_val = file_length(opts.fopen)-1;
			}
		}
		arg_count = 2;
	}

	if(strcmp(func, "ZwTerminateProcess") == 0 
		|| strcmp(func, "ZwTerminateThread") == 0
		|| strcmp(func, "TerminateThread") == 0
		|| strcmp(func, "TerminateProcess") == 0
	){
		log_val = get_ret(env,0); //handle
		arg_count = 2;
		opts.steps =0;
	}

	if(strcmp(func, "InternetReadFile") == 0){
		log_val = get_ret(env,4); //lpBuffer
		ret_val = get_ret(env,12);
		arg_count = 4;
	}

	if(arg_count == -1 ){
		printf("invalid use of generic stub no match found for %s",func);
		exit(0);
	}

	int r_esp = cpu->reg[esp];
	r_esp -= arg_count*4;
	
	cpu->reg[esp] = r_esp;

	/*int interval = 25;
	char *x = "|//-|\\-";
	//char tmp[22] = {0};
	int i=0;

	//i hate spam...
	if(strcmp(func, "GetFileSize") == 0){
		if( (last_GetSizeFHand+1) == log_val || (last_GetSizeFHand+4) == log_val){ 
			if(rep_count == (interval*5+1) ){
				rep_count=0;
				for(i=0;i<6;i++) printf("\b \b");
				printf("%x", log_val);
			}else{
				if(rep_count % interval == 0){
					printf("%c\b", x[rep_count/interval]);
				}
				rep_count++;
			}
		}else{
			printf("%x\t%s(%x) = %x\n", eip_save, func, log_val, ret_val );
		}
		last_GetSizeFHand = log_val;
	}else{*/ 
		if(log_val == -1){
			printf("%x\t%s() = %x\n", eip_save, func, ret_val );
		}else{
			printf("%x\t%s(%x) = %x\n", eip_save, func, log_val, ret_val );
		}
	//}

	emu_cpu_reg32_set(c, eax, ret_val);
	emu_cpu_eip_set(c, eip_save);
	return 0;
}


int32_t	new_user_hook_CreateProcessInternalA(struct emu_env *env, struct emu_env_hook *hook)
{

	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*
	DWORD WINAPI CreateProcessInternal(  
		__in         DWORD unknown1,                              // always (?) NULL  
		__in_opt     LPCTSTR lpApplicationName,  
		__inout_opt  LPTSTR lpCommandLine,  
		__in_opt     LPSECURITY_ATTRIBUTES lpProcessAttributes,  
		__in_opt     LPSECURITY_ATTRIBUTES lpThreadAttributes,  
		__in         BOOL bInheritHandles,  
		__in         DWORD dwCreationFlags,  
		__in_opt     LPVOID lpEnvironment,  
		__in_opt     LPCTSTR lpCurrentDirectory,  
		__in         LPSTARTUPINFO lpStartupInfo,  
		__out        LPPROCESS_INFORMATION lpProcessInformation,  
		__in         DWORD unknown2                               // always (?) NULL
	);
*/
	uint32_t stack_addr = cpu->reg[esp]; 
	uint32_t p_cmdline =0;

	emu_memory_read_dword(mem,stack_addr+8, &p_cmdline);

	if(p_cmdline == 0) emu_memory_read_dword(mem,stack_addr+4, &p_cmdline);

	stack_addr -= 12*4;
	cpu->reg[esp] = stack_addr;

	if(p_cmdline !=0){
		struct emu_string *s_text = emu_string_new();
		emu_memory_read_string(mem, p_cmdline, s_text, 255);
		printf("%x\tCreateProcessInternalA( %s )\n",eip_save,  emu_string_char(s_text) );
		emu_string_free(s_text);
	}else{
		printf("%x\tCreateProcessInternalA()\n",eip_save);
	}

	emu_cpu_reg32_set(c, eax, 0);
	emu_cpu_eip_set(c, eip_save);
	return 1;
}


int32_t	new_user_hook_GlobalAlloc(struct emu_env *env, struct emu_env_hook *hook)
{

	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*
	CopyHGLOBAL WINAPI GlobalAlloc(
	  __in  UINT uFlags,
	  __in  SIZE_T dwBytes
	);
*/
	uint32_t flags;
	POP_DWORD(c, &flags);

	uint32_t size;
	POP_DWORD(c, &size);

	uint32_t baseMemAddress = next_alloc;

	if(size > 0 && size < 0x99000){
		set_next_alloc(size);
		void *buf = malloc(size);
		memset(buf,0,size);
		emu_memory_write_block(mem,baseMemAddress,buf, size);
		printf("%x\tGlobalAlloc(sz=%x) = %x\n", eip_save, size, baseMemAddress);
		free(buf);
	}else{
		printf("%x\tGlobalAlloc(sz=%x) (Ignored size out of range)\n", eip_save, size);
	}

	emu_cpu_reg32_set(c, eax, baseMemAddress);
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	new_user_hook_MapViewOfFile(struct emu_env *env, struct emu_env_hook *hook)
{

	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*
	
	LPVOID WINAPI MapViewOfFile(  //todo: the return value is the starting address of the mapped view.
	  __in  HANDLE hFileMappingObject,
	  __in  DWORD dwDesiredAccess,
	  __in  DWORD dwFileOffsetHigh,
	  __in  DWORD dwFileOffsetLow,
	  __in  SIZE_T dwNumberOfBytesToMap
	);
*/
	uint32_t size;
	POP_DWORD(c, &size);
	POP_DWORD(c, &size);
	POP_DWORD(c, &size);
	POP_DWORD(c, &size);
	POP_DWORD(c, &size);

	uint32_t baseMemAddress = next_alloc;

	if(size==0) size = 5000; //size was specified in CreateFileMapping...so we default it...

	if(size > 0 && size < 0x99000){
		set_next_alloc(size);
		void *buf = malloc(size);
		memset(buf,0,size);
		emu_memory_write_block(mem,baseMemAddress,buf, size);
		printf("%x\tMapViewOfFile(sz=%x) = %x\n", eip_save, size, baseMemAddress);
		free(buf);
	}else{
		printf("%x\tMapViewOfFile(sz=%x) (Ignored to big)\n", eip_save, size);
	}

	emu_cpu_reg32_set(c, eax, baseMemAddress);
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	new_user_hook_URLDownloadToCacheFileA(struct emu_env *env, struct emu_env_hook *hook)
{
	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*
	HRESULT URLDownloadToCacheFile(      
		LPUNKNOWN lpUnkcaller,
		LPCSTR szURL,
		LPTSTR szFileName,
		DWORD cchFileName,
		DWORD dwReserved,
		IBindStatusCallback *pBSC
	);
*/
	uint32_t stack_addr = cpu->reg[esp]; 
	uint32_t p_url =0;
	uint32_t p_fname =0;
	uint32_t bufsz =0;

	emu_memory_read_dword(mem,stack_addr+4, &p_url);
	emu_memory_read_dword(mem,stack_addr+8, &p_fname);
	emu_memory_read_dword(mem,stack_addr+12, &bufsz);

	stack_addr -= 6*4;
	cpu->reg[esp] = stack_addr;

	struct emu_string *s_url = emu_string_new();

	emu_memory_read_string(mem, p_url, s_url, 255);

	printf("%x\tURLDownloadToCacheFileA(%s, buf=%x)\n",eip_save,  emu_string_char(s_url), p_fname);

	emu_string_free(s_url);

	char* tmp = "c:\\URLCacheTmpPath.exe";

	//printf("bufsize = %d , pfname = %x\n", bufsz, p_fname);

	if(bufsz > strlen(tmp) ){
		emu_memory_write_block(mem,p_fname, tmp, strlen(tmp));
		emu_memory_write_byte(mem,p_fname + strlen(tmp)+1, 0x00);
	}

	emu_cpu_reg32_set(c, eax, 0); // S_OK 
	emu_cpu_eip_set(c, eip_save);
	return 1;
}

int32_t	new_user_hook_system(struct emu_env *env, struct emu_env_hook *hook)
{
	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

	uint32_t stack_addr = cpu->reg[esp]; 
	uint32_t p_url =0;

	emu_memory_read_dword(mem,stack_addr+0, &p_url);

	stack_addr -= 1*4;
	cpu->reg[esp] = stack_addr;

	struct emu_string *s_url = emu_string_new();

	emu_memory_read_string(mem, p_url, s_url, 255);

	printf("%x\tsystem(%s)\n",eip_save,  emu_string_char(s_url));

	emu_string_free(s_url);
	emu_cpu_reg32_set(c, eax, 0);  
	emu_cpu_eip_set(c, eip_save);
	return 1;
}

int32_t	new_user_hook_VirtualAlloc(struct emu_env *env, struct emu_env_hook *hook)
{

	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*
	LPVOID WINAPI VirtualAlloc(
	  __in_opt  LPVOID lpAddress,
	  __in      SIZE_T dwSize,
	  __in      DWORD flAllocationType,
	  __in      DWORD flProtect
);


*/
	uint32_t address;
	POP_DWORD(c, &address);

	uint32_t size;
	POP_DWORD(c, &size);

	uint32_t atype;
	POP_DWORD(c, &atype);

	uint32_t flProtect;
	POP_DWORD(c, &flProtect);

	uint32_t baseMemAddress = next_alloc;

	if(size < 0x99000){
		set_next_alloc(size);
		printf("%x\tVirtualAlloc(base=%x , sz=%x) = %x\n", eip_save, address, size, baseMemAddress);
		if(size < 1024) size = 1024;
		void *buf = malloc(size);
		memset(buf,0,size);
		emu_memory_write_block(mem,baseMemAddress,buf, size);
		free(buf);
	}else{
		printf("%x\tVirtualAlloc(sz=%x) (Ignored size out of range)\n", eip_save, size);
	}

	emu_cpu_reg32_set(c, eax, baseMemAddress);
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	new_user_hook_VirtualProtectEx(struct emu_env *env, struct emu_env_hook *hook)
{

	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*
	BOOL WINAPI VirtualProtectEx(
	  __in   HANDLE hProcess,
	  __in   LPVOID lpAddress,
	  __in   SIZE_T dwSize,
	  __in   DWORD flNewProtect,
	  __out  PDWORD lpflOldProtect
	);
*/
	uint32_t hProcess;
	POP_DWORD(c, &hProcess);

	uint32_t address;
	POP_DWORD(c, &address);

	uint32_t size;
	POP_DWORD(c, &size);

	uint32_t flNewProtect;
	POP_DWORD(c, &flNewProtect);

	uint32_t lpflOldProtect;
	POP_DWORD(c, &lpflOldProtect);

	printf("%x\tVirtualProtectEx(hProc=%x , addr=%x , sz=%x, prot=%x)\n", eip_save, hProcess, address, size, flNewProtect);
		
	emu_cpu_reg32_set(c, eax, 1);
	emu_cpu_eip_set(c, eip_save);
	return 0;
}



//need to find a clean way to have these stubs handle multiple api..this is a start anyway..
//this one can handle logging of 1 or 2 string args..
int32_t	new_user_hook_GenericStub2String(struct emu_env *env, struct emu_env_hook *hook)
{

	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*
	HINTERNET InternetOpenA(
	  __in  LPCTSTR lpszAgent,
	  __in  DWORD dwAccessType,
	  __in  LPCTSTR lpszProxyName,
	  __in  LPCTSTR lpszProxyBypass,
	  __in  DWORD dwFlags
	);

	HINTERNET InternetOpenUrl(
	  __in  HINTERNET hInternet,
	  __in  LPCTSTR lpszUrl,
	  __in  LPCTSTR lpszHeaders,
	  __in  DWORD dwHeadersLength,
	  __in  DWORD dwFlags,
	  __in  DWORD_PTR dwContext
	);


*/
	int arg_count=0;
	int ret_val = 1;
    int log_sarg = -1; //stub support optional logging of 2 string arg
	int log_sarg2 = -1; //stub support optional logging of 2 string args
	int sarg1_len = 255;
	int sarg2_len = 255;

	char* func = hook->hook.win->fnname;

	if(strcmp(func, "InternetOpenA") ==0 ){
		log_sarg = get_ret(env,0);  //lpszAgent
		arg_count = 5;
	}

	if(strcmp(func, "InternetOpenUrlA") ==0 ){
		log_sarg = get_ret(env,4);  //url
		sarg1_len = 500;
		arg_count = 6;
	}

	if(arg_count==0){
		printf("invalid use of generic stub no match found for %s",func);
		exit(0);
	}

	int r_esp = cpu->reg[esp];
	r_esp -= arg_count*4;
	
	cpu->reg[esp] = r_esp;

	if(log_sarg == -1){
		printf("%x\t%s()\n", eip_save, func );
	}
	else if(log_sarg2 == -1){
		struct emu_string *s_data = emu_string_new();
	    emu_memory_read_string(mem, log_sarg, s_data, sarg1_len);
		printf("%x\t%s(%s)\n", eip_save, func, emu_string_char(s_data) );
		emu_string_free(s_data);
	}
	else{ //two string args
		struct emu_string *s_1 = emu_string_new();
		struct emu_string *s_2 = emu_string_new();
	    emu_memory_read_string(mem, log_sarg, s_1, sarg1_len);
		emu_memory_read_string(mem, log_sarg2, s_2, sarg2_len);
		printf("%x\t%s(%s , %s)\n", eip_save, func, emu_string_char(s_1), emu_string_char(s_2) );
		emu_string_free(s_1);
		emu_string_free(s_2);
	}


	emu_cpu_reg32_set(c, eax, ret_val);
	emu_cpu_eip_set(c, eip_save);
	return 0;
}


int32_t	new_user_hook_SetFilePointer(struct emu_env *env, struct emu_env_hook *hook)
{

	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*
	
	DWORD WINAPI SetFilePointer(
  __in         HANDLE hFile,
  __in         LONG lDistanceToMove,
  __inout_opt  PLONG lpDistanceToMoveHigh,
  __in         DWORD dwMoveMethod
);


*/
	uint32_t hfile;
	uint32_t lDistanceToMove;
	uint32_t lDistanceToMoveHigh;
	uint32_t dwMoveMethod;

	POP_DWORD(c, &hfile);
	POP_DWORD(c, &lDistanceToMove);
	POP_DWORD(c, &lDistanceToMoveHigh);
	POP_DWORD(c, &dwMoveMethod);

	if(dwMoveMethod > 2 || dwMoveMethod < 0) dwMoveMethod = 3; //this shouldnt happen..
	char* method[4] = {"FILE_BEGIN", "FILE_CURRENT", "FILE_END","UNKNOWN"};

	printf("%x\tSetFilePointer(hFile=%x, dist=%x, %s)\n", eip_save, hfile, lDistanceToMove, method[dwMoveMethod]);

	if((int)opts.fopen > 0){
		if( hfile == (int)opts.fopen || hfile == 4){ //scanners start at 4 so no spam this way..
			if(dwMoveMethod == 0) fseek (opts.fopen, lDistanceToMove, SEEK_SET);
			if(dwMoveMethod == 1) fseek (opts.fopen, lDistanceToMove, SEEK_CUR);
			if(dwMoveMethod == 2) fseek (opts.fopen, lDistanceToMove, SEEK_END);
		}
	}

	emu_cpu_reg32_set(c, eax, lDistanceToMove);
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	new_user_hook_ReadFile(struct emu_env *env, struct emu_env_hook *hook)
{

	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*	
	BOOL WINAPI ReadFile(
	  __in         HANDLE hFile,
	  __out        LPVOID lpBuffer,
	  __in         DWORD nNumberOfBytesToRead,
	  __out_opt    LPDWORD lpNumberOfBytesRead,
	  __inout_opt  LPOVERLAPPED lpOverlapped
	);
*/
	uint32_t hfile;
	uint32_t lpBuffer;
	uint32_t numBytes;
	uint32_t lpNumBytes;
	uint32_t lpOverlap;

	POP_DWORD(c, &hfile);
	POP_DWORD(c, &lpBuffer);
	POP_DWORD(c, &numBytes);
	POP_DWORD(c, &lpNumBytes);
	POP_DWORD(c, &lpOverlap);

	printf("%x\tReadFile(hFile=%x, buf=%x, numBytes=%x)\n", eip_save, hfile, lpBuffer, numBytes);
	
	numBytes++;
	if((int)opts.fopen > 0){
		if( hfile == (int)opts.fopen || hfile == 4){ //scanners start at 4 so no spam this way..
			char* tmp = malloc(numBytes);
			fread(tmp, numBytes, 1, opts.fopen);
			emu_memory_write_block(mem, lpBuffer,tmp,numBytes);
			free(tmp);
		}
	}

	//todo support interactive mode here..(no file read functions yet supported w/nanny for i mode)
	//nanny should only be invoked for opening with write access..allow interactive mode to open
	//real files if in read mode?

	if(lpNumBytes != 0) emu_memory_write_dword(mem, lpNumBytes, numBytes);

	emu_cpu_reg32_set(c, eax, 1);
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

//scans for first null in emu memory from address. returns emu address of null or limit
uint32_t emu_string_length(uint32_t addr, int scan_limit){
	uint32_t o = addr;
	char b;

	emu_memory_read_byte(mem, o, &b);
	while(b != 0){
		o++;
		if(o - addr > scan_limit) break;
		emu_memory_read_byte(mem, o, &b);
	}

	return o;
}


int32_t	new_user_hook_strstr(struct emu_env *env, struct emu_env_hook *hook)
{

	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*	
	char *strstr(const char *s1, const char *s2);
*/
	uint32_t s1;
	uint32_t s2;
	uint32_t ret=0;
	POP_DWORD(c, &s1);
	POP_DWORD(c, &s2);
	
	struct emu_string *find = emu_string_new();

	if(s2==0){
		ret = s1;
	}else{
		uint32_t len = emu_string_length(s1, 0x6000);
		emu_memory_read_string(mem, s2, find, 255);

		if(len > 0){
			char* tmp = malloc(len);
			emu_memory_read_block(mem, s1, tmp, len);
			ret = (int)strstr(tmp, (char*)find->data);
			if(ret != 0){
				uint32_t delta = ret - (int)tmp;
				ret = s1 + delta;
			}
			free(tmp);
		}

	}

	printf("%x\tstrstr(buf=%x, find=\"%s\") = %x\n", eip_save, (int)s1, emu_string_char(find), ret);
	
	emu_string_free(find);
	emu_cpu_reg32_set(c, eax, ret);
	emu_cpu_eip_set(c, eip_save);
	return 0;
}


int32_t	new_user_hook_strtoul(struct emu_env *env, struct emu_env_hook *hook)
{

	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*	
	unsigned long strtoul(const char *restrict str, char **restrict endptr, int base);
*/
	uint32_t s1;
	uint32_t s2;
	uint32_t base;
	uint32_t ret=0;
	POP_DWORD(c, &s1);
	POP_DWORD(c, &s2);
	POP_DWORD(c, &base);
	
	struct emu_string *arg = emu_string_new();
	uint32_t len = emu_string_length(s1, 0x6000);
	emu_memory_read_string(mem, s1, arg, len);
	ret = strtoul( emu_string_char(arg), NULL, base);

	printf("%x\tstrtoul(buf=%x -> \"%s\", base=%d) = %x\n", eip_save, s1, emu_string_char(arg), base, ret);
	
	emu_string_free(arg);
	emu_cpu_reg32_set(c, eax, ret);
	emu_cpu_eip_set(c, eip_save);
	return 0;
}




