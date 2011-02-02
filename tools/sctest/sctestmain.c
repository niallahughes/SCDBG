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

/*  this source has been modified from original see changelog 

	TODO: seh handler - remove last handler on trigger?
		  support unhandledexceptionfilter w/seh (implement as req)
		  display bug, on breakpoint and on error disasm shown twice
		  add string deref for pointers in stack dump, deref regs and dword dump?
		  possible add call back to monitor mem access of specific addresses (PEB, TEB etc)
		  opcodes A9 and 2F could use supported (pretty easy ones too i think)
		  add support for getting k32base from TEB (fs18) and SEH methods

*/
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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/wait.h>

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

#define F(x) (1 << (x))

#include "userhooks.h"
#include "options.h"
#include "dot.h"
#include "tests.h"
#include "nanny.h"


struct run_time_options opts;
int graph_draw(struct emu_graph *graph);
void debugCPU(struct emu *e, bool showdisasm);

//-------------------------------------------------------------

#include <io.h>
#include <termios.h>
#include <signal.h>

uint32_t FS_SEGMENT_DEFAULT_OFFSET = 0x7ffdf000;
int CODE_OFFSET = 0x00401000;
static struct termios orgt;
int ctrl_c_count=0;

//this is just easier...only one global object anyway
struct emu *e = 0;
struct emu_cpu *cpu = 0;
struct emu_memory *mem = 0;
struct emu_env *env = 0;
uint32_t last_good_eip=0;
bool disable_mm_logging = false;

char *regm[] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};

	                    /* 0     1     2     3      4       5       6     7 */
const char *eflagm[] = { "CF", "  ", "PF", "  " , "AF"  , "    ", "ZF", "SF", 
	                     "TF", "IF", "DF", "OF" , "IOPL", "IOPL", "NT", "  ",
	                     "RF", "VM", "AC", "VIF", "RIP" , "ID"  , "  ", "  ",
	                     "  ", "  ", "  ", "   ", "    ", "    ", "  ", "  "};

struct mm_point mm_points[] = 
{ //http://en.wikipedia.org/wiki/Win32_Thread_Information_Block
	{0x00251ea0,"PEB Data",0},
	{0x7ffdf000,"SEH (fs0)",0},
	{0x7ffdf030,"PEB (fs30)",0},
	{0x7ffdf000+4,"Top of thread Stack (fs4)",0},
	{0x7ffdf000+0x18,"TEB (fs18)",0},
	{0x7ffdf030+0xC,"peb.InLoadOrderModuleList",0},
	{0x7ffdf030+0x14,"peb.InMemoryOrderModuleList",0},
	{0x7ffdf030+0x1C,"peb.InInitializationOrderModuleList",0},
	{0x252ea0+0x00,"ldrDataEntry.InLoadOrderLinks",0}, /* only addresses here for the [0] entry rest would spam */
	{0x252ea0+0x08,"ldrDataEntry.InMemoryOrderLinks",0},
	{0x252ea0+0x10,"ldrDataEntry.InInitializationOrderLinks",0},
	{0x00253320,   "ldrDataEntry.BaseDllName",0},
	{0,NULL,0},
};

#define CPU_FLAG_ISSET(cpu_p, fl) ((cpu_p)->eflags & (1 << (fl)))


enum colors{ mwhite=0, mgreen, mred, myellow, mblue, mpurple };

void start_color(enum colors c){
	char* cc[] = {"\033[37;1m", "\033[32;1m", "\033[31;1m", "\033[33;1m", "\033[34;1m", "\033[35;1m"};
	printf("%s", cc[c]);
}
void end_color(void){ printf("\033[0m"); }
void nl(void){ printf("\n"); }
#define FLAG(fl) (1 << (fl))
void restore_terminal(int arg)    { tcsetattr( STDIN_FILENO, TCSANOW, &orgt); }
void atexit_restore_terminal(void){ tcsetattr( STDIN_FILENO, TCSANOW, &orgt); }

void ctrl_c_handler(int arg){ 
	opts.verbose = 3;             //break next instruction
	ctrl_c_count++;               //user hit ctrl c a couple times, 
	if(ctrl_c_count > 1) exit(0); //must want out for real.. (zeroed each step)
}

void mm_hook(uint32_t address){ //memory monitor callback function

	int i=0;
	//printf("in mm_hook addr= %x eip= %x\n", address, cpu->eip );

	if(disable_mm_logging) return;

	while(mm_points[i].address != 0){
		if(address == mm_points[i].address){
			mm_points[i].hitat = last_good_eip ; //we dont want a long long list, just last one probably only from one spot anyway..
			break;
		}
		i++;
	}

}

void symbol_lookup(char* symbol){
	
	bool dllmap_mode = false;

	if(strcmp(symbol,"peb") == 0){
		printf("\tpeb -> 0x00251ea0\n");
		return;
	}

	if(strcmp(symbol,"fs0") == 0){
		printf("\tfs0 -> 0x%x\n", FS_SEGMENT_DEFAULT_OFFSET);
		return;
	}

	if(strcmp(symbol,"dllmap") == 0) dllmap_mode = true;

	int numdlls=0;
	while ( env->env.win->loaded_dlls[numdlls] != 0 ){
		 
		struct emu_env_w32_dll *dll = env->env.win->loaded_dlls[numdlls];
		
		if(dllmap_mode){
			printf("\t%-8s Dll mapped at %x - %x\n", dll->dllname, dll->baseaddr , dll->baseaddr+dll->imagesize);
		}
		else{
			if(strcmp(dll->dllname, symbol)==0){
				printf("\t%s Dll mapped at %x - %x\n", dll->dllname, dll->baseaddr , dll->baseaddr+dll->imagesize);
				return;
			}
			
			struct emu_hashtable_item *ehi = emu_hashtable_search(dll->exports_by_fnname, (void *)symbol);
			

			if ( ehi != 0 ){
				int dllBase = dll->baseaddr; 
				struct emu_env_hook *hook = (struct emu_env_hook *)ehi->value;
				printf("\tAddress found: %s - > %x\n", symbol, dllBase + hook->hook.win->virtualaddr);
				return;
			}	
		}
		numdlls++;
	}
	if(!dllmap_mode) printf("\tNo results found...\n");
}



int fulllookupAddress(int eip, char* buf255){

	int numdlls=0;
	int i=0;
	strcpy(buf255," ");

	//additional lookup for a couple addresses not in main tables..
	while(mm_points[i].address != 0){
		if(eip == mm_points[i].address){
			strcpy(buf255, mm_points[i].name);
			return 1;
		}
		i++;
	}

	while ( env->env.win->loaded_dlls[numdlls] != 0 )
	{
		if ( eip == env->env.win->loaded_dlls[numdlls]->baseaddr ){
			
			if(eip == 0x7C800000)
				strcpy(buf255, "Kernel32 Base Address");
			else
				sprintf(buf255, "%s Base Address", env->env.win->loaded_dlls[numdlls]->dllname );
			
			return 1;
		}
		else if ( eip > env->env.win->loaded_dlls[numdlls]->baseaddr && 
			      eip < env->env.win->loaded_dlls[numdlls]->baseaddr + 
				            env->env.win->loaded_dlls[numdlls]->imagesize )
		{
			
			//printf("Address %08x is within %s\n",eip, env->env.win->loaded_dlls[numdlls]->dllname);

			struct emu_env_w32_dll *dll = env->env.win->loaded_dlls[numdlls];

			struct emu_hashtable_item *ehi = emu_hashtable_search(dll->exports_by_fnptr, (void *)(uintptr_t)(eip - dll->baseaddr));

			if ( ehi == 0 )
			{
				//printf("No specific lookup found for %08x\n", eip);
				return 0;
			}

			struct emu_env_hook *hook = (struct emu_env_hook *)ehi->value;
			//printf("Address found: %x = %s\n", eip, hook->hook.win->fnname);
			//printf("%s", hook->hook.win->fnname);
			strncpy(buf255, hook->hook.win->fnname, 254);
			return 1;

		}
		numdlls++;
	}

	return 0;
}

int file_length(FILE *f)
{
	int pos;
	int end;

	pos = ftell (f);
	fseek (f, 0, SEEK_END);
	end = ftell (f);
	fseek (f, pos, SEEK_SET);

	return end;
}

void dumpFlags(struct emu_cpu *c){

	char *fmsg;
	fmsg = (char *)malloc(32*3+1);
	memset(fmsg, 0, 32*3+1);
	int i;
	for ( i=0;i<32;i++ )
	{
		if ( CPU_FLAG_ISSET(c, i) )
		{
			strcat(fmsg, eflagm[i]);
			strcat(fmsg," ");
		}
	}

	start_color(myellow);
	printf(" %s\n", fmsg);
	end_color();

	free(fmsg);

}

void deref_regs(void){

	int i=0;
	int output_addr = 0;
	char ref[255];

	for(i=0;i<8;i++){
		if( fulllookupAddress( cpu->reg[i], (char*)&ref) > 0 ){
			printf("\t%s -> %s\n", regm[i], ref);
			if(output_addr++==3) nl();
		}
	}
	if(output_addr==0) printf("No known values found...");
	nl();
}

void hexdump(unsigned char* str, int len){
	
	char asc[19];
	int aspot=0;
	int i=0;
    int hexline_length = 3*16+4;
	
	char *nl="\n";
	unsigned char *tmp = (unsigned char*)malloc(50);

	printf(nl);

	for(i=0;i<len;i++){

		sprintf(tmp, "%02x ", str[i]);
		printf("%s",tmp);
		
		if( (int)str[i]>20 && (int)str[i] < 123 ) asc[aspot] = str[i];
		 else asc[aspot] = 0x2e;

		aspot++;
		if(aspot%16==0){
			asc[aspot]=0x00;
			sprintf(tmp,"    %s\n", asc);
			printf("%s",tmp);
			aspot=0;
		}

	}

	if(aspot%16!=0){//print last ascii segment if not full line
		int spacer = hexline_length - (aspot*3);
		while(spacer--)	printf("%s"," ");	
		asc[aspot]=0x00;
		sprintf(tmp, "%s\n",asc);
		printf("%s",tmp);
	}
	
	printf("%s",nl);
	free(tmp);


}

//---------------------------------------------------------




int disasm_addr(struct emu *e, int va){  //arbitrary offset
	
	int instr_len =0;
	char disasm[200];
	struct emu_cpu *cpu = emu_cpu_get(e);
	
	uint32_t m_eip     = va;
	instr_len = emu_disasm_addr(cpu, m_eip, disasm); 
	
	int foffset = m_eip - CODE_OFFSET;
	if(foffset < 0) foffset = m_eip; //probably a stack address.

	start_color(mgreen);
	if(opts.verbose ==1){
		if(opts.cur_step % 5 == 0){
			printf("%x   %s\t\t step: %i\n", m_eip, disasm, opts.cur_step );
		}else{
			printf("%x   %s\n", m_eip, disasm);
		}
	}else{
		printf("%x   %s\t\t step: %d  foffset: %x\n", m_eip, disasm, opts.cur_step,  foffset);
	}
	end_color();

	return instr_len;

}



void show_seh(void){
	
	uint32_t seh = 0;
	uint32_t seh_handler = 0;
	
	emu_memory_read_dword( mem, FS_SEGMENT_DEFAULT_OFFSET, &seh);
	emu_memory_read_dword( mem, seh+4, &seh_handler);

	printf("\tPointer to next SEH record = %08x\n\tSE handler: %08x\n", seh, seh_handler);
	//todo: walk chain? probably not necessary for shellcode..

}

void show_disasm(struct emu *e){  //current line

	uint32_t m_eip = emu_cpu_eip_get(emu_cpu_get(e));

	disasm_addr(e,m_eip);

	if(opts.time_delay > 0){
		if(opts.verbose ==1 || opts.verbose ==2) usleep(opts.time_delay * 1000);
	}

}

unsigned int read_hex(char* prompt, char* buf){
	unsigned int base = 0;
	int nBytes = 20;
	int i=0;

	printf("%s: (hex/reg) 0x", prompt);
	getline(&buf, &nBytes, stdin);

	if(strlen(buf)==4){
		for(i=0;i<8;i++){
			if(strstr(buf, regm[i]) > 0 ){
				base = cpu->reg[i];
				//printf("found register! %s = %x\n", regm[i], base);
				break;
			}
		}
	}

	if(base==0){
		base = strtol(buf, NULL, 16); //support negative numbers..
		if(base == INT32_MAX) base = strtoul(buf, NULL, 16); //but in this case assume unsigned val entered
	}

	printf("%x\n",base);

	return base;
}

int read_string(char* prompt, char* buf){
	int nBytes = 20;
	int i=0;

	printf("%s", prompt);
	getline(&buf, &nBytes, stdin);
	i = strlen(buf);
	if(i>0) buf[i-1] = 0; //strip new line
	nl();
	return i-1;
}


unsigned int read_int(char* prompt, char* buf){
	unsigned int base = 0;
	int nBytes = 20;
	int i=0;

	printf("%s: (int/reg) ", prompt);
	getline(&buf, &nBytes, stdin);

	if(strlen(buf)==4){
		for(i=0;i<8;i++){
			if(strstr(buf, regm[i]) > 0 ){
				base = cpu->reg[i];
				//printf("found register! %s = %x\n", regm[i], base);
				break;
			}
		}
	}

	if(base==0) base = atoi(buf);
	printf("%d\n",base);

	return base;
}

void show_stack(void){
	
	int i=0;
	uint32_t curesp = emu_cpu_reg32_get(cpu ,esp);
	uint32_t mretval=0;
	char buf[255];

	for(i = -16; i<=24;i+=4){
		emu_memory_read_dword(mem,curesp+i,&mretval);
		fulllookupAddress(mretval, (char*)&buf);
		if(i<0){
			printf("[ESP - %-2x] = %08x\t%s\n", abs(i), mretval, buf);
		}else if(i==0){
			printf("[ESP --> ] = %08x\t%s\n", mretval, buf);
		}else{
			printf("[ESP + %-2x] = %08x\t%s\n", i, mretval, buf);
		}
	}
	
}

void savemem(void){
	FILE *fp;
	char fname[255];
	char tmp[255];

	int base = read_hex("Enter base address to dump", (char*)&tmp);
	int size = read_hex("Enter size to dump", (char*)&tmp);

	if(base < 1 || size < 1){
		printf("Invalid base (%x) or size (%x)", base,size);
		return;
	}

	void* buf = malloc(size);

	if(emu_memory_read_block(mem,base,buf,size) == -1){
		printf("Failed to read block...\n");
	}else{
		sprintf(fname,"memdump_0x%x-0x%x.bin", base, base+size);
		fp = fopen(fname,"wb");
		fwrite(buf,1,size,fp);
		fclose(fp);
		printf("Dump saved to %s\n", fname);
	}

	free(buf);
	
}

void show_debugshell_help(void){
	printf( 
			"\n"
			"\t? - help, this help screen, h also works\n"
			"\tv - change verbosity (0-4)\n"
			"\tg - go - continue with v=0 \n"
			"\ts - step, continues execution, ENTER also works\n"
			"\tc - reset step counter\n"
			"\tr - execute till return (v=0 recommended)\n"
			"\tu - unassembled address\n"
			"\tb - break at address\n"
			"\tm - reset max step count (-1 = infinate)\n"
			"\te - set eip\n"
			"\tw - dWord dump,(32bit ints) prompted for hex base addr and then size\n"
			"\td - Dump Memory (hex dump) prompted for hex base addr and then size\n"
			"\tx - execute x steps (use with reset step count)\n"
			"\tt - set time delay (ms) for verbosity level 1/2\n"
			"\tk - show stack\n"
			"\ti - break at instruction (scans disasm for next string match)\n"
			"\tf - dereF registers (show any common api addresses in regs)\n"  
			"\t.so - step over (macro for exec return v 0\n" 
			"\t.lp - lookup - get symbol for address\n"  
			"\t.pl - reverse lookup - get address for symbol\n"  
			"\t.seh - shows current value at fs[0]\n"
			"\t.reg - manually set register value\n"
			"\t.poke1 - write a single byte to memory\n"
			"\t.poke4 - write a 4 byte value to memory\n"
			"\t.savemem - saves a memdump of specified range to file\n"
			"\tq - quit\n\n"
		  );
}

//we can build this out to be more as we need it..not gonna get crazy off the bat...
void interactive_command(struct emu *e){

	
	printf("\n");

	//struct emu_memory *mem = 0;  //global now
	//mem = emu_memory_get(e);
    
	disable_mm_logging = true;

	char *buf=0;
	char *tmp = (char*)malloc(21);
	char lookup[255];
	unsigned int base=0;
	unsigned int size=0;
	unsigned int i=0;
	int bytes_read=0;
	char x[2]; x[1]=0;
    //uint8_t byte = 0;

	while(1){

		printf("dbg> ");

		char c = getchar();
		//if(c!='.') nl();

		if(c=='q'){ opts.steps =0; break; }
		if(c=='g'){ opts.verbose =0; break; }
		if(c=='s' || c== 0x0A) break;
		if(c=='?' || c=='h') show_debugshell_help();
		if(c=='f') deref_regs();
		if(c=='k'){ nl(); show_stack(); nl();}
		if(c=='c'){ opts.cur_step = 0; printf("Step counter has been zeroed\n"); }
		if(c=='t') opts.time_delay = read_int("Enter time delay (1000ms = 1sec)", tmp);
		if(c=='r'){ opts.exec_till_ret = true; printf("Exec till ret set. Set verbosity < 3 and step.\n"); }

		if(c=='.'){  //dot commands
			i = read_string("",tmp);
			if(i>0){
				if(strcmp(tmp,"seh")==0) show_seh();
				if(strcmp(tmp,"savemem")==0) savemem();
				if(strcmp(tmp,"so")==0){
					opts.exec_till_ret = true;
					opts.verbose = 0;
					break;
				}
				if(strcmp(tmp,"pl")==0){
					i = read_string("Enter symbol to lookup address for: ", tmp);
					symbol_lookup(tmp);
				}
				if(strcmp(tmp,"lp")==0){
					base = read_hex("Enter address to do a lookup on", tmp);
					if(base > 0){
						if( fulllookupAddress(base, (char*)&lookup) > 0){
							printf("\tFound: %s\n", lookup);
						}
					}
				}
				if(strcmp(tmp,"poke4")==0){
					base = read_hex("Enter address to write to", tmp);
					if(base > 0){
						 i = read_hex("Enter value to write", tmp);
						 emu_memory_write_dword(mem,base,i);
					}
				}
				if(strcmp(tmp,"poke1")==0){
					base = read_hex("Enter address to write to", tmp);
					if(base > 0){
						 i = read_hex("Enter value to write", tmp);
						 emu_memory_write_byte(mem,base,(uint8_t)i);
					}
				}
				if(strcmp(tmp,"reg")==0){
					base = read_string("Enter register name to modify:", tmp);
					if(base > 0){
						for(i=0;i<8;i++){
							if(strcmp(regm[i], tmp)==0) break;
						}
						if(i < 8){
							printf("set %s to", regm[i]);
							base = read_hex("", tmp);
							cpu->reg[i] = base;
							nl();
							debugCPU(e,true);
						}
					}
				}
			}
		}

		if(c=='i'){
			i = read_string("Enter the disasm instruction you want to break at:", tmp);
			if(opts.break_at_instr != 0) free(opts.break_at_instr); 
			if(i > 0){
				opts.break_at_instr = strdup(tmp);
				printf("Will break when we see %s in disasm, set verbosity and step", opts.break_at_instr);
			}
		}

		if(c=='x'){
			base = read_int("Execute x steps",tmp);
			opts.log_after_step = base;
			printf("Log after step updated. Now clear steps, set verbosity < 3 and step\n");
		}

		if(c=='v'){
			printf("Enter desired verbosity (0-3):");
			x[0] = getchar();
			opts.verbose = atoi(x);
			printf("%i\n", opts.verbose );
		}

		if(c=='m'){
			base = read_int("Reset Max step count",tmp);
			if(base==0){ printf("Failed to get value...\n");}
			else{ opts.steps = base;}
		}

		if(c=='e'){
			base = read_hex("Set eip", tmp);
			if(base==0){ printf("Failed to get value...\n");}
			else{ emu_cpu_eip_set(emu_cpu_get(e), base);}
		}

		if(c=='u'){
			base = read_hex("Disassemble address",tmp);
			size = read_int("Number of instructions to dump (max 100)", tmp);
			if(size > 100) size = 100;
			for(i=0;i<size;i++){
				bytes_read = disasm_addr(e,base);
				if(bytes_read < 1) break;
				base += bytes_read;
			}
		}

		if(c=='b'){
			opts.log_after_va = read_hex("Break at address",tmp);
			printf("Log after address updated. Now set verbosity < 3 and step\n");
		}

		if(c=='d'){
			base = read_hex("Enter hex base to dump", tmp);
			size = read_hex("Enter hex size",tmp);

			buf = (char*)malloc(size);
			if(emu_memory_read_block(mem, base, buf,  size) == -1){
				printf("Memory read failed...\n");
			}else{
				hexdump(buf,size);
			}
			free(buf);

		}

		if(c=='w'){
			base = read_hex("Enter hex base to dump", tmp);
			size = read_hex("Enter words to dump",tmp);
			int rel = read_int("Show relative offset? (1/0)", tmp);			

			for(i=0;i<size;i++){
				if(emu_memory_read_dword(mem, base+(i*4), &bytes_read) == -1){
					printf("Memory read of %x failed \n", base+(i*4) );
					break;
				}else{
					fulllookupAddress(bytes_read,(char*)&lookup);
					if(rel > 0){
						printf("[x + %-2x]\t%08x\t%s\n", (i*4), bytes_read, lookup );
					}else{
						printf("%08x\t%08x\t%s\n", base+(i*4), bytes_read, lookup);
					}
				}
			}

		}

	}

	printf("\n");
	free(tmp);
	disable_mm_logging = false;

}


void debugCPU(struct emu *e, bool showdisasm){

	int i=0;
	//struct emu_memory *m = emu_memory_get(e);

	if (opts.verbose == 0) return;

	//verbose 1= offset opcodes disasm step count every 5th hit
	//verbose 2= adds register and flag dump
	//verbose 3= adds interactive shell 
	//verbose 4= adds stack dump

	if(showdisasm) show_disasm(e);

	if (opts.verbose < 2) return;

	//show registers 
	for(i=0;i<8;i++){
		printf("%s=%-8x  ", regm[i], emu_cpu_reg32_get(emu_cpu_get(e),i) );
		if(i==3)printf("\n");
	}

	dumpFlags(emu_cpu_get(e));
	printf("\n");

	if (opts.verbose < 3) return;
	if(opts.verbose > 3) show_stack();

	interactive_command(e);

	return;

}

void set_hooks(struct emu_env *env,struct nanny *na){

	/* (as far as i understand it..)
	   api function hooking in libemu works in 3 layers. first the addresses
	   of each api are kept in a table with api name, pointer to libemudll primary hook 
	   and pointer to a secondary user hook.
	   
	   if execution is sent to one of these addresses, then the libemu dll primary hook
	   is called, which handles stack cleanup, arg dereferencing, setting return
	   address, and setting eip to return value on stack. If a user hook has been
	   set with emu_env_w32_export_hook, then the libemu dll hook will (in most cases)
	   call the user hook. In the original dll, not all libemu hooked functions supported
	   setting user hooks. That is one update i did. The second update was a new export
	   called emu_env_w32_export_new_hook which allows application developers to set
	   primary hooks for api functions which are unimplemented by the dll itself. 
	   
	   If you want to use this note that the function prototype is slightly different, 
	   and you will now be the one responsible for the emu stack cleanup and resetting
	   eip to return address at completion of your function. This mod allows for the development
	   and testing of new hooks in applications without requiring further modifications to the
	   dll itself. -dzzie
	*/

	emu_env_w32_load_dll(env->env.win,"user32.dll");
	emu_env_w32_load_dll(env->env.win,"shell32.dll");
	emu_env_w32_load_dll(env->env.win,"msvcrt.dll");
	emu_env_w32_load_dll(env->env.win,"urlmon.dll");
	emu_env_w32_load_dll(env->env.win,"ws2_32.dll");

	emu_env_w32_export_hook(env, "ExitProcess", user_hook_ExitProcess, NULL);
	emu_env_w32_export_hook(env, "ExitThread", user_hook_ExitThread, NULL);
	emu_env_w32_export_hook(env, "CreateProcessA", user_hook_CreateProcess, NULL);
	emu_env_w32_export_hook(env, "WaitForSingleObject", user_hook_WaitForSingleObject, NULL);
	emu_env_w32_export_hook(env, "CreateFileA", user_hook_CreateFile, na);
	emu_env_w32_export_hook(env, "WriteFile", user_hook_WriteFile, na);
	emu_env_w32_export_hook(env, "CloseHandle", user_hook_CloseHandle, na);
	emu_env_w32_export_hook(env, "fclose", user_hook_fclose, na);
	emu_env_w32_export_hook(env, "fopen", user_hook_fopen, na);
	emu_env_w32_export_hook(env, "fwrite", user_hook_fwrite, na);
	emu_env_w32_export_hook(env, "accept", user_hook_accept, NULL);
	emu_env_w32_export_hook(env, "bind", user_hook_bind, NULL);
	emu_env_w32_export_hook(env, "closesocket", user_hook_closesocket, NULL);
	emu_env_w32_export_hook(env, "connect", user_hook_connect, NULL);
	emu_env_w32_export_hook(env, "listen", user_hook_listen, NULL);
	emu_env_w32_export_hook(env, "recv", user_hook_recv, NULL);
	emu_env_w32_export_hook(env, "send", user_hook_send, NULL);
	emu_env_w32_export_hook(env, "socket", user_hook_socket, NULL);
	emu_env_w32_export_hook(env, "WSASocketA", user_hook_WSASocket, NULL);
	emu_env_w32_export_hook(env, "URLDownloadToFileA", user_hook_URLDownloadToFile, NULL);
	emu_env_linux_syscall_hook(env, "exit", user_hook_exit, NULL);
	emu_env_linux_syscall_hook(env, "socket", user_hook_socket, NULL);


	//-----------------------added dz(+ support in dll also)
	emu_env_w32_export_hook(env, "GetProcAddress", user_hook_GetProcAddress, NULL);
	emu_env_w32_export_hook(env, "GetSystemDirectoryA", user_hook_GetSystemDirectoryA, NULL);
	emu_env_w32_export_hook(env, "GetTickCount", user_hook_GetTickCount, NULL);
	emu_env_w32_export_hook(env, "LoadLibraryA", user_hook_LoadLibraryA, NULL);
	emu_env_w32_export_hook(env, "_lcreat", user_hook__lcreat, na);
	emu_env_w32_export_hook(env, "_lwrite", user_hook__lwrite, na);
	emu_env_w32_export_hook(env, "_lclose", user_hook__lclose, na);
	emu_env_w32_export_hook(env, "malloc", user_hook_malloc, NULL);
	emu_env_w32_export_hook(env, "memset", user_hook_memset, NULL);
	emu_env_w32_export_hook(env, "SetUnhandledExceptionFilter", user_hook_SetUnhandledExceptionFilter, NULL);
	emu_env_w32_export_hook(env, "WinExec", user_hook_WinExec, NULL);
	emu_env_w32_export_hook(env, "DeleteFileA", user_hook_DeleteFileA, NULL);
	emu_env_w32_export_hook(env, "GetVersion", user_hook_GetVersion, NULL);
	emu_env_w32_export_hook(env, "GetTempPathA", user_hook_GetTempPath, NULL);
	emu_env_w32_export_hook(env, "Sleep", user_hook_Sleep, NULL);
	emu_env_w32_export_hook(env, "VirtualProtect", user_hook_VirtualProtect, NULL);
	emu_env_w32_export_new_hook(env, "GetModuleHandleA", new_user_hook_GetModuleHandleA, NULL);
	emu_env_w32_export_new_hook(env, "GlobalAlloc", new_user_hook_GlobalAlloc, NULL);
	emu_env_w32_export_new_hook(env, "CreateProcessInternalA", new_user_hook_CreateProcessInternalA, NULL);
	emu_env_w32_export_new_hook(env, "MessageBoxA", new_user_hook_MessageBoxA, NULL);
	emu_env_w32_export_new_hook(env, "ShellExecuteA", new_user_hook_ShellExecuteA, NULL);
	emu_env_w32_export_new_hook(env, "SHGetSpecialFolderPathA", new_user_hook_SHGetSpecialFolderPathA, NULL);
	emu_env_w32_export_new_hook(env, "MapViewOfFile", new_user_hook_MapViewOfFile, NULL);
	emu_env_w32_export_new_hook(env, "URLDownloadToCacheFileA", new_user_hook_URLDownloadToCacheFileA, NULL);
	emu_env_w32_export_new_hook(env, "system", new_user_hook_system, NULL);
	emu_env_w32_export_new_hook(env, "VirtualAlloc", new_user_hook_VirtualAlloc, NULL);

	//-----handled by the generic stub
	emu_env_w32_export_new_hook(env, "GetFileSize", new_user_hook_GenericStub, NULL);
	emu_env_w32_export_new_hook(env, "CreateFileMappingA", new_user_hook_GenericStub, NULL);



}



/* 
	FS:[00000000]=[7FFDF000]=0012FF98
	0012FF98  0012FFE0  Pointer to next SEH record
	0012FF9C  0040140B  SE handler

	- set registers for exception (observed from debugger not sure of actual docs)
	- zero out eax, ebx, esi, edi
	- set ecx to handler address
	- set edx to next handler 
	- [ESP+8] must = esp before exception
		- add 8 to esp and write value there to be current esp
	
	seems to work, done from observed tested in olly - dzzie

    todo: should we also check the UnhandledExceptionFilter here if its set?
*/
int handle_seh(struct emu *e,int last_good_eip){
			
		int i=0;
		int regs[8];
	    uint32_t seh = 0;
		uint32_t seh_handler = 0;
		struct emu_memory *m = emu_memory_get(e);
		
		//lets check and see if an exception handler has been set
		if(emu_memory_read_dword( m, FS_SEGMENT_DEFAULT_OFFSET, &seh) == -1) return -1;
		if(emu_memory_read_dword( m, seh+4, &seh_handler) == -1) return -1;
		if(seh_handler == 0) return -1; //better to check to see if code section huh?

		start_color(myellow);
		printf("\n%x\tException caught SEH=0x%x (seh foffset:%x)\n", last_good_eip, seh_handler, seh_handler - CODE_OFFSET);
		
		//now take our saved esp, add two ints to stack (subtract 8) and set org esp pointer there.
		uint32_t cur_esp = emu_cpu_reg32_get( emu_cpu_get(e), esp);
		uint32_t new_esp = cur_esp - 8; //make room on stack for seh args
		
		if (opts.verbose >= 1) printf("\tcur_esp=%x new_esp=%x\n\n",cur_esp,new_esp); 
		end_color();
		
		debugCPU(e,false);

		emu_cpu_eip_set(emu_cpu_get(e), seh_handler);

		regs[eax] = 0;
		regs[ebx] = 0;
		regs[esi] = 0;
		regs[edi] = 0;
		regs[ecx] = seh_handler;
		regs[edx] = 0xDEADBEEF; //unsure what this is was some ntdll addr 0x7C9032BC
		regs[esp] = new_esp;

		//update the registers with our new values
		for (i=0;i<8;i++) emu_cpu_reg32_set( emu_cpu_get(e), i , regs[i]);

		uint32_t write_at  = new_esp + 8;
		emu_memory_write_dword(m, write_at, cur_esp); //write saved esp to stack

		return 0; //dont break in final error test..give it a chance...to work in next step

}

int run_sc(void)
{

	int i =  0;
	int j =  0;
	int ret;
	void* stack;
	int stacksz;
	char disasm[200];
    bool firstchance = true;
	int static_offset = CODE_OFFSET;
	uint32_t eipsave = 0;
	bool parse_ok = false;
	struct emu_vertex *last_vertex = NULL;
	struct emu_graph *graph = NULL;
	struct emu_hashtable *eh = NULL;
	struct emu_hashtable_item *ehi = NULL;

	int regs[] = {0,    0,      0,     0,  0x12fe00,0x12fff0  ,0,    0};
	//            0      1      2      3      4      5         6      7    
	//*regm[] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};
	
	//init our global pointers..
	e = emu_new();
	cpu = emu_cpu_get(e);
	mem = emu_memory_get(e);
	env = emu_env_new(e);

	env->profile = emu_profile_new();
	struct nanny *na = nanny_new();

	if ( env == 0 )
	{
		printf("%s \n", emu_strerror(e));
		printf("%s \n", strerror(emu_errno(e)));
		return -1;
	}

	for (i=0;i<8;i++) emu_cpu_reg32_set( emu_cpu_get(e), i , regs[i]);

	stacksz = regs[ebp] - regs[esp] + 500;
	stack = malloc(stacksz);
	memset(stack, 0, stacksz);
	
	//printf("writing initial stack space\n");
	emu_memory_write_block(mem, regs[esp] - 250, stack, stacksz);


	/*  support the topstack method to find k32 base...
		00401003   64:8B35 18000000 MOV ESI,DWORD PTR FS:[18]
		0040100A   AD               LODS DWORD PTR DS:[ESI]
		0040100B   AD               LODS DWORD PTR DS:[ESI]
		0040100C   8B40 E4          MOV EAX,DWORD PTR DS:[EAX-1C]
	*/
	emu_memory_write_dword(mem, FS_SEGMENT_DEFAULT_OFFSET + 0x18, FS_SEGMENT_DEFAULT_OFFSET); //point back to fs0
	emu_memory_write_dword(mem, FS_SEGMENT_DEFAULT_OFFSET + 0x4, 0x00130000); // Top of thread's stack
	emu_memory_write_dword(mem, 0x00130000 - 0x1c, 0x7C800abc); //technically a seh addr in k32 here set to work with the libemu mem map

	/* support seh method to find k32 base */
	emu_memory_write_dword(mem, FS_SEGMENT_DEFAULT_OFFSET + 0, 0x00130000); //address of current seh handler
	emu_memory_write_dword(mem, 0x00130000, 0xFFFFFFFF);   //end of seh chain
	emu_memory_write_dword(mem, 0x00130000+4, 0x7C800abc); //mock handler in k32

	/*  this block no longer necessary after dll PEB modifications 1-32-11
		401016   64A130000000                    mov eax,fs:[0x30]  ;&(PEB)
		40101c   8B400C                          mov eax,[eax+0xc]  ;PEB->Ldr
		40101f   8B701C                          mov esi,[eax+0x1c] ;PEB->Ldr.InInitOrder 
		401022   AD                              lodsd              ;PEB->Ldr.InInitOrder.flink (kernel32.dll)
		401023   8B6820                          mov ebp,[eax+0x20]  InInitOrder[X].module_name (unicode)
		401026   807D0C33                        cmp byte [ebp+0xc],0x33   
	
	unsigned char uni_k32[23] = {
			0x6B, 0x00, 0x65, 0x00, 0x72, 0x00, 0x6E, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x33, 0x00, 0x32, 0x00, 
			0x2E, 0x00, 0x64, 0x00, 0x6C, 0x00, 0x6C
	};
	emu_memory_write_block(mem, 0x252020+0x40, uni_k32, 23 ); //embed the data
	emu_memory_write_dword(mem, 0x252020+0x20, 0x252020+0x40); //embed the pointer
	*/

	//some of the shellcodes look for hooks set on some API, lets add some mem so it exists to check
    emu_memory_write_dword(mem, 0x7df7b0bb, 0x00000000); //UrldownloadToFile

	printf("Writing code to memory\n\n");	
	emu_memory_write_block(mem, static_offset, opts.scode,  opts.size);

	//printf("Setting eip\n");
	emu_cpu_eip_set(emu_cpu_get(e), static_offset + opts.offset);  //+ opts.offset for getpc mode

	set_hooks(env,na);

	if ( opts.graphfile != NULL )
	{
		graph = emu_graph_new();
		eh = emu_hashtable_new(2047, emu_hashtable_ptr_hash, emu_hashtable_ptr_cmp);
	}

//----------------------------- MAIN STEP LOOP ----------------------
	opts.cur_step = -1;
	while(1)
	{
	
		opts.cur_step++;
		j = opts.cur_step;
		ctrl_c_count = 0;

		if(opts.steps >= 0){ //this allows us to use -1 as run till crash..we can ctrl c so
			if(opts.cur_step > opts.steps) break;
		}

		if(emu_cpu_get(e)->eip  == opts.log_after_va) //we hit the requested eip start logging.
		{
			opts.verbose = opts.verbosity_after;
			opts.log_after_va = 0;
			opts.log_after_step = 0;
		}

		if( j == opts.log_after_step && opts.log_after_step > 0 )
		{
			opts.verbose = opts.verbosity_after;
			opts.log_after_step = 0;
			opts.log_after_va = 0;
		}



		if ( cpu->repeat_current_instr == false )
			eipsave = emu_cpu_eip_get(emu_cpu_get(e));

		struct emu_env_hook *hook = NULL;
		struct emu_vertex *ev = NULL;
		struct instr_vertex *iv = NULL;

		if ( opts.graphfile != NULL )
		{

			ehi = emu_hashtable_search(eh, (void *)(uintptr_t)eipsave);
			if ( ehi != NULL )
				ev = (struct emu_vertex *)ehi->value;

			if ( ev == NULL )
			{
				ev = emu_vertex_new();
				emu_graph_vertex_add(graph, ev);

				emu_hashtable_insert(eh, (void *)(uintptr_t)eipsave, ev);
			}
		}

		hook = emu_env_w32_eip_check(env);

		if ( hook != NULL )
		{					
			if ( opts.graphfile != NULL )
			{
				if ( ev->data != NULL && strcmp(hook->hook.win->fnname, "CreateProcessA") == 0)
				{
					ev = emu_vertex_new();
					emu_graph_vertex_add(graph, ev);
				}

//				fnname_from_profile(env->profile, dllhook->fnname);
				iv = instr_vertex_new(eipsave,hook->hook.win->fnname);
				emu_vertex_data_set(ev, iv);

				// get the dll
				int numdlls=0;
				while ( env->env.win->loaded_dlls[numdlls] != NULL )
				{
					if ( eipsave > env->env.win->loaded_dlls[numdlls]->baseaddr && 
						 eipsave < env->env.win->loaded_dlls[numdlls]->baseaddr + env->env.win->loaded_dlls[numdlls]->imagesize )
					{
						iv->dll = env->env.win->loaded_dlls[numdlls];
					}
					numdlls++;
				}

			}

			if ( hook->hook.win->fnhook == NULL )
			{
				printf("unhooked call to %s\n", hook->hook.win->fnname);
				break;
			}

		}
		else
		{

			if(firstchance == false){ //we are in our seh handled code now debugging stuff here.
					debugCPU(e,true);
			}

			ret = 0;
			parse_ok = true;
			if(opts.verbose > 0) show_disasm(e);

//--- PARSE
			ret = emu_cpu_parse(emu_cpu_get(e));

			if(ret == -1){ parse_ok = false; }  // FOR SEH


			struct emu_env_hook *hook =NULL;
			if ( ret != -1 )
			{

				if ( ( hook = emu_env_linux_syscall_check(env)) != NULL )
				{
					if ( opts.graphfile != NULL && ev->data == NULL )
					{
						iv = instr_vertex_new(eipsave, hook->hook.lin->name);
						emu_vertex_data_set(ev, iv);
						iv->syscall = hook->hook.lin;
					}
				}
				else
				{

					if ( opts.graphfile != NULL && ev->data == NULL )
					{
						iv = instr_vertex_new(eipsave, emu_cpu_get(e)->instr_string);
						emu_vertex_data_set(ev, iv);
					}
				}
			}
			else
			{
				if ( opts.graphfile != NULL && ev->data == NULL )
				{
					iv = instr_vertex_new(eipsave, "ERROR");
					emu_vertex_data_set(ev, iv);
				}
			}

			if ( ret != -1 )
			{
				if ( hook != NULL )
				{
					if ( hook->hook.lin->fnhook != NULL )
						hook->hook.lin->fnhook(env, hook);
					else
						break;

				}
				else
				{

/*----- STEP------*/    ret = emu_cpu_step(emu_cpu_get(e));

						if(ret != -1)  //step was ok
						{ 
							last_good_eip = emu_cpu_eip_get(emu_cpu_get(e)); //used in case of seh exception
							if(opts.exec_till_ret == true){
								emu_disasm_addr(emu_cpu_get(e),last_good_eip,disasm);
								if(strstr(disasm,"ret") > 0){
									opts.exec_till_ret = false;
									opts.verbose = 3; //interactive dbg prompt
									show_disasm(e);
									start_color(myellow);
									printf("Exec till return hit!\n");
									end_color();
								}
							}
							if(opts.break_at_instr != 0){
								emu_disasm_addr(emu_cpu_get(e),last_good_eip,disasm);
								if(strstr(disasm, opts.break_at_instr) > 0){
									opts.verbose = 3; //interactive dbg prompt
									show_disasm(e);
									start_color(myellow);
									printf("Break at instruction hit!\n");
									end_color();
								}
							}
							firstchance = true;						//step was ok..give it another chance at exception.
							if(opts.verbose > 0) debugCPU(e,false);	//now show the registers after the instruction executed 
						}
					
				} //end hook != null
				
			} // end ret != -1


//SEH HANDLER CODE
			if ( ret == -1 && firstchance && parse_ok) 
			{				
				firstchance = false;
				disable_mm_logging = true;
				ret = handle_seh(e, last_good_eip);
				disable_mm_logging = false;
			} 


			if ( ret == -1 )  //unhandled error time to bail
			{
				if(opts.verbose < opts.verbosity_onerr)	opts.verbose = opts.verbosity_onerr; 

				start_color(mred);
				printf("%x\t %s", emu_cpu_eip_get(emu_cpu_get(e)), emu_strerror(e)); 
				end_color();

				debugCPU(e,true);
				
				break;
			}


		}  //---------------------- end of step loop



		if ( opts.graphfile != NULL )
		{
			if ( last_vertex != NULL )
			{
				struct emu_edge *ee = emu_vertex_edge_add(last_vertex, ev);
				struct emu_cpu *cpu = emu_cpu_get(e);
				if ( cpu->instr.is_fpu == 0 && cpu->instr.source.cond_pos == eipsave && cpu->instr.source.has_cond_pos == 1 )
					ee->data = (void *)0x1;
			}

			last_vertex = ev;
		}

//			printf("\n");
	}

	printf("\nstepcount %i\n",j);

//--------------------------------------- END OF STEP LOOP ---------------------------------

		//------------------ [ dump decoded buffer added dzzie ] ----------------------
	if(opts.dump_mode && opts.file_mode){
		unsigned char* tmp ;
		char* tmp_path;
		int ii;

		printf("Final buffer: Reading 0x%x bytes from 0x%x\n", opts.size, CODE_OFFSET);
		tmp = (unsigned char*)malloc(opts.size);
   		
		if(emu_memory_read_block(mem, CODE_OFFSET, tmp,  opts.size) == -1){
			printf("ReadBlock failed!\n");
		}else{
   		 
			printf("Scanning for changes...\n");
			for(ii=0;ii<opts.size;ii++){
				if(opts.scode[ii] != tmp[ii]) break;
			}

			if(ii < opts.size){
				tmp_path = (char*)malloc( strlen(opts.sc_file) + 15);
				strcpy(tmp_path, opts.sc_file);
				sprintf(tmp_path,"%s.unpack",tmp_path);

				start_color(myellow);
				printf("Change found at %i dumping to %s\n",ii,tmp_path);
			
				FILE *fp;
				fp = fopen(tmp_path, "wb");
				if(fp==0){
					printf("Failed to create file\n");
				}else{
					fwrite(tmp, 1, opts.size, fp);
					fclose(fp);
					printf("Data dumped successfully to disk");
				}
				end_color();
			}else{
				printf("No changes found dump not created.\n");
			}

		}
	}
    //------------------ [ dump decoded buffer added dzzie ] ----------------------

	if(opts.mem_monitor){
		//printf("\n%s\n", mm_log);
		printf("\nMemory Monitor Log:\n");
		i=0;
		while(mm_points[i].address != 0){
			if(mm_points[i].hitat != 0){
				printf("\t%s accessed at 0x%x\n", mm_points[i].name, mm_points[i].hitat);
			}
			i++;
		}
	}


	if ( opts.graphfile != NULL )
	{
		graph_draw(graph);
	}

/*
	emu_profile_debug(env->profile);

	if (opts.profile_file)
		emu_profile_dump(env->profile, opts.profile_file);

	if (eh != NULL)
		emu_hashtable_free(eh);

	if (graph != NULL)
		emu_graph_free(graph);

*/

	emu_env_free(env);
	return 0;
}

int getpctest(void)
{
	struct emu *e = emu_new();
	int offset=0;

	if ( opts.verbose > 1 )
	{
		emu_cpu_debugflag_set(emu_cpu_get(e), instruction_string);
		emu_log_level_set(emu_logging_get(e),EMU_LOG_DEBUG);
	}
	
	if ( (offset = emu_shellcode_test(e, (uint8_t *)opts.scode, opts.size)) >= 0 ){
		printf("Shellcode detected at offset = 0x%08x\n", offset);
		printf("Would you like to start execution there? (y/n):");
		offset = getchar() == 'y' ? offset : -1;
	}
	else{
		printf("Did not detect any shellcode in the file\n");
		offset = -1;
	}
	emu_free(e);

	return offset;
}


void print_help(void)
{
	struct help_info 
	{
		const char *short_param;
		const char *args;
		const char *description;
	};

	struct help_info help_infos[] =
	{
		{"hex", NULL,      "show hex dumps for hook reads/writes"},
		{"findsc", NULL ,  "Scans file for possible shellcode buffers (getpc mode)"},
		{"foff", "hexnum" ,"starts execution at file offset"},
		{"mm", NULL,       "enables Memory Monitor to log access to key addresses."},
		{"S", "< file.sc", "read shellcode/buffer from stdin"},
		{"f", "fpath"    , "load shellcode from file specified."},
		{"o", "hexnum"   , "base offset to use (default: 0x401000)"},
		{"redir", "ip:port","redirect connect to ip (port optional)"},
		{"G", "fpath"    , "save a dot formatted callgraph in filepath"},
		{"i",  NULL		 , "enable interactive hooks"},
		{"v",  NULL		 , "verbosity, can be used up to 4 times, ex. /v /v /vv"},
		{"e", "int"	     , "verbosity on error (3 = debug shell)"},
		{"t", "int"	     , "time to delay (ms) between steps when v=1 or 2"},
		{"h",  NULL		 , "show this help"},
		{"bp", "hexnum"  , "set breakpoint (shortcut for -laa <hexaddr> -vvv)"},
		{"a",  NULL		 , "adjust offsets to file offsets not virtual"},
		{"d",  NULL	     , "dump unpacked shellcode if changed (requires /f)"},
		{"las", "int"	 , "log at step ex. -las 100"},
		{"laa", "hexnum" , "log at address ex. -laa 0x401020"},
		{"s", "int"	     , "max number of steps to run (def=1000000, -1 unlimited)"},
	};

	int i;

	 printf("\t\t _______________\n");
	 printf("\t\t|               |\n");
	 printf("\t\t|               |\n");
	 printf("\t\t|    libemu     |\n");
	 printf("\t\t| x86 emulation |\n");
	 printf("\t\t|               |\n");
	 printf("\t\t|               |\n");
	 printf("\t\t|               |\n");
	 printf("\t\t\\ O             |\n");
	 printf("\t\t \\______________|   build: 0.2.dz\n\n");

	 printf("\t-----[ libemu - x86 shellcode emulation ]-----\n");
	 printf("\tCopyright (C) 2007  Paul Baecher & Markus Koetter\n\n");

	for (i=0;i<sizeof(help_infos)/sizeof(struct help_info); i++)
	{
		printf("  /%1s ", help_infos[i].short_param);

		if (help_infos[i].args != NULL)
			printf("%-12s ", help_infos[i].args);
		else
			printf("%12s "," ");

		printf("\t%s\n", help_infos[i].description);
	}

	printf("\n   dbg> shell prompt commands:");
	show_debugshell_help();
	exit(0);

}


/*
	this func may be a bit verbose and ugly, but I cant crash it or get it to bug out
	so I cant gather the will to change it. plus I have no shame 
	step 1..make it work. step 2 use it  -dzzie
*/
void parse_opts(int argc, char* argv[] ){

	int i;
	int sl=0;
	char buf[5];

	memset(&opts,0,sizeof(struct run_time_options));

	opts.offset = 0;
	opts.steps = 1000000;
	opts.file_mode = false;
	opts.dump_mode = false;
	opts.getpc_mode = false;
	opts.mem_monitor = false;


	for(i=1; i < argc; i++){
					
		sl = strlen(argv[i]);

		if( argv[i][0] == '-') argv[i][0] = '/'; //standardize

		buf[0] = argv[i][0];
		buf[1] = argv[i][1];
		buf[2] = '0';
		 		
		if(strstr(buf,"/a") > 0 ) opts.adjust_offsets = true ;
		if(strstr(buf,"/i") > 0 ) opts.interactive_hooks = 1;
		if(strstr(buf,"/v") > 0 ) opts.verbose++;	
		if(sl==4 && strstr(argv[i],"/hex") > 0 )  opts.show_hexdumps = true;
		if(sl==7 && strstr(argv[i],"/findsc") > 0 ) opts.getpc_mode = true;
		if(sl==5 && strstr(argv[i],"/vvvv") > 0 ) opts.verbose = 4;
		if(sl==4 && strstr(argv[i],"/vvv") > 0 )  opts.verbose = 3;
		if(sl==3 && strstr(argv[i],"/vv")  > 0 )  opts.verbose = 2;
		if(sl==3 && strstr(argv[i],"/mm")  > 0 )  opts.mem_monitor = true;
		if(strstr(buf,"/d") > 0 ) opts.dump_mode = true;
		if(sl==2 && strstr(buf,"/h") > 0 ) print_help();
		if(strstr(buf,"/S") > 0 ) opts.from_stdin = true;

		if(sl==2 && strstr(buf,"/f") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /f must specify a file path as next arg\n");
				exit(0);
			}
			strncpy(opts.sc_file, argv[i+1],499);
			opts.file_mode = true;
		}

		if(strstr(buf,"/o") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /o must specify a hex base addr as next arg\n");
				exit(0);
			}
		    CODE_OFFSET = strtol(argv[i+1], NULL, 16);			
		}

		if(sl==5 && strstr(argv[i],"/foff") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /foff must specify start file offset as next arg\n");
				exit(0);
			}
			opts.offset = strtol(argv[i+1], NULL, 16);
		}

		if(sl==3 && strstr(argv[i],"/bp") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /bp must specify hex breakpoint addr as next arg\n");
				exit(0);
			}
		    opts.log_after_va = strtol(argv[i+1], NULL, 16);
			opts.verbosity_after = 3;
		}

		if(sl==4 && strstr(argv[i],"/laa") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /laa must specify a hex addr as next arg\n");
				exit(0);
			}
		    opts.log_after_va = strtol(argv[i+1], NULL, 16);			
		}

		if(sl==6 && strstr(argv[i],"/redir") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /redir must specify IP:PORT as next arg\n");
				exit(0);
			}
		    opts.override.connect.host = strdup(argv[i+1]);
			char *port;
			if (( port = strstr(opts.override.connect.host, ":")) != NULL)
			{
				*port = '\0';
				port++;
				opts.override.connect.port = atoi(port);

				if (*opts.override.connect.host == '\0')
				{
					free(opts.override.connect.host);
					opts.override.connect.host = NULL;
				}

			}			
		}

		if(sl==4 && strstr(argv[i],"/las") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /las must specify a integer as next arg\n");
				exit(0);
			}
		    opts.log_after_step  = atoi(argv[i+1]);			
		}

		if(strstr(buf,"/e") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /e must specify err verbosity as next arg\n");
				exit(0);
			}
		    opts.verbosity_onerr = atoi(argv[i+1]);			
		}

		if(strstr(buf,"/s") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /s must specify num of steps as next arg\n");
				exit(0);
			}
		    opts.steps = atoi(argv[i+1]);			
		}

		if(strstr(buf,"/t") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /t must specify delay in millisecs as next arg\n");
				exit(0);
			}
		    opts.time_delay = atoi(argv[i+1]);			
		}

		if(strstr(buf,"/G") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /G must specify graph path as next arg\n");
				exit(0);
			}
		    opts.graphfile = strdup(argv[i+1]);
			printf("graph file %s\n", opts.graphfile);			
		}

	}


}

void loadsc(void){

	FILE *fp;

	if ( opts.file_mode  ){
	
		opts.from_stdin = true;
		fp = fopen(opts.sc_file, "rb");
		if(fp==0){
			start_color(myellow);
			printf("Failed to open file %s\n",opts.sc_file);
			end_color();
			exit(0);
		}
		opts.size = file_length(fp);
		opts.scode = (unsigned char*)malloc(opts.size);
		fread(opts.scode, 1, opts.size, fp);
		fclose(fp);
		printf("Loaded %x bytes from file %s\n", opts.size, opts.sc_file);

	}
	else if ( opts.from_stdin )
	{
		unsigned buffer[BUFSIZ];
		int ret, eof=0;
		int16_t bytes_read=0;
		uint32_t len=0;
		fd_set read_fds;
		struct timeval st;

		while ( !eof )
		{
			FD_ZERO(&read_fds);
			FD_SET(STDIN_FILENO, &read_fds);

			st.tv_sec  = 10;
			st.tv_usec = 0;

			switch ( ret = select(FD_SETSIZE, &read_fds, NULL, NULL, &st) )
			{
			case -1:
				fprintf(stderr, "Error with select(): %s.\n", strerror(errno));
				exit(1);
			case  0:
				break;
			default:
				if ( FD_ISSET(STDIN_FILENO, &read_fds) )
				{
					if ( (bytes_read = read(STDIN_FILENO, buffer, BUFSIZ)) <= 0 )
					{
						if ( bytes_read == 0 ) eof = 1;
						else
						{
							fprintf(stderr, "Error while reading data: %s.\n", strerror(errno));
							exit(1);
						}
					}
					if ( !eof )
					{
						if ( (opts.scode = (unsigned char *) realloc(opts.scode, len+bytes_read)) == NULL )
						{
							fprintf(stderr, "Error while allocating memory: %s.\n", strerror(errno));
							exit(1);
						}
						memcpy(opts.scode+len, buffer, bytes_read);
						len += bytes_read;
					}
				}
			}
		}
		opts.size = len;
	}
	
	if(opts.size==0){
		printf("No shellcode loaded must use either /f or /S options\n");
		print_help();
		return;
	}

}



int main(int argc, char *argv[])
{
	static struct termios oldt;
	int i=0;

	tcgetattr( STDIN_FILENO, &oldt);
	orgt = oldt;
	oldt.c_lflag &= ~(ICANON | ECHO);                
	tcsetattr( STDIN_FILENO, TCSANOW, &oldt); 

	signal(SIGINT, ctrl_c_handler); //we break into debugger, they can q from there..or x2 to exit
	signal(SIGABRT,restore_terminal);
    signal(SIGTERM,restore_terminal);
	atexit(atexit_restore_terminal);
	
	parse_opts(argc, argv);
	loadsc();

	if(opts.mem_monitor){
		printf("Memory monitor enabled..\n");
		//asprintf(&mm_log, "Memory Monitor Log:\n");
		emu_memory_set_access_monitor((uint32_t)mm_hook);
		while(mm_points[i].address != 0){
			emu_memory_add_monitor_point(mm_points[i++].address);
		}
	}

	if(opts.offset > 0){
		printf("Execution starts at file offset 0x%04x (start byte: %X)\n", opts.offset, opts.scode[opts.offset]);
	}

	if(opts.getpc_mode){
		opts.offset = getpctest();
		if(opts.offset == -1) return 0;
		nl();
	}

	if( opts.override.connect.host != NULL){
		printf("Override connect host active %s\n", opts.override.connect.host);
	}

	if( opts.override.connect.port != 0){
		printf("Override connect port active %d\n", opts.override.connect.port);
	}

	if(opts.log_after_va  > 0 || opts.log_after_step > 0){
		
		if(opts.verbosity_after == 0) opts.verbosity_after =1;
		if(opts.verbose > opts.verbosity_after) opts.verbosity_after = opts.verbose ;
		opts.verbose = 0;
		
		if(opts.log_after_va  > 0){
			printf("Will commence logging at eip 0x%x verbosity: %i\n", opts.log_after_va , opts.verbosity_after );
		}else{
			printf("Will commence logging at step %d verbosity: %i\n", opts.log_after_step , opts.verbosity_after );
		}

	}

	if(opts.file_mode == false && opts.from_stdin == false){
		print_help();
	}

	if(opts.dump_mode){
		if( opts.from_stdin) 
			printf("Dump mode Disabled when getting file from stdin\n"); //no default path to use to lazy to work around
		else
			printf("Dump mode Active...\n");
	};
		
	if(opts.interactive_hooks){
		start_color(myellow);
		printf("Interactive Hooks enabled\n");
		end_color();
	}

	printf("Max Steps: %d\n", opts.steps);
	printf("Using base offset: 0x%x\n", CODE_OFFSET);
	if(opts.verbose>0) printf("Verbosity: %i\n", opts.verbose);

	run_sc();

	tcsetattr( STDIN_FILENO, TCSANOW, &orgt);
	return 0;
	 
}
























