
struct run_time_options
{
	int cur_step;
	int verbose;
	uint32_t steps;
	char *graphfile;
	bool from_stdin;
	unsigned char *scode;
	uint32_t size;
	uint32_t offset;
	bool file_mode;
	char sc_file[500];
	bool dump_mode;
	int interactive_hooks;
	bool adjust_offsets;
	int  log_after_va;
	int  log_after_step;
	int  verbosity_after;
	int  verbosity_onerr;
	bool exec_till_ret;
	int  time_delay;
	bool show_hexdumps;
	char* break_at_instr;
	bool  getpc_mode;

	struct 
	{
		struct
		{
			char *host;
			int port;
		}connect;

	}override;

};

extern struct run_time_options opts;

bool cmp(void *a, void *b);
uint32_t hash(void *key);
bool string_cmp(void *a, void *b);
uint32_t string_hash(void *key);


