#include "arg_parse.h"
#include "dispatcher.h"
#include <string.h>

void arg_parse_init(struct arg_parse * arg_p, int argc, char ** argv)
{
	int i;

	arg_p->file_name_count = 0;
	arg_p->file_name_allocated = EXPECTED_FILES;
	arg_p->file_names = (char**)malloc(sizeof(char*) * EXPECTED_FILES);
	arg_p->opts = 0;
	arg_p->error_encountered = 0;

	for(i=1;i<argc;++i)
	{
		char * current_arg = argv[i];
		int arg_len = strlen(current_arg);
		if(arg_len > 2 && current_arg[0] == '-' && current_arg[1] == '-')
		{
			register int flag;
			switch(tolower(current_arg[2]))
			{
				case 'e':
					flag = OPT_ENTROPY;
					break;
				default:
					arg_p->error_encountered = 1;
					return;
			}

			if((arg_p->opts & flag) == 0)
			{
				dispatch_add_func(&analysis_entropy);
			}

			arg_p->opts |= flag;
		}
		else
		{
			if(arg_p->file_name_count == arg_p->file_name_allocated)
			{
				arg_p->file_name_allocated += REALLOCATE_INCREMENT;
				arg_p->file_names = (char**)realloc(arg_p->file_names, sizeof(char*) * arg_p->file_name_allocated);
			}

			arg_p->file_names[arg_p->file_name_count] = current_arg;
			arg_p->file_name_count++;
		}
	}
}

void arg_parse_free(struct arg_parse * arg_p)
{
	free(arg_p->file_names);
}
