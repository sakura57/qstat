#include "arg_parse.h"
#include "dispatcher.h"
#include <string.h>

static int(*linked_function[MAX_ANALYZEFUNCS])(struct analysis_base *) =
{
	&analysis_entropy,
	&analysis_imports
};

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
		size_t arg_len = strlen(current_arg);
		if(arg_len > 2 && current_arg[0] == '-' && current_arg[1] == '-')
		{
			register unsigned int flag;
			register unsigned int non_invoker_flag = 0;

			switch(tolower(current_arg[2]))
			{
				case 'e':
					flag = ID_ENTROPY;
					break;
				case 'i':
					flag = ID_IMPORTS;
					break;
				case 'v':
					flag = ID_VERBOSE;
					non_invoker_flag = 1;
					break;
				default:
					arg_p->error_encountered = 1;
					return;
			}

			if(!non_invoker_flag && (arg_p->opts & (1 << flag)) == 0)
			{
				dispatch_add_func(linked_function[flag]);
			}

			arg_p->opts |= 1 << flag;
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
