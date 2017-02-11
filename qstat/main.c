#include "strings.h"
#include "win_short.h"
#include "arg_parse.h"
#include "analysis_basic.h"
#include "dispatcher.h"
#include <stdio.h>

int main(int argc, char **argv)
{
	struct arg_parse arg_p;
	unsigned int i;

	printf(SPLASH_TEXT);
#ifdef _WIN64
	printf("64-bit.\n");
#else
	printf("32-bit.\n");
#endif

	arg_parse_init(&arg_p, argc, argv);

	if(!arg_p.file_name_count || arg_p.error_encountered)
	{
		printf(SYNTAX_TEXT);
		goto main_exit;
	}

	for(i=0;i<arg_p.file_name_count;++i)
	{
		struct analysis_base anal;
		if(analysis_init(&anal, arg_p.file_names[i]))
		{
			goto file_exit;
		}
		
		dispatch_all(&anal);

	file_exit:
		print_errors(&anal);
		analysis_free(&anal);
	}

main_exit:
	arg_parse_free(&arg_p);
}
