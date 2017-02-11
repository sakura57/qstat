#include "dispatcher.h"

static unsigned int analysis_function_count = 1;
static int (*analysis_function[MAX_ANALYZEFUNCS])(struct analysis_base *) =
{
	&analysis_parse_pe,
    0
};

int dispatch_analysis_func(unsigned int func, struct analysis_base *anal)
{
	return (*analysis_function[func])(anal);
}

void dispatch_add_func(int (*new_analysis_func)(struct analysis_base *))
{
	analysis_function[analysis_function_count++] = new_analysis_func;
    analysis_function[analysis_function_count] = 0;
}

int dispatch_all(struct analysis_base *anal)
{
    int i;
    
    for(i=0;i<analysis_function_count;++i)
    {
        unsigned int errors = (*analysis_function[i])(anal);
        if(errors)
        {
            return errors;
        }
    }
    
    return 0;
}
