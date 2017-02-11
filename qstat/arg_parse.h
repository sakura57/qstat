#ifndef _ARG_PARSER_H
#define _ARG_PARSER_H

#include <stdlib.h>
#include <ctype.h>

#define EXPECTED_FILES 4
#define REALLOCATE_INCREMENT 2

#define OPT_ENTROPY 1 << 0

struct arg_parse
{
	unsigned int file_name_count;
	unsigned int file_name_allocated;
	char ** file_names;
	unsigned int opts;
	unsigned int error_encountered;
};

void arg_parse_init(struct arg_parse *, int, char **);
void arg_parse_free(struct arg_parse *);

#endif