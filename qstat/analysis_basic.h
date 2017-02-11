#ifndef _ANALYSIS_BASIC_H
#define _ANALYSIS_BASIC_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "strings.h"
#include "win_short.h"

#define ERROR_FILE_NOT_FOUND 1 << 0
#define ERROR_FILE_IS_EMPTY 1 << 1
#define ERROR_ALLOCATION_FAILURE 1 << 2
#define ERROR_FILE_READ_FAILURE 1 << 3
#define ERROR_NOT_AN_EXECUTABLE 1 << 4
#define ERROR_INVALID_OPTIONAL_HDR 1 << 5
#define ERROR_NO_SECTIONS 1 << 6
#define ERROR_INVALID_PE 1 << 7

#define ERROR_COUNT 8

struct analysis_base
{
	unsigned char * data;
	char * filename;
	long size;
	unsigned long errors;

	WORD pi_sections;
	PIMAGE_DOS_HEADER pi_dos_header;
	PIMAGE_NT_HEADERS pi_nt_headers;
	PIMAGE_FILE_HEADER pi_file_header;
	PIMAGE_OPTIONAL_HEADER pi_optional_header;
	PIMAGE_SECTION_HEADER pi_section_header;
};

int analysis_init(struct analysis_base *, char *);
int analysis_parse_pe(struct analysis_base *);
void analysis_free(struct analysis_base *);
void print_errors(struct analysis_base *);


#endif