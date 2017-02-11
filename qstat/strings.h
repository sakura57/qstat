#ifndef _STRINGS_H
#define _STRINGS_H

#define TAG_ERROR "[ERROR]"
#define TAG_STATUS "[STATUS]"
#define TAG_WARNING "[WARN]"

#define SPLASH_TEXT \
	"electrolux's QuickStat 0.1\n"

#define SYNTAX_TEXT \
	"At least one file-name is required.\n\n" \
	"Options:\n" \
	"--e\tDetermine section entropy.\n" \
	"\n"

#define ERROR_TEXT_MAX_LEN 32
#define ERRORS_TEXT \
{ \
	"ERROR_FILE_NOT_FOUND", \
	"ERROR_FILE_IS_EMPTY", \
	"ERROR_ALLOCATION_FAILURE", \
	"ERROR_FILE_READ_FAILURE", \
	"ERROR_NOT_AN_EXECUTABLE", \
	"ERROR_INVALID_OPTIONAL_HDR", \
	"ERROR_NO_SECTIONS", \
	"ERROR_INVALID_PE_HDR" \
}

#endif