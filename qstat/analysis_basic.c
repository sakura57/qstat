#include "analysis_basic.h"
#include <string.h>

static char const error_msgs[ERROR_COUNT][ERROR_TEXT_MAX_LEN] = ERRORS_TEXT;
static char const packer_section_strings[NUM_PACKER_SECTION_STRINGS][8] =
{
	"UPX",
	"vmp"
};

static char const packer_names[NUM_PACKER_SECTION_STRINGS][16] =
{
	"UPX",
	"VMProtect"
};

DWORD rva_to_raw(struct analysis_base *anal, DWORD rva)
{
	unsigned int i, sections=anal->pi_sections;

	for(i=0; i<sections; ++i)
	{
		PIMAGE_SECTION_HEADER section = &anal->pi_section_header[i];
		DWORD virtual_address = section->VirtualAddress;

		if(rva >= virtual_address && rva < (virtual_address + section->SizeOfRawData))
		{
			return rva - virtual_address + section->PointerToRawData;
		}
	}

	return 0;
}

/*
	Load an executable into memory given a filename.
*/
int analysis_init(struct analysis_base *anal, char *filename)
{
	FILE * f;
	long size;

	anal->filename = filename;
	anal->errors = 0;
	anal->data = 0;

	printf("%s Starting analysis of \"%s\"\n", TAG_STATUS, filename);

	f = fopen(filename, "rb");

	if(!f)
	{
		anal->errors |= ERROR_FILE_NOT_FOUND;
		return 1;
	}

	fseek(f, 0L, SEEK_END);
	size = ftell(f);

	if(!size)
	{
		anal->errors |= ERROR_FILE_IS_EMPTY;
		return 1;
	}

	anal->size = size;
	anal->data = (unsigned char *)malloc(sizeof(unsigned char) * size);

	if(!anal->data)
	{
		anal->errors |= ERROR_ALLOCATION_FAILURE;
		return 1;
	}

	fseek(f, 0, SEEK_SET);
	if(fread(anal->data, sizeof(unsigned char), size, f) != size)
	{
		anal->errors |= ERROR_FILE_READ_FAILURE;
		return 1;
	}

	return fclose(f);
}

/*
	Does some initial parsing of the PE header.
	This includes some parsing of the section info.
*/
int analysis_parse_pe(struct analysis_base *anal)
{
	WORD sections;
	unsigned int i,j;

	anal->pi_dos_header = (PIMAGE_DOS_HEADER)anal->data;

	//Check for "MZ" signature.
	if(anal->pi_dos_header->e_magic != 0x5A4D)
	{
		anal->errors |= ERROR_NOT_AN_EXECUTABLE;
		return 1;
	}

	anal->pi_nt_headers = (PIMAGE_NT_HEADERS)((BYTE*)anal->data + anal->pi_dos_header->e_lfanew);

	if(anal->pi_nt_headers->Signature != 0x00004550)
	{
		anal->errors |= ERROR_INVALID_PE;
		return 1;
	}

	anal->pi_file_header = (PIMAGE_FILE_HEADER)&anal->pi_nt_headers->FileHeader;

	sections = anal->pi_file_header->NumberOfSections;
	printf("%s %d sections\n", TAG_STATUS, sections);

	if(sections == 0)
	{
		anal->errors |= ERROR_NO_SECTIONS;
		return 1;
	}

	anal->pi_sections = sections;

	anal->pi_optional_header = (PIMAGE_OPTIONAL_HEADER)&anal->pi_nt_headers->OptionalHeader;

	if(anal->pi_optional_header->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
	{
		anal->errors |= ERROR_INVALID_OPTIONAL_HDR;
		return 1;
	}

	anal->pi_section_header = (PIMAGE_SECTION_HEADER)(anal->data + anal->pi_dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	unsigned int packer_identified = 0;

	for(i=0;i<sections;++i)
	{
		PIMAGE_SECTION_HEADER section = &anal->pi_section_header[i];
		printf("%s Section %d, name \'%s\'\n", TAG_STATUS, i, section->Name);

		if(!packer_identified)
		{
			for(j=0;j<NUM_PACKER_SECTION_STRINGS;++j)
			{
				if(strstr(section->Name, packer_section_strings[j]))
				{
					packer_identified = j + 1;
					break;
				}
			}
		}
	}

	if(packer_identified)
	{
		printf("%s Section naming indicates %s packing\n", TAG_WARNING, packer_names[packer_identified-1]);
	}

	return 0;
}

/*
	Disposes of resources we acquired in analysis_init
*/
void analysis_free(struct analysis_base *anal)
{
	printf("%s Ending analysis of \"%s\"\n", TAG_STATUS, anal->filename);
	if(anal->data)
	{
		free(anal->data);
	}
}

/*
	Loop through the bit numbers in the error flags and print which
	ones are toggled.
*/
void print_errors(struct analysis_base *anal)
{
	for(unsigned long i=0;i<ERROR_COUNT;++i)
	{
		unsigned long error_bit = (1 << i);
		if((anal->errors & error_bit) == error_bit)
		{
			printf("%s Error %d: %s\n", TAG_ERROR, i + 1, error_msgs[i]);
		}
	}
}