#include "analysis_imports.h"
#include <string.h>

#define FLAGGED_MODULE_MAX_NAME_LEN 32
#define FLAGGED_MODULE_COUNT 3

#define INITIAL_IMPORT_COUNT 64

static char const flagged_modules[][FLAGGED_MODULE_MAX_NAME_LEN] =
{
	"ws2_32.dll",
	"wininet.dll",
	"advapi32.dll",
	"\0"
};

int analysis_imports(struct analysis_base *anal)
{
	DWORD imports_addr, imports_size;

	char **imports = (char**)malloc(INITIAL_IMPORT_COUNT*sizeof(char*));
	DWORD *import_location_table = (DWORD*)malloc(INITIAL_IMPORT_COUNT*sizeof(DWORD));

	printf("%s Starting imports analysis\n", TAG_STATUS);

	//Obtain the address of the import descriptor table
	{
		PIMAGE_DATA_DIRECTORY data_directory;

		data_directory = anal->pi_optional_header->DataDirectory;

		imports_addr = rva_to_raw(anal, data_directory[1].VirtualAddress);
		imports_size = data_directory[1].Size;
	}

	if(!imports_addr)
	{
		printf("%s Unable to locate import descriptor table\n", TAG_ERROR);

		//Not a critical error
		goto imports_analysis_end;
	}

	printf("%s Located import descriptor table, address 0x%X, size=0x%X\n", TAG_STATUS, imports_addr, imports_size);

	//Now walk the imported modules
	{
		PIMAGE_IMPORT_DESCRIPTOR import_desc = (PIMAGE_IMPORT_DESCRIPTOR)(anal->data + imports_addr);

		if(!import_desc->FirstThunk)
		{
			printf("%s No imported modules! Image is packed?\n", TAG_ERROR);

			//Not a critical error
			goto imports_analysis_end;
		}

		do
		{
			DWORD raw_module_name_ptr = rva_to_raw(anal, import_desc->Name);
			char const *imported_module_name = (char const *)(anal->data + raw_module_name_ptr);

			if(anal->verbose)
			{
				printf("%s Image imports module %s\n", TAG_STATUS, imported_module_name);
			}

			//check if the imported module is flagged
			{
				unsigned int i;
				
				for(i=0;i<FLAGGED_MODULE_COUNT;++i)
				{
					if(!stricmp(imported_module_name, flagged_modules[i]))
					{
						printf("%s Imported module %s is flagged\n", TAG_WARNING, imported_module_name);
						break;
					}
				}
			}

			//walk the imported symbols for each module
			{
				PIMAGE_THUNK_DATA thunk_ptr = (PIMAGE_THUNK_DATA)(anal->data + rva_to_raw(anal, import_desc->FirstThunk));
				DWORD string;

				while(string = (thunk_ptr++)->u1.ForwarderString)
				{
					//todo: actually something here
				}
			}

		} while((++import_desc)->FirstThunk);
	}

imports_analysis_end:
	free(imports);
	free(import_location_table);
	return 0;
}