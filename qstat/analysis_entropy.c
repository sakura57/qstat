#include "analysis_entropy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

float compute_data_entropy(unsigned char *data, unsigned int len)
{
    float entropy = 0.0;
    float bytes[256];
    unsigned int i,j;
    
    memset((void*)&bytes, 0, 256 * sizeof(float));
    
    for(i=0;i<len;++i)
    {
        bytes[data[i]] += 1.0;
    }
    
    for(j=0;j<256;++j)
    {
        float byte = bytes[j];
        if(byte != 0.0f)
        {
            float occurrence = byte / ((float)len);
            entropy += (-log(occurrence) / log(2.0f)) * byte;
        }
    }
    
    entropy /= (float)len;
    return entropy;
}

int analysis_entropy(struct analysis_base *anal)
{
    WORD i;
    
    printf("%s Starting entropy tests\n", TAG_STATUS);
    
    for(i=0;i<anal->pi_file_header->NumberOfSections;++i)
    {
        DWORD virtual_address = anal->pi_section_header[i].VirtualAddress;
        DWORD section_size = anal->pi_section_header[i].SizeOfRawData;
        float entropy = compute_data_entropy(anal->data + virtual_address, section_size);
        printf("%s Section %d Shannon entropy: %f\n", TAG_STATUS, i, entropy);
        
        if(anal->pi_section_header[i].Characteristics & IMAGE_SCN_MEM_EXECUTE && entropy > ENTROPY_THRESHOLD)
        {
            printf("%s  Executable section appears packed\n", TAG_WARNING);
        }
    }
    
	return 0;
}
