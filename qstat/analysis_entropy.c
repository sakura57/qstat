#include "analysis_entropy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

static unsigned char excluded_bytes_none[] = {0};

/*
    Function to compute Shannon entropy of a byte block
*/
float compute_data_entropy(unsigned char *data, unsigned int len, unsigned char *exclude_list)
{
    float entropy = 0.0;
    float bytes[256];
    unsigned int i,j;
    register unsigned char *exclude, pulled_byte, exclude_byte = 0;
    
    memset((void*)&bytes, 0, 256 * sizeof(float));
    
    for(i=0;i<len;++i)
    {
        pulled_byte = data[i];
        exclude = exclude_list;
        
        while(exclude_byte = *exclude++)
        {
            if(exclude_byte == pulled_byte)
            {
                goto exclude_continue_outer;
            }
        }
        
        bytes[pulled_byte] += 1.0;
        
exclude_continue_outer:
        continue;
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

/*
    Run entropy tests on each section
*/
int analysis_entropy(struct analysis_base *anal)
{
    WORD i;
    
    printf("%s Starting entropy tests\n", TAG_STATUS);
    
    for(i=0;i<anal->pi_file_header->NumberOfSections;++i)
    {
        DWORD address = anal->pi_section_header[i].PointerToRawData;
        DWORD section_size = anal->pi_section_header[i].SizeOfRawData;
        float entropy;
        
        if(!address)
        {
            printf("%s Section %d has a null address, cannot compute entropy\n", TAG_ERROR, i);
            
            //Not a critical error
            continue;
        }
        
        //If the section header claims the size is zero, we can still
        //compute size based on the address
        if(!section_size)
        {
            if(i == (anal->pi_file_header->NumberOfSections - 1))
            {
                goto critical_fail_section_size;
            }
            
            section_size = anal->pi_section_header[i+1].PointerToRawData - address;
            
            if(!section_size)
            {
critical_fail_section_size:
                printf("%s Section %d is empty, cannot compute entropy\n", TAG_ERROR, i);
                
                //Not a critical error (as far as the big picture is concerned)
                continue;
            }
            
            printf("%s Section %d is \"empty,\" computed size of 0x%X\n", TAG_WARNING, i, section_size);
        }
        else
        {
            DWORD section_is_executable = anal->pi_section_header[i].Characteristics & IMAGE_SCN_MEM_EXECUTE;
            
            entropy = compute_data_entropy(anal->data + address,
                                           section_size,
                                           excluded_bytes_none);
            
            printf("%s Section %d Shannon entropy: %f\n", TAG_STATUS, i, entropy);
            
            if(section_is_executable && entropy > ENTROPY_THRESHOLD)
            {
                printf("%s Executable section appears packed\n", TAG_WARNING);
            }
        }
    }
    
	return 0;
}
