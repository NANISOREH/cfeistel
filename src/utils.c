#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "feistel.h"

int half_block_xor(unsigned char * result, unsigned char * first, unsigned char * second)
{
	for (int i = 0; i<BLOCKSIZE/2; i++)
	{
		result[i] = first[i] ^ second[i];
	}

	return 1;
}

void print_byte(char c)
{
    for (int i = 7; i >= 0; --i)
    {
        putchar( (c & (1 << i)) ? '1' : '0' );
    }
    putchar('\n');
}

void print_to_file(unsigned char * out, char * filename)
{
	FILE *write_ptr;
	write_ptr = fopen(filename,"wb");  
	fwrite(out,sizeof(char),strlen(out),write_ptr); 
	fclose(write_ptr);
}

int read_from_file(unsigned char * buffer, char * filename)
{
	FILE *ptr;
	ptr = fopen(filename,"rb");

	int length;  

	if (ptr != NULL)
	{
		length = fread(buffer,sizeof(char),100000,ptr); 
		buffer[length++] = '\0';
		fclose(ptr);
	}
	else
		return -1;
}
