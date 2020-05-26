#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#define BLOCKSIZE 16
#define KEYSIZE 8

int char_xor(unsigned char * result, unsigned char * first, unsigned char * second)
{
	//different size for the two operands of a xor: should never happen in a feistel cipher
	if (sizeof(first) != sizeof(second))
	{
		return -1;
	}

	for (int i = 0; i<sizeof(first); i++)
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

void print_to_file(unsigned char * left, unsigned char * right)
{
	unsigned char out[BLOCKSIZE];
	for (int i=0; i<BLOCKSIZE/2; i++)
	{
		out[i] = left[i];
		out[i+8] = right[i];
	}
	FILE *write_ptr;
	write_ptr = fopen("out","w");  
	fwrite(out,sizeof(out),1,write_ptr); 
	fclose(write_ptr);
}

void read_from_file(unsigned char * buffer)
{
	FILE *ptr;
	ptr = fopen("in","r");  
	fread(buffer,sizeof(buffer),2,ptr); 
}
