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

void reverse_keys(unsigned char keys[NROUND][KEYSIZE])
{
	unsigned char temp[NROUND][KEYSIZE];
	memcpy(temp, keys, NROUND * KEYSIZE);
	int j=NROUND-1;

	for (int i=0; i<NROUND; i++)
	{
		strncpy(keys[i], temp[j], NROUND);
		j--;
	}
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
	write_ptr = fopen(filename,"w");  
	fwrite(out,sizeof(char),strlen(out),write_ptr); 
	fclose(write_ptr);
}

void print_block(unsigned char * left, unsigned char * right)
{
	long long unsigned checksum = 0;
	char block_data[BLOCKSIZE+1];

	for (int j=0; j<BLOCKSIZE/2; j++)
	{
		checksum = checksum + left[j] + right[j];
		block_data[j] = left[j];
		block_data[j + BLOCKSIZE/2] = right[j];
	}
	block_data[BLOCKSIZE] = '\0';
	printf("\nblock text: %s", block_data);
	printf("\nblock sum: %llu\n", checksum);
	checksum = 0;
}

unsigned char split_byte(unsigned char * left_part, unsigned char * right_part, unsigned char whole)
{
	*right_part = whole;
	*left_part = whole;

	*right_part = *right_part<<(BLOCKSIZE/4);
	*right_part = *right_part>>(BLOCKSIZE/4);
	*left_part = *left_part>>(BLOCKSIZE/4);
}

void merge_byte(unsigned char * target, unsigned char left_part, unsigned char right_part)
{
	left_part = left_part <<(BLOCKSIZE/4);
	*target = right_part | left_part;
}

int read_from_file(unsigned char * buffer, char * filename)
{
	FILE *ptr;
	ptr = fopen(filename,"r");

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
