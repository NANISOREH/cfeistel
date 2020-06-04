#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "ctype.h"
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

void remove_padding(unsigned char * result)
{
	int index = strlen(result) - BLOCKSIZE;
	unsigned char last_block[BLOCKSIZE];
	for (int i = 0; i<BLOCKSIZE; i++)
	{
		last_block[i] = result[index];
		index++; 
	}

	unsigned long size;
	sscanf(last_block, "%lu", &size);

	for (unsigned long i = size; i<strlen(result); i++) 
		result[i] = '\0';
}

void print_to_file(unsigned char * out, char * filename)
{
	FILE *write_ptr;
	write_ptr = fopen(filename,"w"); 

	if (write_ptr != NULL)
	{
		fwrite(out,sizeof(char),strlen(out),write_ptr); 
		fclose(write_ptr);
	}
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

void stringify_counter(unsigned char * string, int counter)
{
	int num_digits = 0;
	memset(string, 35, BLOCKSIZE/2);
	sprintf(string, "%d", counter);

	for (int i=0; i<BLOCKSIZE/2; i++)
	{
		if (string[i]!='\0')
		{
			if (isdigit(string[i]))
				num_digits++;
			else 
				break;
		}
		else
			break;
	}

	for (int j=0; j<(BLOCKSIZE/2); j++)
	{
		if (j<num_digits)
		{
			string[j + (BLOCKSIZE/2) - num_digits - 1] = string[j];
		}
		else
			string[j] = '=';
	}
}

void swap_bit(unsigned char * first, unsigned char * second, unsigned int pos_first, unsigned int pos_second)
{
	if (pos_first > 7 || pos_second > 7)
		return;

	unsigned char first_bit = (*first >> pos_first) & 1U;
	unsigned char second_bit = (*second >> pos_second) & 1U;

	*second = (*second & ~(1UL << pos_second)) | (first_bit << pos_second);
	*first = (*first & ~(1UL << pos_first)) | (second_bit << pos_first);
}
