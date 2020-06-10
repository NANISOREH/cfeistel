#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "ctype.h"
#include "feistel.h"
#include "utils.h"

//Does bitwise xor between two block halves
int half_block_xor(unsigned char * result, unsigned char * first, unsigned char * second)
{
	for (int i = 0; i<BLOCKSIZE/2; i++)
	{
		result[i] = first[i] ^ second[i];
	}

	return 1;
}

//Prints a byte as a binary string
void print_byte(char c)
{
    for (int i = 7; i >= 0; --i)
    {
        putchar( (c & (1 << i)) ? '1' : '0' );
    }
    putchar('\n');
}

//Removes the padding from the padded block after decryption, by reading the size from the last block 
//and cutting the result as necessary. Returns the size read from the last block.
unsigned long remove_padding(unsigned char * result, unsigned long num_blocks)
{
	unsigned long index = (num_blocks - 1) * BLOCKSIZE;
	unsigned char last_block[BLOCKSIZE];
	for (int i = 0; i<BLOCKSIZE; i++)
	{
		last_block[i] = result[index];
		index++; 
	}

	unsigned long size;
	sscanf(last_block, "%lu", &size);

	for (unsigned long i = size; i<num_blocks * BLOCKSIZE; i++) 
		result[i] = '\0';

	return size;
}

//Reads the input file, copies it into a buffer.
int read_from_file(unsigned char * buffer, char * filename)
{
	FILE *ptr;
	ptr = fopen(filename,"rb");

	unsigned long length; 
	if (ptr != NULL)
	{
		length = fread(buffer,sizeof(char),BUFSIZE,ptr); 
		buffer[length++] = '\0';
		fclose(ptr);
	}
	else
		return -1;
}

//Prints the result of the program into the output file
void print_to_file(unsigned char * out, char * filename, unsigned long size)
{
	FILE *write_ptr;
	write_ptr = fopen(filename,"wb");

	if (write_ptr != NULL)
	{
		fwrite(out,size,1,write_ptr); 
		fclose(write_ptr);
	}
}

//Given pointers to left and right halves of a block, it prints out content and checksum of the block
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
	printf("\nblock text:");
	str_safe_print(block_data, BLOCKSIZE);
	printf("\nblock sum: \n%llu\n", checksum);
	checksum = 0;
}

//Splits the character in the 'whole' parameter in two binary strings representing respectively
//the 4 most significant bits and the 4 least significant bits of the character fiven 
//Es. split_byte(left_part, right_part, 01001101) --> left_part = 01000000; right_part = 00001101
void split_byte(unsigned char * left_part, unsigned char * right_part, unsigned char whole)
{
	*right_part = whole;
	*left_part = whole;

	*right_part = *right_part<<(BLOCKSIZE/4);
	*right_part = *right_part>>(BLOCKSIZE/4);
	*left_part = *left_part>>(BLOCKSIZE/4);
}

//Merges the two halves produced by split_byte into a target character
//Es. merge_byte(target, 10110000, 00001001) --> target = 10111001 
void merge_byte(unsigned char * target, unsigned char left_part, unsigned char right_part)
{
	left_part = left_part <<(BLOCKSIZE/4);
	*target = right_part | left_part;
}

//Makes a string out of the counter int, padding it to the right to make it 8 bytes long.
//Operates in-place (the string to populate is passed as a pointer to character)
void stringify_counter(unsigned char * string, unsigned long counter)
{
	unsigned char number[BLOCKSIZE/2];
	int num_digits = 0;
	sprintf(number, "%lu", counter);

	for (int i=0; i<BLOCKSIZE/2; i++)
	{
		if (number[i]!='\0')
		{
			if (isdigit(number[i]))
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
			string[j] = number[j];
		}
		else
			string[j] = '=';
	}
}

//Takes two bytes, swaps the pos_first bit of the first byte with the pos_second bit of the second byte
//Operates in-place (the two bytes are passed as pointers to char)
void swap_bit(unsigned char * first, unsigned char * second, unsigned int pos_first, unsigned int pos_second)
{
	if (pos_first > 7 || pos_second > 7)
		return;

	unsigned char first_bit = (*first >> pos_first) & 1U;
	unsigned char second_bit = (*second >> pos_second) & 1U;

	*second = (*second & ~(1UL << pos_second)) | (first_bit << pos_second);
	*first = (*first & ~(1UL << pos_first)) | (second_bit << pos_first);
}

//Basicly strncpy but it ignores '\0' null characters.
void str_safe_copy(unsigned char * dest, unsigned char * src, unsigned long size)
{
	for (long unsigned i=0; i<size; i++)
		dest[i] = src[i];
}

//Printf wrapper that ignores '\0' null characters.
void str_safe_print(unsigned char * to_print, unsigned long size)
{
	printf("\n");
	for (int i=0; i<size; i++)
		printf("%c", to_print[i]);
}

//Basicly strlen but it doesn't stop counting the length at the first '\0'.
//Note: still has the problem that it won't count the length correctly if a ciphertext ENDS with '/0'
//and while it has never happened so far in my test runs, it could theoretically happen.
unsigned long str_safe_len(unsigned char * string)
{
	unsigned long len=0;
	int flag=0;
	for (unsigned long i=0; i<BUFSIZE; i++)
	{
		if (string[i]==0)
			flag=1;
		else
			flag=0;

		if (flag==0)
			len = i + 1;
	}

	return len;
}