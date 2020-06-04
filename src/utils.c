#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "ctype.h"
#include "feistel.h"

//Does bitwise xor between two block halves
int half_block_xor(unsigned char * result, unsigned char * first, unsigned char * second)
{
	for (int i = 0; i<BLOCKSIZE/2; i++)
	{
		result[i] = first[i] ^ second[i];
	}

	return 1;
}

//Reverses the order of the string array containing the round keys
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
//and cutting the result as necessary.
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

//Prints the result of the program into the output file
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
	printf("\nblock text: %s", block_data);
	printf("\nblock sum: %llu\n", checksum);
	checksum = 0;
}

//Splits the character in the 'whole' parameter in two binary strings representing respectively
//the 4 most significant bits and the 4 least significant bits of the character fiven 
//Es. split_byte(left_part, right_part, 01001101) --> left_part = 01000000; right_part = 00001101
unsigned char split_byte(unsigned char * left_part, unsigned char * right_part, unsigned char whole)
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

//Reads the input file, copies it into a 100000 bytes buffer.
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

//Makes a string out of the counter int, padding it to the right to make it 8 bytes long.
//Operates in-place (the string to populate is passed as a pointer to character)
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
