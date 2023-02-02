#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "ctype.h"
#include "common.h"
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
	
	if (sscanf(last_block, "%lu", &size) < 1) //didn't find a number here, decryption key is wrong
		return -1;

	for (unsigned long i = size; i<num_blocks * BLOCKSIZE; i++) 
		result[i] = '\0';

	return size;
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

//Basicly strncpy but it ignores '\0' null characters, copying exactly size characters.
void str_safe_copy(unsigned char * dest, unsigned char * src, unsigned long size)
{
	for (long unsigned i=0; i<size; i++)
		dest[i] = src[i];
}

//Printf wrapper that ignores '\0' null characters, printing exactly size characters.
void str_safe_print(unsigned char * to_print, unsigned long size)
{
	printf("\n");
	for (int i=0; i<size; i++)
		printf("%c", to_print[i]);
}

//Checks if the next character is EOF without altering the position of the file pointer,
//basicly takes a peek forward to see if it's the last chunk of data.
int check_end_file(FILE *stream)
{
    int c;

    c = fgetc(stream);
    ungetc(c, stream);

    if (c == EOF) return 1;
    else return 0;
}

//Checks if the last block for the size accounting goes a block over the BUFSIZE bounds and only returns 1 in that case.
//Needing this check to allow the last chunk of data to be BUFSIZE + 1 extra block instead of just BUFSIZE,
//so that we can handle the case in which data ends exactly within the last block of the last chunk,
//causing the accounting block to go over the BUFSIZE bounds.
int check_last_block(FILE *stream)
{
    int c;

    fseek(stream, BUFSIZE, SEEK_CUR); //we're at the first character of chunk x, we move to the first character of chunk x+1
    
    c = fgetc(stream);
    if (c == EOF) //if the next character is the EOF it means that there's nothing else to read, rewind the file and return 0
    {
    	ungetc(c, stream);
    	fseek(stream, 0 - BUFSIZE, SEEK_CUR);
    	return 0;
    }
    else //there's other stuff to read, gotta dig deeper 
    {
    	ungetc(c, stream);
    	fseek(stream, BLOCKSIZE, SEEK_CUR); //we're at the first character of chunk x+1, we move a block further

        c = fgetc(stream);
	    if (c == EOF) //next character is EOF means the first and only block of the chunk is the accounting block, bingo!
	    {
	    	ungetc(c, stream);
	    	fseek(stream, 0 - (BUFSIZE + BLOCKSIZE), SEEK_CUR);
	    	return 1;
	    }
	    else //next character is something other than EOF means there's other data to be read, we were not at the last chunk to begin with
	    {
	    	ungetc(c, stream);
	    	fseek(stream, 0 - (BUFSIZE + BLOCKSIZE), SEEK_CUR);
	    	return 0;
	    }
    }

    return -1;
}