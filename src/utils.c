#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "ctype.h"
#include "stdbool.h"
#include "common.h"
#include "feistel.h"
#include "utils.h"
#include "sys/time.h"
#include "stdarg.h"
#include "omp.h"
#include "unistd.h"
#include <stdint.h>
#include "fcntl.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>

//These variables belong to the main but are needed here to print progress info
extern long unsigned total_file_size;
extern long unsigned current_block;
extern struct timeval start_time;

//Does bitwise xor between two block halves
int half_block_xor(unsigned char * result, const unsigned char * first, const unsigned char * second)
{
	for (int i = 0; i<BLOCKSIZE/2; i++)
	{
		result[i] = first[i] ^ second[i];
	}

	return 1;
}

//Does bitwise xor between two blocks by wrapping the half_block_xor function
void block_xor(block *result, const block *first, const block *second)
{
	half_block_xor(result->left, first->left, second->left);
	half_block_xor(result->right, first->right, second->right);
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
unsigned long remove_padding(unsigned char * result, unsigned long num_blocks, enum mode chosen, unsigned long total_file_size)
{
	unsigned long index = (num_blocks - 1) * BLOCKSIZE;
	unsigned char last_block[BLOCKSIZE];
	for (int i = 0; i<BLOCKSIZE; i++)
	{
		last_block[i] = result[index];
		index++; 
	}
	unsigned long size;
	
	if (sscanf((char *)last_block, "%lu", &size) < 1) //didn't find a number here, no accounting block
	{
		return -1;
	}

	//A bit of a hack here: I know that if the operation mode involved an IV block that was excluded from decryption, 
	//the last chunk will be larger by one block.
	//I should solve this by refactoring the accounting block management and make it report the size of the last block, not the last chunk.
	//This way I could always correctly derive the size of last chunk in any case
	//if (chosen == ctr) size += BLOCKSIZE;

	for (unsigned long i = size; i<num_blocks * BLOCKSIZE; i++) 
		result[i] = '\0';

	return size;
}

//Given pointers to left and right halves of a block, it prints out content and checksum of the block
void print_block(unsigned char * left, unsigned char * right)
{
	long long unsigned checksum = 0;
	unsigned char block_data[BLOCKSIZE];

	for (int j=0; j<BLOCKSIZE/2; j++)
	{
		checksum = checksum + left[j] + right[j];
		block_data[j] = left[j];
		block_data[j + BLOCKSIZE/2] = right[j];
	}
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

//Printf wrapper that ignores '\0' null characters, printing exactly size characters (even if some are not characters).
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

//Prints progress information
void show_progress_data(struct timeval current_time)
{
	#ifdef QUIET
    	return;
	#endif

	unsigned long bnum = total_file_size / BLOCKSIZE;
	int percentage = (100 * current_block)/bnum;

	printf("\rProgress: %d%%\t Avg speed: %.2f MB/s", percentage, estimate_speed(current_time));
	fflush(stdout);
}

//Estimates the processing speed at a given point in time
double estimate_speed (struct timeval current_time)
{
	double processed_data = (double) (current_block * BLOCKSIZE)/(1024*1024);
	double elapsed_time = (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0;
	return processed_data/elapsed_time;
}

//Prints a certain number of lines given in input and cleans the screen
void exit_message(int num_strings, ...)
{
	#ifdef QUIET
		return;
	#endif

	// Clear the line before displaying messages
	printf("\r%*s\r", 100, "");
	fflush(stdout);

	va_list args;
	va_start(args, num_strings);

	for (int i = 0; i < num_strings; i++) 
	{
		const char *message = va_arg(args, const char *);
		printf("\n%s", message);
	}

	printf("\n\n");
	va_end(args);
}

//Given a block, it prints out its content and checksum
//Useful for debugging, you can access these per-block logs by compiling with the macro DEBUG
void block_logging(block b, const char* message, unsigned long bcount)
{
	#ifndef DEBUG
		return;
	#endif

	//computes the checksum and populates the block_data string
	long unsigned checksum = compute_checksum((unsigned char *)&b, BLOCKSIZE);
	unsigned char block_data[BLOCKSIZE];
	for (int j=0; j<BLOCKSIZE/2; j++)
	{
		block_data[j] = b.left[j];
		block_data[j + BLOCKSIZE/2] = b.right[j];
	}

	//prints everything out
	printf("\n\n\n====================================================================\n");
	printf("block %lu processed by the thread %d", bcount, omp_get_thread_num());
	printf("%s", message);
	printf("\nblock text:");
	str_safe_print(block_data, BLOCKSIZE);
	printf("\nblock sum: \n%lu\n", checksum);
	printf("====================================================================\n");
	checksum = 0;
}

//Computes a very naive checksum of a given chunk of data
long unsigned compute_checksum (unsigned char * data, long unsigned length)
{
	long long unsigned checksum = 0;
	for (int j=0; j<length; j++)
	{
		checksum = checksum + data[j];
	}

	return checksum;
}

double timeval_diff_seconds(struct timeval start, struct timeval end) 
{
    long long start_micros = (long long)start.tv_sec * 1000000 + start.tv_usec;
    long long end_micros = (long long)end.tv_sec * 1000000 + end.tv_usec;
    
    return (double)(end_micros - start_micros) / 1000000.0;
}

//Creates BLOCKSIZE random bytes and uses them to populate a block, returns a numeric representation of the nonce
long unsigned create_nonce(block * nonce)
{
	long unsigned num_nonce = 0;
	int urandom_fd = open("/dev/urandom", O_RDONLY);
    if (urandom_fd == -1) 
	{
        perror("Error opening /dev/urandom");
        return 1;
    }

    ssize_t bytes_read = read(urandom_fd, nonce, BLOCKSIZE);
    if (bytes_read == -1) 
	{
        perror("Error reading from /dev/urandom");
        close(urandom_fd);
        return 1;
    }

    close(urandom_fd);

    if (bytes_read != BLOCKSIZE) 
	{
        fprintf(stderr, "Did not read enough random bytes\n");
        return 1;
    }

    return derive_number_from_block(nonce);
}

//Derives an unsigned long from the content of a block 
long unsigned derive_number_from_block(block * b)
{
	long unsigned num = 0;

	unsigned char * data = (unsigned char *)b;
	for (int i = 0; i < BLOCKSIZE; i++)
    {
        num |= ((uint64_t)data[i] << (i * BLOCKSIZE));
    }

	return num;
}

//Derives a block from an unsigned long
//It's the inverse function of derive_number_from_block
void derive_block_from_number(long unsigned num, block *b)
{
    unsigned char data[BLOCKSIZE];

    for (int i = 0; i < BLOCKSIZE; i++)
    {
        data[i] = (num >> (i * BLOCKSIZE)) & 0xFF;
    }

    memcpy(b, data, BLOCKSIZE);
}

//Prepends a block to the plaintext/ciphertext
int prepend_block(block * b, unsigned char * data)
{
	for (int i=0; i<BLOCKSIZE/2; i++)
	{
		data[i] = b->left[i];
		data[i + BLOCKSIZE/2] = b->right[i];
	}

	return 0;
}

//Takes a string and derives an 8-byte key out of it using PBKDF2
int compress_key(unsigned char *compressed_key, const char* key) 
{
    // Parameters for PBKDF2
    const char* password = key;
    const unsigned char* salt = (const unsigned char*)"salt"; // You should generate a random salt
    int iterations = 1000; // Adjust the number of iterations as needed

    // Use PBKDF2 to derive a key
    int ret = PKCS5_PBKDF2_HMAC
	(
        password,
        strlen(password), // Use strlen to get the length of the string
        salt,
        strlen((const char*)salt),
        iterations,
        EVP_sha256(), // You can choose a different hash function
        KEYSIZE,
        compressed_key
    );

    if (ret != 1) 
	{
        return -1;
    }

	return 0;
}