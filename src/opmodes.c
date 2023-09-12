//This module contains the functions that implement the logic of the cipher's operation modes.
//They can theoretically be used with any block cipher.

#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "common.h"
#include "utils.h"
#include "feistel.h"
#include "opmodes.h"
#include "sys/time.h"
#include "omp.h"
#include "stdbool.h"


//These variables belong to the main, but are needed here to keep track of the processing
extern long unsigned total_file_size;
extern long unsigned current_block;
extern long unsigned chunk_size;

static bool iv_generated = false;

int create_prepend_iv(block * iv, unsigned char * ciphertext);
int create_nonce(unsigned char nonce[BLOCKSIZE]);

//Executes the cipher in ECB mode; takes a block array, the total number of blocks and the round keys, returns processed data.
unsigned char * operate_ecb_mode(block * b, unsigned long bnum, unsigned char round_keys[NROUND][KEYSIZE])
{
	struct timeval current_time;
	unsigned char * ciphertext;
	ciphertext = calloc(BLOCKSIZE * bnum, sizeof(unsigned char));
	if (ciphertext == NULL) return ciphertext;
	chunk_size = (BLOCKSIZE * bnum) * sizeof(unsigned char);

	//launching the feistel algorithm on every block, by making the index jump by increments of BLOCKSIZE
	#pragma omp parallel for
	for (unsigned long i = 0; i < bnum; ++i) 
	{
		//logging (pre-processing)
		current_block++;
		if (i % 100000 == 0)
		{
			gettimeofday(&current_time, NULL);
			show_progress_data(current_time);
		}
		#pragma omp critical
		block_logging(b[i], "\n----------ECB-------BEFORE-----------", i);

		//applying the cipher on the current block
		process_block(b[i].left, b[i].right, round_keys);

		//logging (post-processing)
		#pragma omp critical
		block_logging(b[i], "\n----------ECB-------AFTER-----------", i);

		//appending the result to the ciphertext variable
		for (int j = 0; j < BLOCKSIZE; j++)	
		{
			ciphertext[(i*BLOCKSIZE) + j] = b[i].left[j];
		}
	}
	return ciphertext;
}

//Executes the cipher in CTR mode; takes a block array, the total number of blocks and the round keys, returns processed data.
unsigned char * encrypt_ctr_mode(block * b, unsigned long bnum, unsigned char round_keys[NROUND][KEYSIZE])
{
	unsigned char * ciphertext;
	struct timeval current_time;
	static block counter_block;
	static block iv;

	//using the checksum of the master key as starting point for the counter
	unsigned long counter = 0;
	for (int j=0; j<KEYSIZE; j++)
		counter = counter + round_keys[0][j] * KEYSIZE;

	//This two variables will contain a string representation of the counter
	//The temp block is simply there to make it easier to xor said string representation with the counter block
	unsigned char str_counter[BLOCKSIZE];
	block temp;

	if (iv_generated) //not the first chunk of data, IV has already been prepended in a previous execution
	{
		ciphertext = malloc(BLOCKSIZE * bnum * sizeof(unsigned char));
		chunk_size = BLOCKSIZE * bnum * sizeof(unsigned char);
	}
	else //first chunk of data, IV has to be prepended to the ciphertext in this execution
	{
		ciphertext = malloc(BLOCKSIZE * (bnum+1) * sizeof(unsigned char));
		chunk_size = BLOCKSIZE * (bnum+1) * sizeof(unsigned char);
		create_prepend_iv(&iv, ciphertext);
	}

	block_logging(iv, "\n----------CTR-------cb before cycle-----------", 0);
	long unsigned cur = 0;

	#pragma omp parallel private (counter_block)
	{
		//Copying the IV in the first counter block for every thread
		memcpy(&counter_block, &iv, BLOCKSIZE);
		
		//launching the feistel algorithm on every block
		//I use the initial counter as a starting point for the index, because openMP parallelizing for cycles
		//apparently works better if you rely on the index to distribute the iterations
		#pragma omp for private (temp, str_counter, cur)
		for (unsigned long i=counter; i<bnum+counter; ++i)
		{
			//This variable will hold the current block number
			//Yes, I already literally have a current_block variable, but it's an extern one that's defined in the main file
			//and keeps track of the current block in the whole input file, not just in the currently processing chunk
			cur = i-counter;

			//initializing the counter block for this iteration by xoring it with the new value of the counter, stringified
			stringify_counter(str_counter, i);
			block_from_byte_array(&temp, str_counter);
			block_xor(&counter_block, &counter_block, &temp);

			//logging (pre-processing)
			current_block++;
			if (cur % 100000 == 0)
			{
				gettimeofday(&current_time, NULL);
				show_progress_data(current_time);
			}

			#pragma omp critical
			block_logging(b[cur], "\n----------CTR-------BEFORE-----------", cur);
			
			//applying the cipher on the counter block and incrementing the counter
			process_block(counter_block.left, counter_block.right, round_keys);

			//xor between the ciphered counter block and the current block of plaintext/ciphertext
			block_xor(&b[cur], &b[cur], &counter_block);
			
			//logging (post-processing)
			#pragma omp critical
			block_logging(b[cur], "\n----------CTR-------AFTER-----------", cur);

			//storing the ciphered block in the ciphertext variable
			for (int j=0; j<BLOCKSIZE; j++)	
			{
				if (iv_generated) //not the first chunk of data, IV has already been prepended in a previous execution
				{
					ciphertext[(cur*BLOCKSIZE)+j] = b[cur].left[j];	
				}
				else //it's the first chunk of data, IV has been prepended in THIS execution, so the actual ciphertext slides by a block
				{
					ciphertext[((cur+1)*BLOCKSIZE)+j] = b[cur].left[j];
				}
			}
		}	
	}

	iv_generated = true;
	return ciphertext;
}

//Executes the cipher in CTR mode; takes a block array, the total number of blocks and the round keys, returns processed data.
unsigned char * decrypt_ctr_mode(block * b, unsigned long bnum, unsigned char round_keys[NROUND][KEYSIZE])
{
	unsigned char * plaintext;
	block * ciphertext;
	struct timeval current_time;
	block counter_block;

	//using the checksum of the master key as starting point for the counter
	unsigned long counter = 0;
	for (int j=0; j<KEYSIZE; j++)
		counter = counter + round_keys[0][j] * KEYSIZE;

	//This two variables will contain a string representation of the counter
	//The temp block is simply there to make it easier to xor said string representation with the counter block
	unsigned char str_counter[BLOCKSIZE];
	block temp;

	if (iv_generated) //not the first chunk of data, IV has already been taken from a previous execution
	{
		ciphertext = b;
	}
	else //first chunk of data, IV (content of counter_block) has to be taken from the ciphertext in this execution
	{
		bnum--;		
		//Instead of just using the pointer to block passed in input, we allocate new space with one less block worth of space
		//because we're going to keep out the prepended IV, and copy everything from b starting from the second block 
		ciphertext = malloc((bnum) * sizeof(block));
		for (int i=0; i<bnum; i++)
		{
			memcpy(&ciphertext[i], &b[i+1], sizeof(block));
		}
	}

	plaintext = malloc(BLOCKSIZE * bnum * sizeof(unsigned char));
	chunk_size = BLOCKSIZE * bnum * sizeof(unsigned char);

	long unsigned cur = 0;

	#pragma omp parallel private (counter_block)
	{	
		//copying the IV in counter_block for every thread
		if (!iv_generated) memcpy(&counter_block, &b[0], sizeof(block));
		
		//launching the feistel algorithm on every block
		//I use the initial counter as a starting point for the index, because openMP parallelizing for cycles
		//apparently works better if you rely on the index to distribute the iterations
		#pragma omp for private (str_counter, temp, cur)
		for (unsigned long i=counter; i<bnum+counter; i++)
		{
			//This variable will hold the current block
			//Yes, I already literally have a current_block variable, but it's an extern one that's defined in the main file
			//and keeps track of the current block in the whole input file, not just in the currently processing chunk
			cur = i-counter;

			//initializing the counter block for this iteration by stringifying it and combining it with the new value of the counter
			stringify_counter(str_counter, i);
			block_from_byte_array(&temp, str_counter);
			block_xor(&counter_block, &counter_block, &temp);

			//logging (pre-processing)
			current_block++;
			if (cur % 100000 == 0)
			{
				gettimeofday(&current_time, NULL);
				show_progress_data(current_time);
			}

			#pragma omp critical
			block_logging(ciphertext[cur], "\n----------CTR-------BEFORE-----------", cur);
			
			//applying the cipher on the counter block and incrementing the counter
			process_block(counter_block.left, counter_block.right, round_keys);

			//xor between the ciphered counter block and the current block of plaintext/ciphertext
			block_xor(&ciphertext[cur], &ciphertext[cur], &counter_block);
			
			//logging (post-processing)
			#pragma omp critical
			block_logging(ciphertext[cur], "\n----------CTR-------AFTER-----------", cur);
			
			//storing the result of the xor in the output variable
			for (unsigned long j=0; j<BLOCKSIZE; j++)	
			{
				plaintext[((cur)*BLOCKSIZE)+j] = ciphertext[cur].left[j];
			}
		}	
	}

	iv_generated = true;
	return plaintext;
}

//Executes encryption in CBC mode; takes a block array, the total number of blocks and the round keys, returns processed data.
unsigned char * encrypt_cbc_mode(block * b, unsigned long bnum, unsigned char round_keys[NROUND][KEYSIZE])
{
	struct timeval current_time;
	unsigned char * ciphertext;
	static block iv;

	if (iv_generated) //not the first chunk of data, IV has already been prepended in a previous execution
	{
		ciphertext = malloc(BLOCKSIZE * bnum * sizeof(unsigned char));
		chunk_size = BLOCKSIZE * bnum * sizeof(unsigned char);
	}
	else //first chunk of data, IV has to be prepended to the ciphertext in this execution
	{
	 	ciphertext = malloc(BLOCKSIZE * (bnum+1) * sizeof(unsigned char));
		chunk_size = BLOCKSIZE * (bnum+1) * sizeof(unsigned char);
		create_prepend_iv(&iv, ciphertext);
	}
	
	//prev_ciphertext will start off with the initialization vector, later it will be used in every iteration x 
	//to store the ciphertext of block x, needed to encrypt the block x+1
	block prev_ciphertext = iv;

	//launching the feistel algorithm on every block
	for (unsigned long i=0; i<bnum; ++i) 
	{
		//logging (pre-encryption)
		current_block++;
		if (i % 100000 == 0)
		{
			gettimeofday(&current_time, NULL);
			show_progress_data(current_time);
		}
		block_logging(b[i], "\n----------CBC(ENC)-------BEFORE-----------", i);

		//XORing the current block x with the ciphertext of the block x-1
		block_xor(&b[i], &b[i], &prev_ciphertext);
		
		//executing the encryption on block x and saving the result in prev_ciphertext; it will be used in the next iteration
		process_block(b[i].left, b[i].right, round_keys);
		memcpy(&prev_ciphertext, &b[i], sizeof(block));

		//logging (post-encryption)
		block_logging(b[i], "\n----------CBC(ENC)-------AFTER-----------", i);
		
		//storing the ciphered block in the ciphertext variable
		for (int j=0; j<BLOCKSIZE; j++)	
		{
			if (iv_generated) //not the first chunk of data, IV has already been prepended in a previous execution
			{
				ciphertext[(i*BLOCKSIZE)+j] = b[i].left[j];
			}
			else //it's the first chunk of data, IV has been prepended in THIS execution, so the actual ciphertext slides by a block
			{
				ciphertext[((i+1)*BLOCKSIZE)+j] = b[i].left[j];
			}
		}
	}

	//The iv block for the next chunk will be the last value of prev_ciphertext
	memcpy(&iv, &prev_ciphertext, sizeof(block));
	//setting the flag here because, if I set it in the IV generation function, the for cycle that stores the ciphertext
	//would already see iv_generated=true and overwrite the IV
	//if I set it in the cycle instead, I would only correctly slide the ciphertext forward in the first iteration
	iv_generated = true;

	return ciphertext;
}

//Executes decryption in CBC mode; takes a block array, the total number of blocks and the round keys, returns processed data.
unsigned char * decrypt_cbc_mode(block * b, unsigned long bnum, unsigned char round_keys[NROUND][KEYSIZE])
{
	struct timeval current_time;
	unsigned char * plaintext;

	//ciphertext_copy will contain a copy of the whole ciphertext: for cbc decryption you need the ciphertext of the block i-1
	//to decrypt the block i. Since I'm operating the feistel algorithm in-place I needed to store these ciphertext blocks in advance.
	//I should find a more elegant way to do it (like a partial buffer with a bunch of blocks instead of a full-on copy).
	block * ciphertext_copy;
	block * ciphertext;
	static block iv;

	if (iv_generated)
	//IV has already been extracted in a previous execution and is already the iv static variable, 
	//this execution will proceed normally by just using the block array given in input 
	//and allocating bnum blocks worth of space for both the plaintext and the ciphertext copy 
	{
		ciphertext = b; 
		plaintext = calloc(BLOCKSIZE * bnum, sizeof(unsigned char));
		ciphertext_copy = malloc(bnum * sizeof(block));
		memcpy(ciphertext_copy, ciphertext, bnum * sizeof(block));
		chunk_size = BLOCKSIZE * bnum * sizeof(unsigned char);
	}
	else
	//IV has to be extracted in THIS execution, so the first element of the input array will be the IV
	//and we'll need to make a copy of the input array without the first block
	//So both the ciphertext array and the plaintext will get (bnum - 1) blocks worth of space
	{ 
		memcpy(&iv, &b[0], sizeof(block));
		plaintext = calloc(BLOCKSIZE * (bnum-1), sizeof(unsigned char));
		ciphertext = calloc(BLOCKSIZE * (bnum-1), sizeof(unsigned char));

		for (int i=0; i<(bnum-1); i++) memcpy(&ciphertext[i], &b[i+1], sizeof(block));

		ciphertext_copy = malloc((bnum-1) * sizeof(block));
		memcpy(ciphertext_copy, ciphertext, (bnum-1) * sizeof(block));
		chunk_size = BLOCKSIZE * (bnum-1) * sizeof(unsigned char);
		bnum--;
	}

	//launching the feistel algorithm on every block, by making the index jump by increments of BLOCKSIZE
	#pragma omp parallel for
	for (unsigned long i=0; i<bnum; ++i) 
	{	
		//logging (pre-decryption)
		#pragma omp critical
		block_logging(ciphertext[i], "\n----------CBC(DEC)------BEFORE-----------", i);
		current_block++;
		if (i % 100000 == 0)
		{
			gettimeofday(&current_time, NULL);
			show_progress_data(current_time);
		}

		//First thing, you run feistel on the block,...
		process_block(ciphertext[i].left, ciphertext[i].right, round_keys);

		if (i == 0) //...if it's the first block, you xor it with the IV...
			block_xor(&ciphertext[i], &ciphertext[i], &iv); 
		else	//...whereas for every other ciphered block x, you xor it with ciphertext[x-1]
			block_xor(&ciphertext[i], &ciphertext[i], &ciphertext_copy[(i)-1]); 			

		//logging (post-decryption)
		#pragma omp critical
		block_logging(ciphertext[i], "\n----------CBC(DEC)-------AFTER-----------", i);
		
		//storing the deciphered block in plaintext variable
		for (int j=0; j<BLOCKSIZE; j++)	plaintext[(i*BLOCKSIZE)+j] = ciphertext[i].left[j];
	}

	//The IV for the next chunk will be the ciphertext of the last decrypted block
	memcpy(&iv, &ciphertext_copy[(bnum)-1], sizeof(block));

	//If this is the first iteration, we have to free the ciphertext variable, 
	//because we used it to copy a version of the b variable without the first block
	//In any other case, we just made it point to main data pointer, so we can't free it
	if (!iv_generated) free(ciphertext);

	iv_generated = true;
	free(ciphertext_copy);

	return plaintext;
}

//Creates an IV block of data out of a random nonce and prepends it to the ciphertext
int create_prepend_iv(block * iv, unsigned char * ciphertext)
{
	if (iv_generated) //not the first chunk of data, IV has already been prepended in a previous execution
		return -1;

	unsigned char nonce[BLOCKSIZE];
	create_nonce(nonce);

	//populating the IV block with the nonce and prepend the IV block to the ciphertext
	for (int i=0; i<BLOCKSIZE/2; i++)
	{
		iv->left[i] = nonce[i];
		iv->right[i] = nonce[i + BLOCKSIZE/2];
		ciphertext[i] = nonce[i];
		ciphertext[i + BLOCKSIZE/2] = nonce[i + BLOCKSIZE/2];
	}

	return 0;
}