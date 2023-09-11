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
unsigned char * operate_ctr_mode(block * b, unsigned long bnum, unsigned char round_keys[NROUND][KEYSIZE])
{
	unsigned char * ciphertext;
	struct timeval current_time;

	//using the checksum of the master key as starting point for the counter
	unsigned long counter = 0;
	for (int j=0; j<KEYSIZE; j++)
		counter = counter + round_keys[0][j];

	//deriving the nonce from the master key (i'm recycling the s-box to do that)
	//you would usually just use a random nonce and append it for decryption
	unsigned char nonce[KEYSIZE];
	create_nonce(nonce, round_keys);
	
	block counter_block;
	ciphertext = calloc(BLOCKSIZE * bnum, sizeof(unsigned char));
	if (ciphertext == NULL) return ciphertext;

	chunk_size = BLOCKSIZE * bnum * sizeof(unsigned char);

	#pragma omp parallel
	{
		int cur = 0;
		//launching the feistel algorithm on every block
		//I use the initial counter as a starting point for the index, because openMP parallelizing for cycles
		//apparently works better if you rely on the index to distribute the iterations
		#pragma omp for private(counter_block)
		for (unsigned long i=counter; i<bnum+counter; ++i)
		{
			//This variable will hold the current block
			//Yes, I already literally have a current_block variable, but it's an extern one that's defined in the main file
			//and keeps track of the current block in the whole input file, not just in the currently processing chunk
			cur = i-counter;

			//initializing the counter block for this iteration
			str_safe_copy(counter_block.left, nonce, BLOCKSIZE/2);
			stringify_counter(counter_block.right, i);

			//logging (pre-processing)
			current_block++;
			if (cur % 1200000 == 0)
			{
				gettimeofday(&current_time, NULL);
				show_progress_data(current_time);
			}
			#pragma omp critical
			block_logging(b[cur], "\n----------CTR-------BEFORE-----------", cur);
			
			//applying the cipher on the counter block and incrementing the counter
			process_block(counter_block.left, counter_block.right, round_keys);

			//xor between the ciphered counter block and the current block of plaintext/ciphertext
			// half_block_xor(b[cur].left, b[cur].left, counter_block.left);
			// half_block_xor(b[cur].right, b[cur].right, counter_block.right);
			block_xor(&b[cur], &b[cur], &counter_block);
			
			//logging (post-processing)
			#pragma omp critical
			block_logging(b[cur], "\n----------CTR-------AFTER-----------", cur);
			
			//storing the result of the xor in the output variable
			for (unsigned long j=0; j<BLOCKSIZE; j++)	
			{
				ciphertext[((cur)*BLOCKSIZE)+j] = b[cur].left[j];
			}
		}	
	}

	return ciphertext;
}

//Executes encryption in CBC mode; takes a block array, the total number of blocks and the round keys, returns processed data.
unsigned char * encrypt_cbc_mode(block * b, unsigned long bnum, unsigned char round_keys[NROUND][KEYSIZE])
{
	struct timeval current_time;
	unsigned char * ciphertext;
	static block iv;

	if (iv_generated) //not the first chunk of data, IV has already been prepended in a previous execution
	{
		ciphertext = calloc(BLOCKSIZE * bnum, sizeof(unsigned char));
		chunk_size = BLOCKSIZE * bnum * sizeof(unsigned char);
	}
	else //it's the first chunk of data, IV has to be prepended in THIS execution, so an extra block worth of space is needed
	{
		ciphertext = calloc(BLOCKSIZE * (bnum+1), sizeof(unsigned char));
		chunk_size = BLOCKSIZE * (bnum+1) * sizeof(unsigned char);
		create_prepend_iv(&iv, ciphertext, round_keys);
	}
	if (ciphertext == NULL) return ciphertext;
	
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
	iv_generated = true;
	free(ciphertext_copy);

	return plaintext;
}

//Yes, a fixed IV for each key is highly unsecure and you should never do it 
//I'll have this function generate an unpredictable IV at some point 
int create_prepend_iv(block * iv, unsigned char * ciphertext, unsigned char round_keys[NROUND][KEYSIZE])
{
	if (iv_generated) return -1;

	//deriving the nonce from the master key (i'm recycling the s-box to do that)
	//you would usually just use a random nonce and append it for decryption
	unsigned char nonce[BLOCKSIZE];
	str_safe_copy(nonce, round_keys[0], BLOCKSIZE); 
	unsigned char left_part;
	unsigned char right_part;
	for (int i = 0; i<KEYSIZE; i++) //every byte goes through the s-box
	{
		split_byte(&left_part, &right_part, nonce[i]);
		s_box(&right_part, 0);
		s_box(&left_part, 1);
		merge_byte(&nonce[i], left_part, right_part);
	}

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

int create_nonce(unsigned char nonce[KEYSIZE], unsigned char round_keys[NROUND][KEYSIZE])
{
	//deriving the nonce from the master key (i'm recycling the s-box to do that)
	//you would usually just use a random nonce and append it for decryption
	str_safe_copy(nonce, round_keys[0], KEYSIZE); 
	unsigned char left_part;
	unsigned char right_part;
	for (int i = 0; i<KEYSIZE; i++) //every byte goes through the s-box
	{
		split_byte(&left_part, &right_part, nonce[i]);
		s_box(&right_part, 0);
		s_box(&left_part, 1);
		merge_byte(&nonce[i], left_part, right_part);
	}

	return 0;
}