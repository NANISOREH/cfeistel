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


//These variables belong to the main, but are needed here to keep track of the processing
extern long unsigned total_file_size;
extern long unsigned current_block;

//Executes the cipher in ECB mode; takes a block array, the total number of blocks and the round keys, returns processed data.
unsigned char * operate_ecb_mode(block * b, unsigned long bnum, unsigned char round_keys[NROUND][KEYSIZE])
{
	struct timeval current_time;
	unsigned char * ciphertext;
	ciphertext = calloc(BLOCKSIZE * bnum, sizeof(unsigned char));
	if (ciphertext == NULL) return ciphertext;

	//launching the feistel algorithm on every block, by making the index jump by increments of BLOCKSIZE
	#pragma omp parallel for
	for (unsigned long i = 0; i < bnum; ++i) 
	{
		//logging (pre-processing)
		current_block++;
		if (i % 1200000 == 0)
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
	
	block counter_block;
	ciphertext = calloc(BLOCKSIZE * bnum, sizeof(unsigned char));
	if (ciphertext == NULL) return ciphertext;

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
			block_xor(b[cur], b[cur], counter_block);
			
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
	ciphertext = calloc(BLOCKSIZE * bnum, sizeof(unsigned char));
	if (ciphertext == NULL) return ciphertext;

	//prev_ciphertext will start off with the initialization vector, later it will be used in every iteration x 
	//to store the ciphertext of block x, needed to encrypt the block x+1
	block prev_ciphertext;
	for (int i=0; i<BLOCKSIZE/2; i++)
	{
		prev_ciphertext.left[i] = 12 + i;
		prev_ciphertext.right[i] = 65 + i;
	}

	//launching the feistel algorithm on every block
	for (unsigned long i=0; i<bnum; ++i) 
	{
		//logging (pre-encryption)
		current_block++;
		if (i % 1200000 == 0)
		{
			gettimeofday(&current_time, NULL);
			show_progress_data(current_time);
		}
		block_logging(b[i], "\n----------CBC(ENC)-------BEFORE-----------", i);

		//XORing the current block x with the ciphertext of the block x-1
		block_xor(b[i], b[i], prev_ciphertext);
		
		//executing the encryption on block x and saving the result in prev_ciphertext; it will be used in the next iteration
		process_block(b[i].left, b[i].right, round_keys);
		memcpy(&prev_ciphertext, &b[i], sizeof(block));

		//logging (post-encryption)
		block_logging(b[i], "\n----------CBC(ENC)-------AFTER-----------", i);
		
		//storing the ciphered block in the ciphertext variable
		for (int j=0; j<BLOCKSIZE; j++)	
		{
			ciphertext[(i*BLOCKSIZE)+j] = b[i].left[j];
		}
	}

	return ciphertext;
}

//Executes decryption in CBC mode; takes a block array, the total number of blocks and the round keys, returns processed data.
unsigned char * decrypt_cbc_mode(block * b, unsigned long bnum, unsigned char round_keys[NROUND][KEYSIZE])
{
	struct timeval current_time;
	unsigned char * plaintext;
	plaintext = calloc(BLOCKSIZE * bnum, sizeof(unsigned char));
	if (plaintext == NULL) return plaintext;

	//making a copy of the whole ciphertext: for cbc decryption you need the ciphertext of the block i-1
	//to decrypt the block i. Since I'm operating the feistel algorithm in-place I needed to store these ciphertexts in advance.
	//I should find a more elegant way to do it (like a partial buffer with a bunch of blocks instead of a full-on copy).
	//As it is now, it burns more ram than friggin Chrome.
	block * blocks_copy;
	blocks_copy = malloc(bnum * sizeof(block));
	memcpy(blocks_copy, b, bnum * sizeof(block));

	//initialization vector
	block iv;
	for (int i=0; i<BLOCKSIZE/2; i++)
	{
		iv.left[i] = 12 + i;
		iv.right[i] = 65 + i;
	}

	//launching the feistel algorithm on every block, by making the index jump by increments of BLOCKSIZE
	#pragma omp parallel for
	for (unsigned long i=0; i<bnum; ++i) 
	{	
		//logging (pre-decryption)
		#pragma omp critical
		block_logging(b[i], "\n----------CBC(DEC)-------BEFORE-----------", i);
		current_block++;
		if (i % 1200000 == 0)
		{
			gettimeofday(&current_time, NULL);
			show_progress_data(current_time);
		}

		//First thing, you run feistel on the block,...
		process_block(b[i].left, b[i].right, round_keys);

		//...if it's the first block, you xor it with the IV...
		if (i == 0)	block_xor(b[i], b[i], iv); 
		//...whereas for every other ciphered block x, you xor it with ciphertext[x-1]
		else	block_xor(b[i], b[i], blocks_copy[(i)-1]); 

		//logging (post-decryption)
		#pragma omp critical
		block_logging(b[i], "\n----------CBC(DEC)-------AFTER-----------", i);
		
		//storing the deciphered block in plaintext variable
		for (int j=0; j<BLOCKSIZE; j++)	plaintext[(i*BLOCKSIZE)+j] = b[i].left[j];

	}

	free(blocks_copy);
	return plaintext;
}

//Executes encryption in ICBC (Interleaved CBC) mode; takes a block array, the total number of blocks and the round keys, returns processed data.
unsigned char * encrypt_icbc_mode(block * b, unsigned long bnum, unsigned char round_keys[NROUND][KEYSIZE])
{
	struct timeval current_time;
	unsigned char * ciphertext;
	ciphertext = calloc(BLOCKSIZE * bnum, sizeof(unsigned char));
	if (ciphertext == NULL) return ciphertext;

	//launching the feistel algorithm on every block
	#pragma omp parallel
	{
		//prev_ciphertext will start off with the initialization vector, later it will be used in every iteration x 
		//to store the ciphertext of block x, needed to encrypt the block x+1
		block prev_ciphertext;
		for (int i=0; i<BLOCKSIZE/2; i++)
		{
			prev_ciphertext.left[i] = 12 + i;
			prev_ciphertext.right[i] = 65 + i;
		}

		//each thread will have its own copy of prev_ciphertext, since they will always have to xor a different block
		//and the schedule(static, 1) clause will make sure that every thread gets one "turn" and then gives control to the next thread
		//so that the processing gets correctly interleaved and prev_ciphertext for any thread on iteration i 
		//always contains the cyphertext of the block [i-n], where n is the number of active threads
		#pragma omp for private(prev_ciphertext) schedule(static, 1)
		for (unsigned long i=0; i<bnum; ++i) 
		{
			//logging (pre-encryption)
			current_block++;
			if (i % 1200000 == 0)
			{
				gettimeofday(&current_time, NULL);
				show_progress_data(current_time);
			}
			#pragma omp critical
			block_logging(b[i], "\n----------ICBC(enc)-------BEFORE-----------", i);

			//XORing the current block x with the ciphertext of the block x-n, where n is the number of active threads
			block_xor(b[i], b[i], prev_ciphertext);
			
			//executing the encryption on block x and saving the result in prev_ciphertext; it will be used in the next iteration
			process_block(b[i].left, b[i].right, round_keys);
			memcpy(&prev_ciphertext, &b[i], sizeof(block));

			//logging (post-encryption)
			#pragma omp critical
			block_logging(b[i], "\n----------ICBC(enc)-------AFTER-----------", i);
			
			//storing the ciphered block in the ciphertext variable
			for (int j=0; j<BLOCKSIZE; j++)	
			{
				ciphertext[(i*BLOCKSIZE)+j] = b[i].left[j];
			}
		}
	}

	return ciphertext;
}