//This module contains the functions that implement the logic of the cipher's operation modes.
//They can theoretically be used with any block cipher.

#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "stdbool.h"
#include "common.h"
#include "utils.h"
#include "feistel.h"
#include "opmodes.h"
#include "sys/time.h"
#include "omp.h"
#include "stdint.h"

//These variables belong to the main, but are needed here to keep track of the processing
extern long unsigned total_file_size;
extern long unsigned current_block;
extern long unsigned chunk_size;
extern int nchunk;

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
		if (i % 10000 == 0)
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
	block counter_block;
	block iv;
	unsigned long initial_counter = 0;
	long unsigned counter = 0;
	//This static variable will contain the last counter value for the previous processed chunk
	static unsigned long next_initial_counter;

	if (nchunk==0) //Initializing the counter and the IV when it's the first processed chunk
	{
		//first chunk of data, IV has to be created and prepended to the ciphertext in this execution
		ciphertext = malloc(BLOCKSIZE * (bnum+1) * sizeof(unsigned char));
		chunk_size = BLOCKSIZE * (bnum+1) * sizeof(unsigned char);
		initial_counter = create_nonce(&iv);
		prepend_block((block*)&iv, ciphertext);
	}
	else //not the first chunk of data, IV has already been prepended in a previous execution
	{
		ciphertext = malloc(BLOCKSIZE * bnum * sizeof(unsigned char));
		chunk_size = BLOCKSIZE * bnum * sizeof(unsigned char);
		initial_counter = next_initial_counter;
	}

	#pragma omp parallel private (counter, counter_block)
	{
		counter = initial_counter;		
		//launching the feistel algorithm on every block
		#pragma omp for schedule(static, 1)
		for (unsigned long i=0; i<bnum; i++)
		{
			counter=initial_counter + i;

			//initializing the counter block for this iteration 
			derive_block_from_number(counter, &counter_block);

			// #pragma omp critical
			// block_logging(counter_block, "\n----------CTR(ENC)-------COUNTER BLOCK-----------", i);

			//logging (pre-processing)
			current_block++;
			if (i % 10000 == 0)
			{
				gettimeofday(&current_time, NULL);
				show_progress_data(current_time);
			}

			#pragma omp critical
			block_logging(b[i], "\n----------CTR-------BEFORE-----------", i);
			
			//applying the cipher on the counter block and incrementing the counter
			process_block(counter_block.left, counter_block.right, round_keys);

			//xor between the ciphered counter block and the current block of plaintext/ciphertext
			block_xor(&b[i], &b[i], &counter_block);
			
			//logging (post-processing)
			#pragma omp critical
			block_logging(b[i], "\n----------CTR-------AFTER-----------", i);

			//storing the ciphered block in the ciphertext variable
			for (int j=0; j<BLOCKSIZE; j++)	
			{
				if (nchunk>0) //not the first chunk of data, IV has already been prepended in a previous execution
				{
					ciphertext[(i*BLOCKSIZE)+j] = b[i].left[j];	
				}
				else //it's the first chunk of data, IV has been prepended in THIS execution, so the actual ciphertext slides by a block
				{
					ciphertext[((i+1)*BLOCKSIZE)+j] = b[i].left[j];
				}
			}

			//It's the last iteration, setting the starting counter for the next chunk
			if (i == bnum - 1 ) next_initial_counter = counter + 1;
		}	
	}

	//I'm using a second static variable to save the initial counter for the next chunk
	//Because if I used the one that I access during the parallel for, I would have interleaving issues:
	//the value would be set by the thread handling the last iteration numerically, not chronologically
	//and that means some threads might occasionally still be "left behind" processing earlier iterations
	//with an incorrect value of initial_counter
	initial_counter = next_initial_counter;
	return ciphertext;
}

//Executes the cipher in CTR mode; takes a block array, the total number of blocks and the round keys, returns processed data.
unsigned char * decrypt_ctr_mode(block * b, unsigned long bnum, unsigned char round_keys[NROUND][KEYSIZE])
{
	unsigned char * plaintext;
	block * ciphertext;
	struct timeval current_time;
	block counter_block;
	block iv;
	unsigned long initial_counter = 0;
	long unsigned counter = 0;
	//This static variable will contain the last counter value for the previous processed chunk
	static unsigned long next_initial_counter;

	ciphertext = b;
	plaintext = malloc(BLOCKSIZE * bnum * sizeof(unsigned char));

	if (nchunk>0) //not the first chunk of data, IV has already been taken from a previous execution
	{
		initial_counter = next_initial_counter;
		chunk_size = BLOCKSIZE * (bnum) * sizeof(unsigned char);
	}
	else //first chunk of data, IV (content of counter_block) has to be taken from the ciphertext in this execution
	{
		//Copying the first block of data into the iv variable and using it to initialize the counter
		memcpy(&iv, &b[0], BLOCKSIZE * sizeof(unsigned char));
		initial_counter = derive_number_from_block(&iv);

		//We set the chunksize to BLOCKSIZE less than the data we received in input
		//to account for the first block not containing actual data 
		chunk_size = BLOCKSIZE * (bnum-1) * sizeof(unsigned char);
	}
	
	#pragma omp parallel private (counter, counter_block)
	{	
		counter = initial_counter;
		//launching the feistel algorithm on every block
		#pragma omp for schedule(static, 1)
		for (unsigned long i=0; i<bnum; i++)
		{
			if (nchunk==0) 
			{
				counter = initial_counter + i - 1;
				//It's the IV, we don't process it
				if (i == 0) continue;
			}
			else counter = initial_counter + i;

			//initializing the counter block for this iteration 
			derive_block_from_number(counter, &counter_block);

			// #pragma omp critical
			// block_logging(counter_block, "\n----------CTR(DEC)-------COUNTER BLOCK-----------", i);

			//logging (pre-processing)
			current_block++;
			if (i % 10000 == 0)
			{
				gettimeofday(&current_time, NULL);
				show_progress_data(current_time);
			}

			#pragma omp critical
			block_logging(ciphertext[i], "\n----------CTR-------BEFORE-----------", i);
			
			//applying the cipher on the counter block and incrementing the counter
			process_block(counter_block.left, counter_block.right, round_keys);

			//xor between the ciphered counter block and the current block of plaintext/ciphertext
			block_xor(&ciphertext[i], &ciphertext[i], &counter_block);
			
			//logging (post-processing)
			#pragma omp critical
			block_logging(ciphertext[i], "\n----------CTR-------AFTER-----------", i);
			
			//storing the result of the xor in the output variable
			for (unsigned long j=0; j<BLOCKSIZE; j++)	
			{
				plaintext[((i)*BLOCKSIZE)+j] = ciphertext[i].left[j];
			}

			//It's the last iteration, setting the starting counter for the next chunk
			if (i == bnum - 1 ) next_initial_counter = counter + 1;
		}	
	}

	//I'm using a second static variable to save the initial counter for the next chunk
	//Because if I used the one that I access during the parallel for, I would have interleaving issues:
	//the value would be set by the thread handling the last iteration numerically, not chronologically
	//and that means some threads might occasionally still be "left behind" processing earlier iterations
	//with an incorrect value of initial_counter
	initial_counter = next_initial_counter;

	//If it's the first chunk, the first block was the IV, so we skip it
	if (nchunk==0) 
	{
		plaintext = plaintext + 16;
	}

	return plaintext;
}

//Executes encryption in CBC mode; takes a block array, the total number of blocks and the round keys, returns processed data.
unsigned char * encrypt_cbc_mode(block * b, unsigned long bnum, unsigned char round_keys[NROUND][KEYSIZE])
{
	struct timeval current_time;
	unsigned char * ciphertext;
	static block iv;

	if (nchunk>0) //not the first chunk of data, IV has already been prepended in a previous execution
	{
		ciphertext = malloc(BLOCKSIZE * bnum * sizeof(unsigned char));
		chunk_size = BLOCKSIZE * bnum * sizeof(unsigned char);
	}
	else //first chunk of data, IV has to be prepended to the ciphertext in this execution
	{
	 	ciphertext = malloc(BLOCKSIZE * (bnum+1) * sizeof(unsigned char));
		chunk_size = BLOCKSIZE * (bnum+1) * sizeof(unsigned char);
		create_nonce(&iv);
		prepend_block(&iv, ciphertext);
	}
	
	//prev_ciphertext will start off with the initialization vector, later it will be used in every iteration x 
	//to store the ciphertext of block x, needed to encrypt the block x+1
	block prev_ciphertext = iv;

	//launching the feistel algorithm on every block
	for (unsigned long i=0; i<bnum; ++i) 
	{
		//logging (pre-encryption)
		current_block++;
		if (i % 10000 == 0)
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
			if (nchunk>0) //not the first chunk of data, IV has already been prepended in a previous execution
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

	if (nchunk>0)
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
		if (i % 10000 == 0)
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
	if (nchunk==0) free(ciphertext);

	free(ciphertext_copy);

	return plaintext;
}




































void operate_ctr_mode(unsigned char * processed, block * to_process, unsigned long initial_counter, unsigned long * next_initial_counter, unsigned long bnum, unsigned char round_keys[NROUND][KEYSIZE])
{
	unsigned int counter = 0;
	block counter_block;
	struct timeval current_time;

	#pragma omp parallel private (counter, counter_block)
	{	
		counter = initial_counter;
		//launching the feistel algorithm on every block
		#pragma omp for schedule(static, 1)
		for (unsigned long i=0; i<bnum; i++)
		{
			counter = initial_counter + i;

			//initializing the counter block for this iteration 
			derive_block_from_number(counter, &counter_block);

			#pragma omp critical
			block_logging(counter_block, "\n----------CTR(DEC)-------COUNTER BLOCK-----------", i);

			//logging (pre-processing)
			current_block++;
			if (i % 100000 == 0)
			{
				gettimeofday(&current_time, NULL);
				show_progress_data(current_time);
			}

			#pragma omp critical
			block_logging(to_process[i], "\n----------CTR-------BEFORE-----------", i);
			
			//applying the cipher on the counter block and incrementing the counter
			process_block(counter_block.left, counter_block.right, round_keys);

			//xor between the ciphered counter block and the current block of plaintext/ciphertext
			block_xor(&to_process[i], &to_process[i], &counter_block);
			
			//logging (post-processing)
			#pragma omp critical
			block_logging(to_process[i], "\n----------CTR-------AFTER-----------", i);
			
			//storing the result of the xor in the output variable
			for (unsigned long j=0; j<BLOCKSIZE; j++)	
			{
				processed[((i)*BLOCKSIZE)+j] = to_process[i].left[j];
			}

			//It's the last iteration, setting the starting counter for the next chunk
			if (i == bnum - 1 ) *next_initial_counter = counter + 1;
		}	
	}
}