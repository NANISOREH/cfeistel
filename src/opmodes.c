//This module contains the functions that implement the logic of the cipher's operation modes.
//They can theoretically be used with any block cipher.

#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "stdbool.h"
#include "common.h"
#include "utils.h"
#include "feistel.h"
#include "sys/time.h"
#include "omp.h"
#include "stdint.h"
#include <openssl/asn1.h>

//These variables belong to the main, but are needed here to keep track of the processing
extern long unsigned total_file_size;
extern long unsigned current_block;
extern long unsigned chunk_size;
extern int nchunk;

//Executes the cipher in ECB mode; takes a block array, the total number of blocks and the round keys, returns processed data.
unsigned char * operate_ecb_mode(block * b, unsigned long bnum, unsigned char round_keys[NROUND][KEYSIZE])
{
	struct timeval current_time;
	
	static unsigned char * ciphertext;
	free(ciphertext);
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
		block_logging((unsigned char *)&b[i], "\n----------ECB-------BEFORE-----------", i);

		//applying the cipher on the current block
		process_block((unsigned char *)&b[i], b[i].left, b[i].right, round_keys);

		//logging (post-processing)
		#pragma omp critical
		block_logging((unsigned char *)&b[i], "\n----------ECB-------AFTER-----------", i);

		//appending the result to the ciphertext variable
		for (int j = 0; j < BLOCKSIZE; j++)	
		{
			ciphertext[(i*BLOCKSIZE) + j] = b[i].left[j];
		}
	}
	return ciphertext;
}

//Executes the cipher in CTR mode; takes a block array, the total number of blocks and the round keys, returns processed data.
unsigned char * operate_ctr_mode(block * b, unsigned long bnum, unsigned char round_keys[NROUND][KEYSIZE], block iv)
{
	static unsigned char * ciphertext;
	struct timeval current_time;
	block counter_block;
	unsigned long initial_counter = 0;
	long unsigned counter = 0;
	//This static variable will contain the last counter value for the previous processed chunk
	static unsigned long next_initial_counter;

	if (nchunk==0) //Initializing the counter and the IV when it's the first processed chunk
	{
		initial_counter = derive_number_from_block(&iv);
	}
	else //not the first chunk of data, IV has already been used in a previous execution
	{
		initial_counter = next_initial_counter;
	}

	//The ciphertext variable can't be deallocated after use here, because the caller needs it
	//So, in order to avoid memory leaks, I've made it static and I free its memory before any consequent execution
	//(I could just reuse the space but I don't know how big the last chunk will be at this point)
	free(ciphertext);
	ciphertext = malloc(BLOCKSIZE * bnum * sizeof(unsigned char));
	if (ciphertext == NULL) return ciphertext;

	chunk_size = BLOCKSIZE * bnum * sizeof(unsigned char);

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
			block_logging((unsigned char *)&b[i], "\n----------CTR-------BEFORE-----------", i);
			
			//applying the cipher on the counter block and incrementing the counter
			process_block((unsigned char *)&counter_block, counter_block.left, counter_block.right, round_keys);

			//xor between the ciphered counter block and the current block of plaintext/ciphertext
			block_xor(&b[i], &b[i], &counter_block);
			
			//logging (post-processing)
			#pragma omp critical
			block_logging((unsigned char *) &b[i], "\n----------CTR-------AFTER-----------", i);

			//storing the ciphered block in the ciphertext variable
			for (int j=0; j<BLOCKSIZE; j++)	
			{
				ciphertext[(i*BLOCKSIZE)+j] = b[i].left[j];	
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

//Executes encryption in CBC mode; takes a block array, the total number of blocks and the round keys, returns processed data.
unsigned char * encrypt_cbc_mode(block * b, unsigned long bnum, unsigned char round_keys[NROUND][KEYSIZE], block iv)
{
	struct timeval current_time;
	static unsigned char * ciphertext;

	free(ciphertext);
	ciphertext = malloc(BLOCKSIZE * bnum * sizeof(unsigned char));
	if (ciphertext == NULL) return ciphertext;

	chunk_size = BLOCKSIZE * bnum * sizeof(unsigned char);

	//Copying the IV to a local variable if we're processing the first block 
	static block prev_ciphertext;
	if (nchunk == 0) memcpy(&prev_ciphertext, &iv, BLOCKSIZE);

	block_logging((unsigned char *)&prev_ciphertext, "\n----------CBC(ENC)-------IV-----------", 0);

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
		block_logging((unsigned char *)&b[i], "\n----------CBC(ENC)-------BEFORE-----------", i);

		//XORing the current block x with the ciphertext of the block x-1
		block_xor(&b[i], &b[i], &prev_ciphertext);
		
		//executing the encryption on block x and saving the result in prev_ciphertext; it will be used in the next iteration
		process_block((unsigned char *)&b[i], b[i].left, b[i].right, round_keys);
		memcpy(&prev_ciphertext, &b[i], sizeof(block));

		//logging (post-encryption)
		block_logging((unsigned char *)&b[i], "\n----------CBC(ENC)-------AFTER-----------", i);
		
		//storing the ciphered block in the ciphertext variable
		for (int j=0; j<BLOCKSIZE; j++)	
		{
			ciphertext[(i*BLOCKSIZE)+j] = b[i].left[j];
		}
	}

	return ciphertext;
}

//Executes decryption in CBC mode; takes a block array, the total number of blocks and the round keys, returns processed data.
unsigned char * decrypt_cbc_mode(block * b, unsigned long bnum, unsigned char round_keys[NROUND][KEYSIZE], block iv)
{
	struct timeval current_time;
	
	//The plaintext variable can't be deallocated after use here, because the caller needs it
	//So, in order to avoid memory leaks, I've made it static and I free its memory before any consequent execution
	//(I could just reuse the space but I don't know how big the last chunk will be at this point)
	static unsigned char * plaintext;
	free(plaintext);
	plaintext = calloc(BLOCKSIZE * bnum, sizeof(unsigned char));
	if (plaintext == NULL) return plaintext;

	//ciphertext_copy will contain a copy of the whole ciphertext: for cbc decryption you need the ciphertext of the block i-1
	//to decrypt the block i. Since I'm operating the feistel algorithm in-place I needed to store these ciphertext blocks in advance.
	//I should find a more elegant way to do it (like a partial buffer with a bunch of blocks instead of a full-on copy).
	block * ciphertext_copy;
	ciphertext_copy = malloc(bnum * sizeof(block));
	
	//Copying the IV to the local variable if we're processing the first block 
	static block current_iv;
	if (nchunk == 0) memcpy(&current_iv, &iv, BLOCKSIZE);
	
	memcpy(ciphertext_copy, b, bnum * sizeof(block));
	chunk_size = BLOCKSIZE * bnum * sizeof(unsigned char);

	block_logging((unsigned char *)&current_iv, "\n----------CBC(DEC)-------IV-----------", 0);

	//launching the feistel algorithm on every block, by making the index jump by increments of BLOCKSIZE
	#pragma omp parallel for
	for (unsigned long i=0; i<bnum; ++i) 
	{	
		//logging (pre-decryption)
		#pragma omp critical
		block_logging((unsigned char *)&b[i], "\n----------CBC(DEC)------BEFORE-----------", i);
		current_block++;
		if (i % 10000 == 0)
		{
			gettimeofday(&current_time, NULL);
			show_progress_data(current_time);
		}

		//First thing, you run feistel on the block,...
		process_block((unsigned char *)&b[i], b[i].left, b[i].right, round_keys);

		if (i == 0) //...if it's the first block, you xor it with the IV...
			block_xor(&b[i], &b[i], &current_iv); 
		else	//...whereas for every other ciphered block x, you xor it with ciphertext[x-1]
			block_xor(&b[i], &b[i], &ciphertext_copy[(i)-1]); 			

		//logging (post-decryption)
		#pragma omp critical
		block_logging((unsigned char *)&b[i], "\n----------CBC(DEC)-------AFTER-----------", i);
		
		//storing the deciphered block in plaintext variable
		for (int j=0; j<BLOCKSIZE; j++)	plaintext[(i*BLOCKSIZE)+j] = b[i].left[j];
	}

	//The IV for the next chunk will be the ciphertext of the last decrypted block
	memcpy(&current_iv, &ciphertext_copy[(bnum)-1], sizeof(block));

	free(ciphertext_copy);

	return plaintext;
}

//Executes the cipher in OFB mode; takes a block array, the total number of blocks and the round keys, returns processed data.
unsigned char * operate_ofb_mode(block * b, unsigned long bnum, unsigned char round_keys[NROUND][KEYSIZE], block iv)
{
	struct timeval current_time;
	unsigned char * keystream;
	static unsigned char * ciphertext;
	//Casting the block pointer to a char one because it's comfier for stream-like logic
	unsigned char * plaintext = (unsigned char*)b;

	//Copying the IV block to a local variable only if we're operating on the first chunk
	static block current_iv;
	if (nchunk == 0) 
		memcpy(&current_iv, &iv, BLOCKSIZE);

	chunk_size = BLOCKSIZE * bnum * sizeof(unsigned char);
	keystream = malloc(BLOCKSIZE * bnum * sizeof(unsigned char));

	free(ciphertext);
	ciphertext = malloc(BLOCKSIZE * bnum * sizeof(unsigned char));
	if (ciphertext == NULL) return ciphertext;

	block_logging((unsigned char *)&iv, "\n----------OFB(ENC)------IV-----------", 0);

	//launching the cycle that will create the OFB keystream
	for (unsigned long i=0; i<bnum; ++i) 
	{
		//logging (pre-encryption)
		current_block++;
		if (i % 10000 == 0)
		{
			gettimeofday(&current_time, NULL);
			show_progress_data(current_time);
		}
		
		//executing the encryption on the last processed keystream block
		if (i==0) 
			process_block(&keystream[i*BLOCKSIZE], current_iv.left, current_iv.right, round_keys);
		else 
			process_block(&keystream[i*BLOCKSIZE], &keystream[(i-1)*BLOCKSIZE], &keystream[((i-1)*BLOCKSIZE) + BLOCKSIZE/2], round_keys);
	}

	//launching the cycle that will XOR the keystream and the plaintext to produce the ciphertext
	#pragma omp parallel for
	for (size_t i = 0; i < bnum * BLOCKSIZE; i++) 
	{
		ciphertext[i] = keystream[i] ^ plaintext[i];
		
		//If i+1 is a multiple of blocksize, it means we just finished XORing a whole block, we can print it
		if (i > 0 && (i+1) % BLOCKSIZE == 0)
		{
			//The position where we start printing would be i - (b-1) with b=BLOCKSIZE, here's why:
			//
			//We're now at iteration i = b*k - 1, where k is a natural multiple of BLOCKSIZE, and we want the index we had at i = b * (k-1),
			//which is exactly the last multiple of BLOCKSIZE before the current index and therefore the last used block index.
			//
			//Again, the current index is i = b*k - 1 because we enter this conditional one position before a multiple of b.
			//If we subtract (b - 1) to the current index we get i = b*k-1-(b-1) = b*k-1-b+1 = b*k-b = b * (k-1)
			block_logging(&keystream[(i - (BLOCKSIZE - 1))], "\n----------OFB(ENC)------keystream-----------", (i/BLOCKSIZE));
			block_logging(&plaintext[(i - (BLOCKSIZE - 1))], "\n----------OFB(ENC)------plaintext-----------", i/BLOCKSIZE);
			block_logging(&ciphertext[(i - (BLOCKSIZE - 1))], "\n----------OFB(ENC)------ciphertext-----------", i/BLOCKSIZE);
		}
    }

	//The iv block for the next chunk will be the last block of the keystream
	memcpy(&current_iv, &keystream[(bnum - 1) * BLOCKSIZE], sizeof(block));
	free(keystream);

	return ciphertext;
}
