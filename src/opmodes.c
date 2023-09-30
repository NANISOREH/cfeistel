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
extern struct timeval start_time;

//Executes the cipher in ECB mode; takes a block array, the total number of blocks and the round keys.
void operate_ecb_mode(unsigned char * result, block * b, const unsigned long bnum, const unsigned char round_keys[NROUND][KEYSIZE])
{
	struct timeval current_time;
	static int current_block = 0;

	//launching the feistel algorithm on every block, by making the index jump by increments of BLOCKSIZE
	#pragma omp parallel for
	for (unsigned long i = 0; i < bnum; ++i) 
	{
		//logging (pre-processing)
		current_block++;
		if (i % 10000 == 0)
		{
			gettimeofday(&current_time, NULL);
			show_progress_data(current_time, start_time, total_file_size, current_block);
		}
		#pragma omp critical
		block_logging((unsigned char *)&b[i], "\n----------ECB-------BEFORE-----------", i);

		//applying the cipher on the current block
		process_block(&result[i * BLOCKSIZE], b[i].left, b[i].right, round_keys);

		//logging (post-processing)
		#pragma omp critical
		block_logging(&result[i * BLOCKSIZE], "\n----------ECB-------AFTER-----------", i);
	}
}

//Executes the cipher in CTR mode; 
//takes a block array, the length of the chunk, an IV and the round keys, returns processed data.
void operate_ctr_mode(unsigned char * result, block * b, const unsigned long data_len, const unsigned char round_keys[NROUND][KEYSIZE], const block iv)
{
	struct timeval current_time;
	static int current_block = 0;

	static bool first_chunk = true;

	block counter_block;
	//Casting the block pointer to a char one because it's comfier for stream-like logic
	unsigned char * data = (unsigned char*)b;

	static unsigned long initial_counter;
	long unsigned counter = 0;
	unsigned long next_initial_counter;

	if (first_chunk == true) //Initializing the counter with the IV when it's the first processed chunk
	{
		initial_counter = derive_number_from_block(&iv);
	}

	int bnum = 0;
	if (data_len % BLOCKSIZE == 0) 
		bnum = data_len/BLOCKSIZE;
	else 
		//if data_len is not a perfect multiple of blocksize we need to count an extra block:
		//otherwise we wouldn't have the keystream available for the partial block at the end
	 	bnum = data_len/BLOCKSIZE + 1;

	unsigned char * keystream;
	keystream = malloc(BLOCKSIZE * bnum * sizeof(unsigned char));

	//launching the cycle that will create the CTR keystream
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

			//logging (pre-processing)
			current_block++;
			if (i % 10000 == 0)
			{
				gettimeofday(&current_time, NULL);
				show_progress_data(current_time, start_time, total_file_size, current_block);
			}
			
			//applying the cipher on the counter block 
			process_block(&keystream[i*BLOCKSIZE], counter_block.left, counter_block.right, round_keys);

			//It's the last iteration, setting the starting counter for the next chunk
			if (i == bnum - 1 ) next_initial_counter = counter + 1;
		}	
	}

	//launching the cycle that will XOR the keystream and the data to produce the ciphertext
	#pragma omp parallel for
	for (size_t i = 0; i < data_len; i++) 
	{
		result[i] = keystream[i] ^ data[i];
		
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
			block_logging(&keystream[(i - (BLOCKSIZE - 1))], "\n----------CTR(ENC)------keystream-----------", (i/BLOCKSIZE));
			block_logging(&data[(i - (BLOCKSIZE - 1))], "\n----------CTR(ENC)------plaintext-----------", i/BLOCKSIZE);
			block_logging(&result[(i - (BLOCKSIZE - 1))], "\n----------CTR(ENC)------ciphertext-----------", i/BLOCKSIZE);
		}
    }

	//I'm using a second variable to save the initial counter for the next chunk during the cycle
	//Because if I used the one that I access during the parallel for, I would have interleaving issues:
	//the value would be set by the thread handling the last iteration numerically, not chronologically
	//and that means some threads might occasionally still be "left behind" processing earlier iterations
	//with an incorrect value of initial_counter
	//Here we copy it back to the static variable that will store it for the next chunk
	initial_counter = next_initial_counter;
	
	free(keystream);
	first_chunk = false;
}

//Executes encryption in CBC mode; 
//takes a block array, the total number of blocks, an IV and the round keys, returns processed data.
void encrypt_cbc_mode(unsigned char * ciphertext, block * plaintext, const unsigned long bnum, const unsigned char round_keys[NROUND][KEYSIZE], const block iv)
{
	struct timeval current_time;
	static int current_block = 0;

	static bool first_chunk = true;
	block xor_result;

	//Copying the IV block to a local variable only if we're operating on the first chunk
	static block prev_ciphertext;
	if (first_chunk == true)
	{
		memcpy(&prev_ciphertext, &iv, BLOCKSIZE);
	}	

	block_logging((unsigned char *)&prev_ciphertext, "\n----------CBC(ENC)-------IV-----------", 0);

	//launching the feistel algorithm on every block
	for (unsigned long i=0; i<bnum; ++i) 
	{
		//logging (pre-encryption)
		current_block++;
		if (i % 10000 == 0)
		{
			gettimeofday(&current_time, NULL);
			show_progress_data(current_time, start_time, total_file_size, current_block);
		}
		block_logging((unsigned char *)&plaintext[i], "\n----------CBC(ENC)-------BEFORE-----------", i);

		//XORing the current block x with the ciphertext of the block x-1
		block_xor(&xor_result, &plaintext[i], &prev_ciphertext);
		
		//executing the encryption on the result of the previous xor and saving the result in prev_ciphertext for use in the next iteration
		process_block(&ciphertext[i*BLOCKSIZE], xor_result.left, xor_result.right, round_keys);
		memcpy(&prev_ciphertext, &ciphertext[i*BLOCKSIZE], sizeof(block));

		//logging (post-encryption)
		block_logging(&ciphertext[i*BLOCKSIZE], "\n----------CBC(ENC)-------AFTER-----------", i);
	}

	first_chunk = false;

}

//Executes decryption in CBC mode; 
//takes a block array, the total number of blocks, an IV and the round keys, returns processed data.
void decrypt_cbc_mode(unsigned char * plaintext, block * ciphertext, const unsigned long bnum, const unsigned char round_keys[NROUND][KEYSIZE], const block iv)
{
	struct timeval current_time;
	static int current_block = 0;

	static bool first_chunk = true;

	//This block will hold the result of the feistel cipher on the current ciphertext block
	//so that we can avoid operating in place on the b chunk, and keep the b[i-1] ciphertext block intact
	//and available for the final XOR
	block cur_ciphertext;
	
	//Copying the IV block to a local variable only if we're operating on the first chunk
	//In later chunks, current_iv will hold the last keystream block of the previous chunk 
	static block current_iv;
	if (first_chunk == true)
	{
		memcpy(&current_iv, &iv, BLOCKSIZE);
	}	

	block_logging((unsigned char *)&current_iv, "\n----------CBC(DEC)-------IV-----------", 0);

	//launching the feistel algorithm on every block, by making the index jump by increments of BLOCKSIZE
	#pragma omp parallel for private (cur_ciphertext)
	for (unsigned long i=0; i<bnum; ++i) 
	{	
		//logging (pre-decryption)
		#pragma omp critical
		block_logging((unsigned char *)&ciphertext[i], "\n----------CBC(DEC)------BEFORE-----------", i);
		current_block++;
		if (i % 10000 == 0)
		{
			gettimeofday(&current_time, NULL);
			show_progress_data(current_time, start_time, total_file_size, current_block);
		}

		//First thing, running feistel on the ciphertext block and storing the result in cur_ciphertext,...
		process_block((unsigned char *)&cur_ciphertext, ciphertext[i].left, ciphertext[i].right, round_keys);

		if (i == 0) //...if it's the first block, you xor the result with the IV to get the first plaintext block...
			block_xor((block *)&plaintext[(i*BLOCKSIZE)], &cur_ciphertext, &current_iv); 
		else	//...whereas for every other ciphered block x, you xor the result with ciphertext[x-1] to get plaintext[i]
			block_xor((block *)&plaintext[(i*BLOCKSIZE)], &cur_ciphertext, &ciphertext[(i)-1]); 			

		//logging (post-decryption)
		#pragma omp critical
		block_logging(&plaintext[i*BLOCKSIZE], "\n----------CBC(DEC)-------AFTER-----------", i);
	}

	//The IV for the next chunk will be the ciphertext of the last decrypted block
	memcpy(&current_iv, &ciphertext[(bnum)-1], sizeof(block));

	first_chunk = false;
}

//Executes the cipher in OFB mode; 
//takes a block array, the total size of the chunk, an IV and the round keys, returns processed data.
void operate_ofb_mode (unsigned char * result, block * b, const unsigned long data_len, const unsigned char round_keys[NROUND][KEYSIZE], const block iv)
{
	struct timeval current_time;
	static int current_block = 0;

	unsigned char * keystream;
	
	//Casting the block pointer to a char one because it's comfier for stream-like logic
	unsigned char * data = (unsigned char*)b;
	unsigned long bnum;
	
	if (data_len % BLOCKSIZE == 0) 
		bnum = data_len/BLOCKSIZE;
	else 
		//if data_len is not a perfect multiple of blocksize we need to count an extra block:
		//otherwise we wouldn't have the keystream available for the partial block at the end
	 	bnum = data_len/BLOCKSIZE + 1;

	//Copying the IV block to a local variable only if we're operating on the first chunk
	//In later chunks, current_iv will hold the last keystream block of the previous chunk 
	static block * current_iv = NULL;
	if (current_iv == NULL)
	{
		current_iv = malloc(BLOCKSIZE);
		memcpy(current_iv, &iv, BLOCKSIZE);
	}	

	keystream = malloc(BLOCKSIZE * bnum * sizeof(unsigned char));

	block_logging((unsigned char *)&iv, "\n----------OFB(ENC)------IV-----------", 0);

	//launching the cycle that will create the OFB keystream
	for (unsigned long i=0; i<bnum; ++i) 
	{
		//logging (pre-encryption)
		current_block++;
		if (i % 10000 == 0)
		{
			gettimeofday(&current_time, NULL);
			show_progress_data(current_time, start_time, total_file_size, current_block);
		}
		
		//executing the encryption on the last processed keystream block
		if (i==0) 
			process_block(&keystream[i*BLOCKSIZE], current_iv->left, current_iv->right, round_keys);
		else 
			process_block(&keystream[i*BLOCKSIZE], &keystream[(i-1)*BLOCKSIZE], &keystream[((i-1)*BLOCKSIZE) + BLOCKSIZE/2], round_keys);
	}

	//launching the cycle that will XOR the keystream and the plaintext to produce the ciphertext
	#pragma omp parallel for
	for (size_t i = 0; i < data_len; i++) 
	{
		result[i] = keystream[i] ^ data[i];
		
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
			block_logging(&data[(i - (BLOCKSIZE - 1))], "\n----------OFB(ENC)------plaintext-----------", i/BLOCKSIZE);
			block_logging(&result[(i - (BLOCKSIZE - 1))], "\n----------OFB(ENC)------ciphertext-----------", i/BLOCKSIZE);
		}
    }

	//The iv block for the next chunk will be the last block of the keystream
	memcpy(current_iv, &keystream[(bnum - 1) * BLOCKSIZE], sizeof(block));
	free(keystream);
}

//Executes encryption in PCBC mode; 
//takes a block array, the total number of blocks, an IV and the round keys, returns processed data.
void encrypt_pcbc_mode(unsigned char * ciphertext, block * plaintext, const unsigned long bnum, const unsigned char round_keys[NROUND][KEYSIZE], const block iv)
{
	struct timeval current_time;
	static int current_block = 0;

	static bool first_chunk = true;

	block * prev_ciphertext;
	prev_ciphertext = malloc(BLOCKSIZE);

	block * prev_plaintext;
	prev_plaintext = malloc(BLOCKSIZE);

	//Copying the IV block to a local variable only if we're operating on the first chunk
	static block xor_result;
	if (first_chunk == true)
	{
		memcpy(&xor_result, &iv, BLOCKSIZE);
	}

	block_logging((unsigned char *)&xor_result, "\n----------PCBC(ENC)-------IV-----------", 0);

	//launching the feistel algorithm on every block
	for (unsigned long i=0; i<bnum; ++i) 
	{
		//logging (pre-encryption)
		current_block++;
		if (i % 10000 == 0)
		{
			gettimeofday(&current_time, NULL);
			show_progress_data(current_time, start_time, total_file_size, current_block);
		}
		block_logging((unsigned char *)&plaintext[i], "\n----------PCBC(ENC)-------BEFORE-----------", i);

		//Updating the prev_plaintext variable with the plaintext from last iteration
		if (i>0) memcpy(prev_plaintext, &plaintext[i-1], BLOCKSIZE);

		//First we do plaintext[i-1] XOR ciphertext[i-1]...
		if (i>0) block_xor(&xor_result, prev_plaintext, prev_ciphertext);
		//...then we xor the result (or the IV if it's the first block) with the current (i) plaintext...
		block_xor(&xor_result, &plaintext[i], &xor_result);
		//...and finally we obtain the current ciphertext by encrypting what we got from the last two XOR operations:
		//c[i] = ENC(p[i] XOR (c[i-1] XOR p[i-1]))
		//Note that in the first iteration, the IV substitutes the (c[i-1] XOR p[i-1]) result
		process_block(&ciphertext[i*BLOCKSIZE], xor_result.left, xor_result.right, round_keys);

		//logging (post-encryption)
		block_logging(&ciphertext[i*BLOCKSIZE], "\n----------PCBC(ENC)-------AFTER-----------", i);
		
		//Updating the prev_ciphertext variable with the last ciphertext block we obtained
		memcpy(prev_ciphertext, &ciphertext[i*BLOCKSIZE], BLOCKSIZE);

		//We're encrypting the last block, we store p[i] XOR c[i] to use as IV for the next chunk
		if (i == bnum - 1)
		{
			block_xor(&xor_result, &plaintext[i], (block *)&ciphertext[i*BLOCKSIZE]);
		}
	}

	first_chunk = false;
}

//Executes decryption in PCBC mode; 
//takes a block array, the total number of blocks, an IV and the round keys, returns processed data.
void decrypt_pcbc_mode(unsigned char * plaintext, block * ciphertext, const unsigned long bnum, const unsigned char round_keys[NROUND][KEYSIZE], const block iv)
{
	struct timeval current_time;
	static int current_block = 0;

	static bool first_chunk = true;

	block * prev_ciphertext;
	prev_ciphertext = malloc(BLOCKSIZE);

	block * prev_plaintext;
	prev_plaintext = malloc(BLOCKSIZE);

	//Copying the IV block to a local variable only if we're operating on the first chunk
	static block xor_result;
	if (first_chunk == true)
	{
		memcpy(&xor_result, &iv, BLOCKSIZE);
	}

	block_logging((unsigned char *)&xor_result, "\n----------PCBC(DEC)-------IV-----------", 0);

	//launching the feistel algorithm on every block
	for (unsigned long i=0; i<bnum; ++i) 
	{
		//logging (pre-encryption)
		current_block++;
		if (i % 10000 == 0)
		{
			gettimeofday(&current_time, NULL);
			show_progress_data(current_time, start_time, total_file_size, current_block);
		}
		block_logging((unsigned char *)&ciphertext[i], "\n----------PCBC(DEC)-------BEFORE-----------", i);

		//XORing the plaintext and the ciphertext from the last iteration
		//and saving the current ciphertext to use it in the next iteration
		if (i>0) block_xor(&xor_result, prev_plaintext, prev_ciphertext);
		memcpy(prev_ciphertext, &ciphertext[i], BLOCKSIZE);
		
		//Decrypting the current ciphertext block in-place (we already saved the original value)
		process_block((unsigned char *)&ciphertext[i], ciphertext[i].left, ciphertext[i].right, round_keys);
		
		//Obtaining the plaintext back by XORing the result of the decryption with the result of the previous XOR:
		//p[i] = (c[i-1] XOR p[i-1]) XOR DEC(c[i]).
		//Note that in the first iteration, the IV substitutes the (c[i-1] XOR p[i-1]) result
		block_xor((block *)&plaintext[i*BLOCKSIZE], &ciphertext[i], &xor_result);

		//logging (post-encryption)
		block_logging(&plaintext[i*BLOCKSIZE], "\n----------PCBC(DEC)-------AFTER-----------", i);
		
		//Updating the prev_plaintext variable with the last plaintext block we obtained
		memcpy(prev_plaintext, &plaintext[i*BLOCKSIZE], BLOCKSIZE);
		
		//We're decrypting the last block, we store p[i] XOR c[i] to use as IV for the next chunk
		if (i == bnum - 1)
		{
			block_xor(&xor_result, prev_ciphertext, (block *)&plaintext[i*BLOCKSIZE]);
		}	
	}

	first_chunk = false;
}