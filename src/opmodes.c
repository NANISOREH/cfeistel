//This module contains the functions that implement the logic of the cipher's operation modes.
//They can theoretically be used with any block cipher.

#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "common.h"
#include "utils.h"
#include "feistel.h"
#include "opmodes.h"

//Executes the cipher in ECB mode; takes a block array, the total number of blocks and the round keys, returns processed data.
unsigned char * operate_ecb_mode(block * b, unsigned long bnum, unsigned char round_keys[NROUND][KEYSIZE])
{
	unsigned char * ciphertext;
	unsigned long bcount=0;
	ciphertext = calloc(BLOCKSIZE * bnum, sizeof(unsigned char));
	if (ciphertext == NULL) return ciphertext;

	//launching the feistel algorithm on every block, by making the index jump by increments of BLOCKSIZE
	for (unsigned long i=0; i<BLOCKSIZE * bnum; i+=BLOCKSIZE) 
	{
		//logging (pre-processing)
		printf("\n\n\nblock %lu (ECB)", bcount);
		printf("\n---------- BEFORE -----------");
		print_block(b[bcount].left, b[bcount].right);
		
		//applying the cipher on the current block
		process_block(b[bcount].left, b[bcount].right, round_keys);
		
		//logging (post-processing)
		printf("---------- AFTER ------------");
		print_block(b[bcount].left, b[bcount].right);
		
		//appending the result to the ciphertext variable
		for (int j=0; j<BLOCKSIZE; j++)	
		{
			ciphertext[i+j] = b[bcount].left[j];
		}
		
		bcount++;
	}

	return ciphertext;
}

//Executes the cipher in CTR mode; takes a block array, the total number of blocks and the round keys, returns processed data.
unsigned char * operate_ctr_mode(block * b, unsigned long bnum, unsigned char round_keys[NROUND][KEYSIZE])
{
	unsigned char * ciphertext;
	unsigned long bcount=0;

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

	//launching the feistel algorithm on every block, by making the index jump by increments of BLOCKSIZE
	for (unsigned long i=0; i<BLOCKSIZE * bnum; i+=BLOCKSIZE) 
	{
		//initializing the counter block for this iteration
		str_safe_copy(counter_block.left, nonce, BLOCKSIZE/2);
		stringify_counter(counter_block.right, counter);

		//logging (pre-processing)
		printf("\n\n\nblock %lu (CTR)", bcount);
		printf("\n---------- BEFORE -----------");
		print_block(b[bcount].left, b[bcount].right);
		
		//applying the cipher on the counter block and incrementing the counter
		process_block(counter_block.left, counter_block.right, round_keys);
		counter = counter + 1;

		//xor between the ciphered counter block and the current block of plaintext/ciphertext
		half_block_xor(b[bcount].left, b[bcount].left, counter_block.left);
		half_block_xor(b[bcount].right, b[bcount].right, counter_block.right);
		
		//logging (post-processing)
		printf("---------- AFTER ------------");
		print_block(b[bcount].left, b[bcount].right);
		
		//storing the result of the xor in the output variable
		for (unsigned long j=0; j<BLOCKSIZE; j++)	
		{
			ciphertext[i+j] = b[bcount].left[j];
		}
		bcount++;
	}

	return ciphertext;
}

//Executes encryption in CBC mode; takes a block array, the total number of blocks and the round keys, returns processed data.
unsigned char * encrypt_cbc_mode(block * b, unsigned long bnum, unsigned char round_keys[NROUND][KEYSIZE])
{
	unsigned char * ciphertext;
	unsigned long bcount=0;
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

	//launching the feistel algorithm on every block, by making the index jump by increments of BLOCKSIZE
	for (unsigned long i=0; i<BLOCKSIZE * bnum; i+=BLOCKSIZE) 
	{
		//logging (pre-encryption)
		printf("\n\n\nblock %lu (CBC-ENC)", bcount);
		printf("\n---------- BEFORE -----------");
		print_block(b[bcount].left, b[bcount].right);

		//XORing the current block x with the ciphertext of the block x-1
		half_block_xor(b[bcount].left, b[bcount].left, prev_ciphertext.left);
		half_block_xor(b[bcount].right, b[bcount].right, prev_ciphertext.right);
		
		//executing the encryption on block x and saving the result in prev_ciphertext; it will be used in the next iteration
		process_block(b[bcount].left, b[bcount].right, round_keys);
		memcpy(&prev_ciphertext, &b[bcount], sizeof(block));

		//logging (post-encryption)
		printf("---------- AFTER ------------");
		print_block(b[bcount].left, b[bcount].right);
		
		//storing the ciphered block in the ciphertext variable
		for (int j=0; j<BLOCKSIZE; j++)	
		{
			ciphertext[i+j] = b[bcount].left[j];
		}
		bcount++;
	}

	return ciphertext;
}

//Executes decryption in CBC mode; takes a block array, the total number of blocks and the round keys, returns processed data.
unsigned char * decrypt_cbc_mode(block * b, unsigned long bnum, unsigned char round_keys[NROUND][KEYSIZE])
{
	unsigned long bcount=0;
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
	for (unsigned long i=0; i<BLOCKSIZE * bnum; i+=BLOCKSIZE) 
	{

		if (i % BLOCKSIZE == 0 && bcount < bnum) 
		{
			//logging (pre-decryption)
			printf("\n\n\nblock %lu (CBC-DEC)", bcount);
			printf("\n---------- BEFORE -----------");
			print_block(b[bcount].left, b[bcount].right);

			//First thing, you run feistel on the block,...
			process_block(b[bcount].left, b[bcount].right, round_keys);

			if (i == 0)		//...if it's the first block, you xor it with the IV...
			{
				half_block_xor(b[bcount].left, b[bcount].left, iv.left);
				half_block_xor(b[bcount].right, b[bcount].right, iv.right);
			}
			else	//...whereas for every other ciphered block x, you xor it with x-1 
			{
				half_block_xor(b[bcount].left, b[bcount].left, blocks_copy[bcount-1].left);
				half_block_xor(b[bcount].right, b[bcount].right, blocks_copy[bcount-1].right);
			}

			//logging (post-decryption)
			printf("---------- AFTER ------------");
			print_block(b[bcount].left, b[bcount].right);
			
			//storing the deciphered block in plaintext variable
			for (int j=0; j<BLOCKSIZE; j++)	plaintext[i+j] = b[bcount].left[j];
			bcount++;
		}

	}

	free(blocks_copy);
	return plaintext;
}