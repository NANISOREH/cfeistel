#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "utils.h"
#include "feistel.h"

//handles input data, starts execution of the cipher in encryption mode, returns the result, or NULL if an error is encountered
unsigned char * feistel_encrypt(unsigned char * data, unsigned long data_len, unsigned char * key, enum mode chosen)
{
	//if the size of the input data is not multiple of the block size,
	//remainder will be the number of leftover bytes that will go into the last padded block
	int remainder = data_len % BLOCKSIZE;	
	
	unsigned char buffer[BLOCKSIZE];
	unsigned char round_keys[NROUND][KEYSIZE];
	unsigned long i=0;
	unsigned long bcount=0;

	block last_block;
	snprintf(last_block.left, BLOCKSIZE, "%lu", data_len);

	schedule_key(round_keys, key);	//see the function schedule_key for info

	//allocating space for the blocks. 
	block * b;
	if (remainder == 0)		//data size is multiple of the blocksize
		b = (block*)calloc((data_len * sizeof(char) / BLOCKSIZE) + 1, sizeof(block));		
	else					//data size is not multiple of the blocksize, we need an extra block
		b = (block*)calloc((data_len * sizeof(char) / BLOCKSIZE) + 2, sizeof(block));

	if (b == NULL) return NULL;

	while (i < data_len)	//forming the blocks from the input data
    {
        buffer[i % BLOCKSIZE] = data[i];
        i++;

        if ((i+1) % BLOCKSIZE == 0)		//completed a block
        {
        	buffer[i % BLOCKSIZE] = data[i];
        	i++;
        	for (int j=0; j<BLOCKSIZE/2; j++)	//filling the block with the buffered data
			{
				b[bcount].left[j] = buffer[j];
				b[bcount].right[j] = buffer[j+8];
			}

			bcount++;
			if (bcount==data_len/BLOCKSIZE)		//formed the right number of blocks, break the cycle
				break;
        }
    }

    if (remainder>0)	//forming the last padded block, if there's leftover data
    {
    	for (int z=0; z<BLOCKSIZE; z++)	
    	{
    		if (z < remainder)	//there's still leftover data
    			buffer[z] = data[(bcount * BLOCKSIZE) + z];
    		else	//no more leftover data, proceed with the padding
    			buffer[z] = '0';
    	}

		for (int y=0; y<BLOCKSIZE/2; y++)	//copying the buffered data on the padded block
		{
			b[bcount].left[y] = buffer[y];
			b[bcount].right[y] = buffer[y+8];
		}

		bcount++;
    }

    free(data);

    //appending a final block with the real(unpadded) size of the encrypted data
    int flag = 0;
   	memcpy(&b[bcount], &last_block, sizeof(block));
   	for (int i=0; i<BLOCKSIZE; i++)
   	{
   		if (flag == 1)
   			b[bcount].left[i]='#';
   		
   		if (flag==0 && b[bcount].left[i] == '\0')
   			flag = 1;
   	}
    bcount++;

    if (chosen == cbc)
    	return encrypt_cbc_mode(b, bcount, round_keys);
    else if (chosen == ecb)
    	return operate_ecb_mode(b, bcount, round_keys);
    else if (chosen == ctr)
    	return operate_ctr_mode(b, bcount, round_keys);

    return NULL;
}

//handles input data, starts execution of the cipher in decryption mode, returns the result, or NULL if an error is encountered
unsigned char * feistel_decrypt(unsigned char * data, unsigned long data_len, unsigned char * key, enum mode chosen)
{
	unsigned char buffer[BLOCKSIZE];
	unsigned char round_keys[NROUND][KEYSIZE];
	unsigned char temp[NROUND][KEYSIZE];
	unsigned long i=0;
	unsigned long bcount=0;

	schedule_key(round_keys, key);	//see the function schedule_key for info
	if (chosen != ctr) //round keys sequence has to be inverted for decryption, except for ctr mode
	{
		memcpy(temp, round_keys, NROUND * KEYSIZE);
		int j=NROUND-1;

		for (int i=0; i<NROUND; i++)
		{
			str_safe_copy(round_keys[i], temp[j], NROUND);
			j--;
		}
	}

	//allocating space for the blocks. 
	block * b;
	b = (block*)calloc((data_len * sizeof(char) / BLOCKSIZE), sizeof(block));
	if (b == NULL) return NULL;		

	while (i < data_len)	//forming the blocks from the input data
    {
        buffer[i % BLOCKSIZE] = data[i];
        i++;

        if ((i+1) % BLOCKSIZE == 0)		//completed a block
        {
        	buffer[i % BLOCKSIZE] = data[i];
        	i++;
        	for (int j=0; j<BLOCKSIZE/2; j++)	//filling the block with the buffered data
			{
				b[bcount].left[j] = buffer[j];
				b[bcount].right[j] = buffer[j+8];
			}

			bcount++;
			if (bcount==data_len/BLOCKSIZE)		//we formed the right number of blocks, break the cycle
				break;
        }
    }

    free(data);

    if (chosen == cbc)
    	return decrypt_cbc_mode(b, bcount, round_keys);
    else if (chosen == ecb)
    	return operate_ecb_mode(b, bcount, round_keys);
    else if (chosen == ctr)
    	return operate_ctr_mode(b, bcount, round_keys);

    return NULL;
}

//Schedules the round keys by extending the 8 bytes given in input
void schedule_key(unsigned char round_keys[NROUND][KEYSIZE], unsigned char * key)
{
	unsigned char left_part;
	unsigned char right_part;
	unsigned char master_key[KEYSIZE];
	memcpy(master_key, key, KEYSIZE);
	str_safe_copy(round_keys[0], master_key, KEYSIZE);

	for (int j = 0; j<NROUND; j++)
	{
		for (int i = 0; i<KEYSIZE; i++) 
		{			
			master_key[i] = (master_key[i] + 30 - i) % 256;	
			split_byte(&left_part, &right_part, master_key[i]);
			merge_byte(&master_key[i], right_part, left_part);
		}
		p_box(master_key);
		
		//the altered key generated in the iteration j is saved as round key number j,
		//the final result is an extended key stored in the round_keys matrix
		str_safe_copy(round_keys[j], master_key, KEYSIZE);
	} 

}

//Executes the cipher in ECB mode; takes a block array and the round keys, returns processed data.
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
		printf("\n\n\nblock %d (ECB)", bcount);
		printf("\n---------- BEFORE -----------");
		print_block(b[bcount].left, b[bcount].right);
		
		//applying the cipher on the current block
		feistel_block(b[bcount].left, b[bcount].right, round_keys);
		
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

//Executes the cipher in CTR mode; takes a block array and the round keys, returns processed data.
unsigned char * operate_ctr_mode(block * b, unsigned long bnum, unsigned char round_keys[NROUND][KEYSIZE])
{
	unsigned char * ciphertext;
	unsigned long bcount=0;

	//using the checksum of the master key as starting point for the counter
	unsigned long counter = 0;
	for (int j=0; j<KEYSIZE; j++)
		counter = counter + round_keys[0][j];

	//deriving the nonce from the master key (i'm recycling the s-box to do that)
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
		printf("\n\n\nblock %d (CTR)", bcount);
		printf("\n---------- BEFORE -----------");
		print_block(b[bcount].left, b[bcount].right);
		
		//applying the cipher on the counter block and incrementing the counter
		feistel_block(counter_block.left, counter_block.right, round_keys);
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

//Executes encryption in CBC mode; takes a block array and the round keys, returns processed data.
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
		printf("\n\n\nblock %d (CBC-ENC)", bcount);
		printf("\n---------- BEFORE -----------");
		print_block(b[bcount].left, b[bcount].right);

		//XORing the current block x with the ciphertext of the block x-1
		half_block_xor(b[bcount].left, b[bcount].left, prev_ciphertext.left);
		half_block_xor(b[bcount].right, b[bcount].right, prev_ciphertext.right);
		
		//executing the encryption on block x and saving the result in prev_ciphertext; it will be used in the next iteration
		feistel_block(b[bcount].left, b[bcount].right, round_keys);
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

//Executes decryption in CBC mode; takes a block array and the round keys, returns processed data.
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
			printf("\n\n\nblock %d (CBC-DEC)", bcount);
			printf("\n---------- BEFORE -----------");
			print_block(b[bcount].left, b[bcount].right);

			//First thing, you run feistel on the block,...
			feistel_block(b[bcount].left, b[bcount].right, round_keys);

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

	return plaintext;
}

//execution of the cipher for a single block
void feistel_block(unsigned char * left, unsigned char * right, unsigned char round_keys[NROUND][KEYSIZE]) 
{	
	//buffer variable to temporarily store the left part of the block during the round execution
	unsigned char templeft[BLOCKSIZE/2];

	for (int i=0; i<NROUND; i++)	//execution of NROUND cipher rounds on the block
	{
		str_safe_copy(templeft, left, BLOCKSIZE/2);

		str_safe_copy(left, right, BLOCKSIZE/2);	//the right half in a round becomes the left half in the next round
		sp_network(right, round_keys[i]);	//f(right)
		half_block_xor(right, templeft, right);	  //f(right) XOR left 
	}

	//final inversion of left and right parts of the block after the last round
	str_safe_copy(templeft, left, BLOCKSIZE/2);
	str_safe_copy(left, right, BLOCKSIZE/2);
	str_safe_copy(right, templeft, BLOCKSIZE/2);
}

//"f" function of the feistel cipher. Contains a VERY basic SP network. 
void sp_network(unsigned char * data, unsigned char * key)
{
	unsigned char left_part;
	unsigned char right_part;

	for (int i = 0; i<BLOCKSIZE/2; i++)
	{
		//XORing the round key with the block data
		data[i] = data[i] ^ key[i];

		//Splitting the bytes into two parts of 4 bits and feeding them to the substitution box,
		//then merging the result together.
		split_byte(&left_part, &right_part, data[i]);
		s_box(&right_part, 0);
		s_box(&left_part, 1);
		merge_byte(&data[i], left_part, right_part);
	}

	//feeding data to the permutation box, where bits will get swapped all around
	p_box(data);
}

//4-bit input -> 4-bit output substitution boxes.
//The side parameter differentiates between the two S-boxes: 
//0 is for the left side of the byte and 1 is for the right.
void s_box(unsigned char * byte, int side)
{
	if (side == 0)
	{	
		switch (*byte)
		{
			case 0:	*byte = 14; break;
			case 1: *byte = 2; break;
			case 2: *byte = 9; break;
			case 3: *byte = 11; break;
			case 4: *byte = 15; break;
			case 5:	*byte = 4; break;
			case 6: *byte = 4; break;
			case 7: *byte = 3; break;
			case 8: *byte = 5; break;
			case 9: *byte = 6; break;
			case 10: *byte = 11; break;
			case 11: *byte = 1; break;
			case 12: *byte = 10; break;
			case 13: *byte = 8; break;
			case 14: *byte = 12; break;
			case 15: *byte = 13; break;
		}
	} 
	else if (side == 1)
	{
		switch (*byte)
		{
			case 0:	*byte = 14; break;
			case 1: *byte = 2; break;
			case 2: *byte = 9; break;
			case 3: *byte = 0; break;
			case 4: *byte = 15; break;
			case 5:	*byte = 0; break;
			case 6: *byte = 7; break;
			case 7: *byte = 3; break;
			case 8: *byte = 5; break;
			case 9: *byte = 6; break;
			case 10: *byte = 7; break;
			case 11: *byte = 1; break;
			case 12: *byte = 10; break;
			case 13: *byte = 8; break;
			case 14: *byte = 12; break;
			case 15: *byte = 13; break;
		}
	}
}

//64-bit permutation box
void p_box(unsigned char * data)
{
	swap_bit(&data[0], &data[7], 2, 4);
	swap_bit(&data[0], &data[7], 1, 6);
	swap_bit(&data[0], &data[7], 7, 5);
	swap_bit(&data[0], &data[7], 3, 7);
	swap_bit(&data[0], &data[7], 0, 1);
	swap_bit(&data[0], &data[7], 4, 0);
	swap_bit(&data[0], &data[7], 5, 3);
	swap_bit(&data[0], &data[7], 6, 2);

	swap_bit(&data[1], &data[4], 0, 7);
	swap_bit(&data[1], &data[4], 1, 6);
	swap_bit(&data[1], &data[4], 2, 5);
	swap_bit(&data[1], &data[4], 3, 4);
	swap_bit(&data[1], &data[4], 4, 3);
	swap_bit(&data[1], &data[4], 5, 2);
	swap_bit(&data[1], &data[4], 6, 1);
	swap_bit(&data[1], &data[4], 7, 0);

	swap_bit(&data[2], &data[5], 7, 4);
	swap_bit(&data[2], &data[5], 6, 6);
	swap_bit(&data[2], &data[5], 5, 5);
	swap_bit(&data[2], &data[5], 4, 7);
	swap_bit(&data[2], &data[5], 3, 1);
	swap_bit(&data[2], &data[5], 2, 0);
	swap_bit(&data[2], &data[5], 1, 3);
	swap_bit(&data[2], &data[5], 0, 2);

	swap_bit(&data[3], &data[6], 5, 4);
	swap_bit(&data[3], &data[6], 2, 6);
	swap_bit(&data[3], &data[6], 3, 5);
	swap_bit(&data[3], &data[6], 1, 7);
	swap_bit(&data[3], &data[6], 7, 1);
	swap_bit(&data[3], &data[6], 6, 0);
	swap_bit(&data[3], &data[6], 4, 3);
	swap_bit(&data[3], &data[6], 0, 2);
}
