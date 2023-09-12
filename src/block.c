//This module contains functions that manage the block data flow and the key scheduling, 

#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "common.h"
#include "utils.h"
#include "feistel.h"
#include "opmodes.h"
#include "omp.h"

//Receives and organizes input data, starts execution of the cipher in encryption mode. 
//Returns the result as a pointer to unsigned char, or NULL if an error is encountered.
unsigned char * encrypt_blocks(unsigned char * data, unsigned long data_len, unsigned char * key, enum mode chosen, unsigned long total_file_size)
{	
	unsigned char buffer[BLOCKSIZE];
	unsigned char round_keys[NROUND][KEYSIZE];
	unsigned long i=0;
	unsigned long bcount=0;

	block last_block;
	snprintf(last_block.left, BLOCKSIZE, "%lu", data_len);
	//scheduling the round keys starting from the master key given
	schedule_key(round_keys, key);	//see the function schedule_key for info

   	//if the size of the last chunk is not multiple of the block size,
	//remainder will be the number of leftover bytes that will go into the padded block
	unsigned int remainder = data_len % BLOCKSIZE;

	//Figuring how much space we need for the blocks.
	//We only need extra blocks if we're at the last chunk of input data, because only in that case we have to append the data size and eventually add padding.
	//We understand that it's the last chunk when there's less data than the input buffer can contain.
	if (data_len == BUFSIZE)	//full buffer worth of data means it's not the last chunk of data, so we won't need to add extra blocks
		bcount = (data_len * sizeof(char)) / BLOCKSIZE;	
	else if (data_len < BUFSIZE && remainder == 0)		//last block: data size is multiple of the blocksize, we need an extra block
		bcount = ((data_len * sizeof(char)) / BLOCKSIZE) + 1;
	else if (data_len < BUFSIZE && remainder > 0)		//last block: data size is not multiple of the blocksize, we need two extra blocks
		bcount = ((data_len * sizeof(char)) / BLOCKSIZE) + 2;
	
	//Reallocating the data pointer as a block pointer with the new size
	block * b = (block *) realloc(data, bcount * sizeof(block));
	if (b == NULL) return NULL;

    //Padding shenanigans: they apply only if it's the last chunk of data read.
    //It's a pretty naive padding scheme, but it works on any mode of operation so it simplifies coding.
    //I just 0-pad the last block if data length is not multiple of blocksize and use a size accounting block
    //to know how much of the last block is 0-padding to properly decrypt.
    if (data_len<BUFSIZE)	
    {	
	    if (remainder>0)	//forming the last padded block, if there's leftover data
	    {
	    	for (int z=0; z<BLOCKSIZE; z++)	
	    	{
	    		if (z < remainder)	//there's still leftover data
	    			buffer[z] = data[((bcount-2) * BLOCKSIZE) + z];
	    		else	//no more leftover data, proceed with the padding
	    			buffer[z] = '0';
	    	}

			for (int y=0; y<BLOCKSIZE/2; y++)	//copying the buffered data on the padded block
			{
				b[bcount - 2].left[y] = buffer[y];
				b[bcount - 2].right[y] = buffer[y+8];
			}
	    }

	    //appending a final block to store the real(unpadded) size of the encrypted data
	    int flag = 0;
	   	memcpy(&b[bcount-1], &last_block, sizeof(block));
	   	for (int i=0; i<BLOCKSIZE; i++)
	   	{
	   		if (flag == 1)
	   			b[bcount-1].left[i]='#';
	   		
	   		if (flag==0 && b[bcount-1].left[i] == '\0')
	   			flag = 1;
	   	}
	}

    if (chosen == cbc)
    	return encrypt_cbc_mode(b, bcount, round_keys);
    else if (chosen == ecb)
    	return operate_ecb_mode(b, bcount, round_keys);
    else if (chosen == ctr)
    	return encrypt_ctr_mode(b, bcount, round_keys);

    return NULL;
}

//Receives and organizes input data, starts execution of the cipher in decryption mode. 
//Returns the result as a pointer to unsigned char, or NULL if an error is encountered.
unsigned char * decrypt_blocks(unsigned char * data, unsigned long data_len, unsigned char * key, enum mode chosen)
{
	unsigned char buffer[BLOCKSIZE];
	unsigned char round_keys[NROUND][KEYSIZE];
	unsigned char temp[NROUND][KEYSIZE];
	unsigned long i=0;
	unsigned long bcount=0;

	//scheduling the round keys starting from the master key given
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

	bcount = (data_len * sizeof(char)) / BLOCKSIZE;
	//No need to reallocate: after decryption plaintext will never be greater than the ciphertext was:
	//it should be okay to just assign the address of the raw input data to the block pointer b
	block * b = (block *) data;

    if (chosen == cbc)
    	return decrypt_cbc_mode(b, bcount, round_keys);
    else if (chosen == ecb)
    	return operate_ecb_mode(b, bcount, round_keys);
    else if (chosen == ctr)
    	return decrypt_ctr_mode(b, bcount, round_keys);

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
